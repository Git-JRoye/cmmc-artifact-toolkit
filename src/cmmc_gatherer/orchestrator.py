"""Per-tenant orchestration.

Turns a list of ``TenantProfile`` objects into actual collection runs. For each
tenant, this reads its configured plane(s) and auth method, builds only the
collectors that apply, runs them, and returns aggregated artifacts keyed by
tenant.

This is intentionally decoupled from any specific credential store: you supply
a ``secret_resolver`` callable (``secret_ref -> secret value``) that looks up
secrets however you store them (vault, key store, env — your choice), and the
orchestrator never touches secrets directly beyond passing that callable
through to the Graph auth layer.

ASSUMPTION TO VERIFY: this module builds an ``ArtifactCollection`` per tenant
using keyword args ``endpoints=``, ``ad_objects=``, ``security_events=``,
``policies=``. Confirm those match the real field names in
``models/artifacts.py::ArtifactCollection`` — adjust the constructor call in
``_empty_collection`` below if they differ. Everything else in this file is
independent of that detail.
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .cloud.cloud_config import Plane, TenantProfile
from .cloud.graph import GraphClient, build_auth_provider
from .collectors.cloud.cloud_event_collector import CloudSecurityEventCollector
from .collectors.cloud.cloud_policy_collector import CloudPolicyCollector
from .collectors.cloud.entra_identity_collector import EntraIdentityCollector
from .collectors.cloud.intune_device_collector import IntuneDeviceCollector
from .collectors.onprem.ad_collector import ActiveDirectoryCollector
from .collectors.onprem.endpoint_collector import EndpointCollector
from .collectors.onprem.event_log_collector import EventLogCollector
from .collectors.onprem.policy_collector import PolicyCollector
from .models.artifacts import ArtifactCollection
from .asset_scope import ScopeApplicationResult, apply_asset_scope
from .collection_health import CollectionHealthRecorder, HealthLogEntry

logger = logging.getLogger(__name__)

SecretResolver = Callable[[str], str]


@dataclass
class TenantRunResult:
    """Outcome of one tenant's collection run."""
    tenant_key: str
    display_name: str
    collection: ArtifactCollection
    errors: List[str] = field(default_factory=list)
    scope_result: Optional[ScopeApplicationResult] = None  # None if no asset_scope was configured
    health_log: List[HealthLogEntry] = field(default_factory=list)  # every WARNING/ERROR logged during this run


class TenantOrchestrator:
    """Runs the correct collectors for each configured tenant."""

    def __init__(self, secret_resolver: SecretResolver, demo: bool = False):
        self.secret_resolver = secret_resolver
        self.demo = demo  # forces on-prem endpoint collector into demo mode; no cloud equivalent needed

    def run_all(self, profiles: List[TenantProfile]) -> Dict[str, TenantRunResult]:
        """Run collection for every profile. One tenant's failure never blocks the rest."""
        results: Dict[str, TenantRunResult] = {}
        for profile in profiles:
            try:
                results[profile.tenant_key] = self.run_one(profile)
            except Exception as e:
                logger.error("Tenant %s failed entirely: %s", profile.tenant_key, e)
                results[profile.tenant_key] = TenantRunResult(
                    tenant_key=profile.tenant_key,
                    display_name=profile.display_name,
                    collection=self._empty_collection(),
                    errors=[f"fatal: {e}"],
                )
        return results

    def run_one(self, profile: TenantProfile) -> TenantRunResult:
        """Run whichever plane(s) this tenant is configured for."""
        profile.validate()  # fail fast with a specific error, not a mysterious empty result
        logger.info("[%s] deployment mode: %s", profile.tenant_key, profile.deployment_mode())
        errors: List[str] = []
        onprem_endpoints, cloud_endpoints = [], []
        ad_objects, events, policies = [], [], []

        # Captures every WARNING/ERROR any collector logs during this run,
        # so a real failure (a bad Graph call, a permission gap) is visible
        # in the report itself, not only in this console — see
        # collection_health.py. try/finally so the handler is always
        # removed even if something below raises unexpectedly; leaving it
        # attached would leak into every subsequent tenant's run.
        health_recorder = CollectionHealthRecorder()
        cmmc_logger = logging.getLogger("cmmc_gatherer")
        cmmc_logger.addHandler(health_recorder)
        try:
            if profile.runs_onprem():
                try:
                    ep, ad, ev, po = self._run_onprem(profile)
                    onprem_endpoints += ep
                    ad_objects += ad
                    events += ev
                    policies += po
                except Exception as e:
                    logger.error("[%s] on-prem plane failed: %s", profile.tenant_key, e)
                    errors.append(f"onprem: {e}")

            if profile.runs_cloud():
                try:
                    ep, ad, ev, po, cloud_errors = self._run_cloud(profile)
                    cloud_endpoints += ep  # Intune devices, mapped to Endpoint
                    ad_objects += ad       # Entra users/groups, mapped to ADObject
                    events += ev           # Entra sign-in + directory audit logs, mapped to SecurityEvent
                    policies += po         # Conditional Access + Intune config profiles, mapped to Policy
                    errors += cloud_errors
                except Exception as e:
                    logger.error("[%s] cloud plane failed: %s", profile.tenant_key, e)
                    errors.append(f"cloud: {e}")
        finally:
            cmmc_logger.removeHandler(health_recorder)

        endpoints = self._merge_endpoints(onprem_endpoints, cloud_endpoints)
        merged_count = len(onprem_endpoints) + len(cloud_endpoints) - len(endpoints)
        if merged_count:
            logger.info(
                "[%s] merged %d hybrid-managed device(s) (matched by hostname across "
                "on-prem + Intune) so they aren't double-counted as separate endpoints",
                profile.tenant_key, merged_count,
            )

        collection = ArtifactCollection(
            endpoints=endpoints,
            ad_objects=ad_objects,
            security_events=events,
            policies=policies,
        )
        logger.info(
            "[%s] collection complete: %d endpoint(s), %d AD/identity object(s), "
            "%d event(s), %d policy record(s), %d error(s)",
            profile.tenant_key, len(endpoints), len(ad_objects), len(events),
            len(policies), len(errors),
        )

        # Apply CMMC asset-scope categorization AFTER full collection, not
        # during it — collection always sees the whole reachable
        # environment first; scope filtering is a distinct, separate step
        # on top of that, so the two concerns never get tangled together.
        # None means no asset_scope was configured for this tenant at all
        # (e.g. a GCC High client whose entire environment is genuinely in
        # scope) — nothing to apply, no CMMC Assessment Scope section will
        # render for it.
        scope_result = None
        if profile.asset_scope is not None:
            scope_result = apply_asset_scope(collection, profile.asset_scope)

        return TenantRunResult(
            tenant_key=profile.tenant_key,
            display_name=profile.display_name,
            collection=collection,
            errors=errors,
            scope_result=scope_result,
            health_log=health_recorder.entries,
        )

    # -- device de-duplication -----------------------------------------------

    @staticmethod
    def _merge_endpoints(onprem: List, cloud: List) -> List:
        """Merge on-prem and Intune endpoint records describing the SAME
        physical machine, so a hybrid-managed device (locally scanned AND
        Intune-enrolled) isn't reported/scored as two separate endpoints.

        Match key: hostname, case-insensitive exact match — the one
        identifier both planes reliably produce today. KNOWN LIMITATION:
        this will mis-merge two genuinely different machines that happen to
        share a hostname, and will miss a real match if a device was renamed
        between the two collections. A serial-number match would be more
        robust once the on-prem collector captures one; flagged here rather
        than silently assumed to be perfect.

        The merged record keeps the on-prem fields that scoring actually
        reads (firewall_status, antivirus_status, installed_updates) — those
        only ever come from on-prem collection — and folds the Intune record
        into metadata['intune'] so compliance state, encryption, and
        management state are preserved for reporting rather than discarded.
        """
        from .models.artifacts import Endpoint

        cloud_by_host: Dict[str, List] = {}
        for ep in cloud:
            key = (ep.hostname or "").strip().upper()
            if key:
                cloud_by_host.setdefault(key, []).append(ep)

        merged: List = []
        used_cloud_ids = set()

        for ep in onprem:
            key = (ep.hostname or "").strip().upper()
            matches = cloud_by_host.get(key, [])
            if not matches:
                merged.append(ep)
                continue

            cloud_ep = matches[0]  # multiple Intune records for one hostname would be unusual
            used_cloud_ids.add(id(cloud_ep))
            combined_metadata = dict(ep.metadata or {})
            combined_metadata["sources"] = ["onprem", "intune"]
            combined_metadata["intune"] = dict(cloud_ep.metadata or {})
            merged.append(Endpoint(
                hostname=ep.hostname,
                ip_address=ep.ip_address,
                os_version=ep.os_version,
                installed_updates=ep.installed_updates,
                security_products=ep.security_products,
                firewall_status=ep.firewall_status,
                antivirus_status=ep.antivirus_status,
                metadata=combined_metadata,
            ))

        for ep in cloud:
            if id(ep) not in used_cloud_ids:
                merged.append(ep)

        return merged

    # -- plane runners ------------------------------------------------------

    def _run_onprem(self, profile: TenantProfile):
        """Run the four on-prem collectors. Each failure is isolated, not fatal."""
        endpoints, ad_objects, events, policies = [], [], [], []

        for name, fn in [
            ("endpoint", lambda: EndpointCollector(demo=self.demo).collect()),
            ("ad", lambda: ActiveDirectoryCollector(
                config=profile.domain_config,
                secret_resolver=self.secret_resolver,
                demo=self.demo,
            ).collect()),
            ("event_log", lambda: EventLogCollector().collect()),
            ("policy", lambda: PolicyCollector().collect()),
        ]:
            try:
                result = fn()
            except Exception as e:
                logger.error("on-prem %s collector failed: %s", name, e)
                continue
            if name == "endpoint":
                endpoints = result
            elif name == "ad":
                ad_objects = result
            elif name == "event_log":
                events = result
            elif name == "policy":
                policies = result

        return endpoints, ad_objects, events, policies

    def _run_cloud(self, profile: TenantProfile):
        """Build a Graph client for this tenant's cloud/auth, then run cloud collectors."""
        errors: List[str] = []
        auth = build_auth_provider(profile.auth_method, self.secret_resolver)
        graph = GraphClient(profile, auth)

        endpoints: List = []
        try:
            endpoints = IntuneDeviceCollector(graph).collect()
        except Exception as e:
            logger.error("[%s] Intune collector failed: %s", profile.tenant_key, e)
            errors.append(f"intune: {e}")

        ad_objects: List = []
        try:
            ad_objects = EntraIdentityCollector(graph).collect()
        except Exception as e:
            logger.error("[%s] Entra identity collector failed: %s", profile.tenant_key, e)
            errors.append(f"entra: {e}")

        events: List = []
        try:
            events = CloudSecurityEventCollector(graph).collect()
        except Exception as e:
            logger.error("[%s] Cloud security event collector failed: %s", profile.tenant_key, e)
            errors.append(f"cloud_events: {e}")

        policies: List = []
        try:
            policies = CloudPolicyCollector(graph).collect()
        except Exception as e:
            logger.error("[%s] Cloud policy collector failed: %s", profile.tenant_key, e)
            errors.append(f"cloud_policies: {e}")

        return endpoints, ad_objects, events, policies, errors

    @staticmethod
    def _empty_collection() -> ArtifactCollection:
        return ArtifactCollection(endpoints=[], ad_objects=[], security_events=[], policies=[])
