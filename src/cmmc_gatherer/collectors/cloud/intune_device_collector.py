"""Intune managed-device collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``EndpointCollector``. Pulls device
compliance and management state from Intune for every enrolled device and maps
it into the existing ``Endpoint`` model, so the current scorer and exporters
work unchanged. Also pulls each device's detected-apps list (CM.L2-3.4.1
system-inventory evidence — software, not just hardware/OS).

Honest field mapping, not a forced fit:
    Intune's device data shape is different from a local PowerShell posture
    check. Some ``Endpoint`` fields have a clean equivalent (os_version,
    hostname); others don't (there is no local-firewall-profile concept for a
    centrally managed device, and "installed hotfixes" isn't what Intune
    reports). Rather than approximate those, this collector leaves them
    ``None``/empty and puts the real Intune-native signals — compliance state,
    encryption, management state, last check-in — in ``metadata``, so nothing
    is silently fabricated. The Phase-3 scoring rework should read from
    ``metadata`` directly for cloud-managed devices rather than expecting
    firewall_status/antivirus_status to be populated.

SCALABILITY NOTE on installed-software collection: fetching each device's
detected apps is a per-device Graph call (N devices = N+1 total calls, same
fan-out cost as CloudPolicyCollector's per-profile status lookups). Trivial
for a handful of devices; on a large MSP client with hundreds of enrolled
devices, this will be slow and is a real candidate for throttling/retry
tuning or making optional — not yet pilot-tested against a large fleet.

PILOT HISTORY on detectedApps, since this endpoint has already proven
unreliable once: a first attempt called it under /v1.0 with $select/$top
query params and got a 400 Bad Request from every device in a real tenant.
The real error body (captured only after adding response-text logging)
showed "Resource not found for the segment 'detectedApps'" — not a bad
query param at all, but the segment not existing under /v1.0. Now calling
it under /beta instead, which is UNVERIFIED as of this writing — if that
also fails, don't guess a third time; log the real response body and look
it up in current Microsoft Graph documentation rather than pattern-matching
against past Graph quirks.

Graph application permission required: DeviceManagementManagedDevices.Read.All
(admin-consented in each tenant) — this single permission covers both the
managedDevices list and its detectedApps sub-resource; no new permission is
needed for the software-inventory piece.
"""

import logging
from typing import Any, Dict, List

from ..base import CollectorBase
from ...models.artifacts import Endpoint
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class IntuneDeviceCollector(CollectorBase):
    """Collects managed-device posture from Intune via Microsoft Graph."""

    def __init__(self, graph: GraphClient):
        self.graph = graph
        # PILOT FINDING #2: detectedApps under /v1.0 returned "Resource not
        # found for the segment 'detectedApps'" against a real tenant — not
        # a query-param problem (that was PILOT FINDING #1, now known to be
        # a wrong guess). This is the classic signature of a resource that
        # only exists under /beta. Trying beta here as the next hypothesis;
        # this is still UNVERIFIED against a live tenant as of this edit.
        # If it fails again, the error will now say so explicitly rather
        # than silently reusing v1.0's wrong assumption a third time.
        self._beta_graph = graph.with_api_version("beta")

    def collect(self) -> List[Endpoint]:
        params = {
            "$select": "id,deviceName,operatingSystem,osVersion,complianceState,"
                       "isEncrypted,managementState,jailBroken,lastSyncDateTime,"
                       "model,manufacturer,serialNumber,azureADDeviceId,"
                       "userPrincipalName,deviceEnrollmentType",
            "$top": "999",
        }
        out: List[Endpoint] = []
        try:
            for d in self.graph.get_all("deviceManagement/managedDevices", params=params):
                ep = self._map(d)
                device_id = d.get("id")
                if device_id:
                    ep.metadata["installed_software"] = self._collect_detected_apps(device_id, ep.hostname)
                out.append(ep)
        except Exception as e:
            logger.error("Intune device collection failed: %s", e)
        logger.info("Intune device collection complete: %d device(s)", len(out))
        return out

    def _collect_detected_apps(self, device_id: str, hostname: str) -> List[Dict[str, Any]]:
        """Per-device software inventory. Failure here is isolated to this one
        device's software list — it never affects the device's own posture
        data collected in _map(), matching this file's overall pattern of
        never letting one section's failure take down another.

        Uses /beta, not /v1.0 — see PILOT FINDING #2 in __init__. This is a
        hypothesis based on the real error message from a live tenant
        ("Resource not found for the segment 'detectedApps'" under v1.0),
        not a confirmed-working fix. If this also fails, the response body
        is logged so the next pilot run gives Graph's actual error text
        instead of another guess.
        """
        apps: List[Dict[str, Any]] = []
        try:
            for app in self._beta_graph.get_all(
                f"deviceManagement/managedDevices/{device_id}/detectedApps"
            ):
                apps.append({
                    "name": app.get("displayName") or "Unknown",
                    "version": app.get("version") or "",
                    "publisher": app.get("publisher") or "",
                })
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not fetch detected apps for device '%s': %s | Response: %s",
                                hostname, e, detail[:500])
            else:
                logger.warning("  Could not fetch detected apps for device '%s': %s", hostname, e)
        return apps

    @staticmethod
    def _map(d: dict) -> Endpoint:
        os_name = d.get("operatingSystem") or "Unknown"
        os_ver = d.get("osVersion") or ""
        compliant = d.get("complianceState") == "compliant"

        return Endpoint(
            hostname=d.get("deviceName") or d.get("azureADDeviceId") or "UNKNOWN",
            ip_address="",  # Not exposed by this Graph endpoint.
            os_version=f"{os_name} {os_ver}".strip(),
            installed_updates=[],  # Not applicable — Intune doesn't report a hotfix list here.
            security_products=[],  # Not applicable — see metadata for the real cloud signals.
            firewall_status=None,  # No local-profile concept for a centrally managed device.
            antivirus_status=None,  # Use metadata['compliance_state'] / Defender data instead.
            metadata={
                "source": "intune",
                "compliance_state": d.get("complianceState"),
                "is_compliant": compliant,
                "is_encrypted": d.get("isEncrypted"),
                "jail_broken": d.get("jailBroken"),
                "management_state": d.get("managementState"),
                "last_sync": d.get("lastSyncDateTime"),
                "model": d.get("model"),
                "manufacturer": d.get("manufacturer"),
                "serial_number": d.get("serialNumber"),
                "azure_ad_device_id": d.get("azureADDeviceId"),
                "owner_upn": d.get("userPrincipalName"),
                "enrollment_type": d.get("deviceEnrollmentType"),
            },
        )
