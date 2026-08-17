"""Intune managed-device collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``EndpointCollector``. Pulls device
compliance and management state from Intune for every enrolled device and maps
it into the existing ``Endpoint`` model, so the current scorer and exporters
work unchanged. Also pulls each device's detected-apps list (CM.L2-3.4.1
system-inventory evidence — software, not just hardware/OS), whether a
BitLocker recovery key is escrowed for the device (SC.L2-3.13.10 key
management evidence — a device can report itself "encrypted" with no
recoverable key anywhere, which is a real gap this closes), and the device's
real-time Windows Defender health (SI.L1-3.14.2 — a stronger, more current
signal than the compliance-policy REQUIREMENT check elsewhere in this
project, since this is the device's actual state right now, not just what's
demanded of it).

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
tuning or making optional — not yet pilot-tested against a large fleet. The
BitLocker recovery-key check below is the SAME per-device fan-out cost,
added on top of the existing one.

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

HARD SECURITY CONSTRAINT on BitLocker recovery keys, non-negotiable:
this collector must NEVER request, read, log, or store the actual recovery
key value — only whether a key exists for a device. The Graph resource
here (informationProtection/bitlockerRecoveryKeys) deliberately separates
two permission scopes: BitLockerKey.ReadBasic.All (metadata only — key ID,
creation date, associated device — key VALUE is never populated under this
scope) and BitLockerKey.Read.All (returns the actual key material when the
caller also does $select=key). This file requests and uses ONLY
BitLockerKey.ReadBasic.All, and the code below never sets $select=key.
If anyone ever considers reading the key value itself for any reason, stop
— that is a fundamentally different, far more sensitive capability than
this compliance-evidence tool should ever hold.

HONEST CONFIDENCE NOTE, and this one is genuinely lower confidence than the
detectedApps/compliance-policy/update-ring additions this session — the
BitLocker recovery key API is a much less common area of Graph than device
inventory or Intune policy, and this project has already been wrong twice
this session about a new endpoint's exact shape (detectedApps needed
/beta; deviceCompliancePolicies rejected $select on subtype fields).

PILOT FINDING (real, confirmed, and actually verified this time): the
correct path is informationProtection/bitlocker/recoveryKeys under /beta
— confirmed directly from Intune's own working Recovery Keys page network
traffic (browser dev tools), not inferred from an error message. Two
earlier attempts both failed with "Resource not found for the segment
'bitlockerRecoveryKeys'" — first under /v1.0, then under /beta — because
the path was missing a "/bitlocker/" segment, not because of an API
version or permission problem. /beta was correct from the very first
attempt; only the path was ever wrong.

Graph application permissions required:
  DeviceManagementManagedDevices.Read.All (existing — covers managedDevices,
  its detectedApps sub-resource, AND windowsProtectionState, since all three
  are sub-resources of the same managedDevices object with no separate
  permission scope)
  BitLockerKey.ReadBasic.All (NEW — metadata-only recovery key existence
  check; deliberately NOT BitLockerKey.Read.All, see constraint above)

HONEST CONFIDENCE NOTE on Microsoft Defender for Endpoint (MDE) device
health (_collect_mde_health): this is a new, genuinely unverified addition,
same "try the bulk export-job report first" approach that worked for
firewall status. Two distinct layers of uncertainty here, not just one:
report NAME ("DefenderAgentHealthStatus" is a best guess, not confirmed —
if wrong, Graph's own 400 response body is expected to name the actual
valid report(s), the same way every other wrong-guess endpoint in this
project has been corrected from real error text rather than another
guess), and COLUMN names within that report (genuinely unknown, so no
$select is passed for this one — letting the report return its own
default columns and reading several plausible candidate names per field,
rather than compounding two guesses into one request that can fail for
either reason with no way to tell which). Required permission is assumed,
not confirmed, to be covered by DeviceManagementManagedDevices.Read.All
already required above — MDE device risk/exposure data more commonly
lives under Microsoft Defender for Endpoint's own Machine.Read.All scope
in other integration patterns, so a permission-specific error here is a
real, expected possible outcome, not evidence the report name is wrong.

Also genuinely possible: an empty or partial result here may reflect a
tenant that hasn't connected Microsoft Defender for Endpoint to Intune at
all (a real, common configuration, not every Intune tenant has MDE Plan 2)
rather than a collection failure — same "empty is not necessarily a bug"
distinction already made for installed-software collection elsewhere in
this project.
"""

import logging
from typing import Any, Dict, List, Optional

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

        # Bulk-fetched ONCE for the whole tenant (not per-device — see
        # _collect_firewall_statuses' own docstring for why this one is
        # architecturally different from everything else in this file), and
        # deliberately isolated in its own try/except BEFORE the main device
        # loop starts. A failure here must never take down the main device
        # list — that's the exact real regression "ownerType" caused earlier
        # this session when a risky addition wasn't properly isolated from
        # the core collection path.
        firewall_statuses: Dict[str, str] = {}
        firewall_lookup_failed = False
        try:
            firewall_statuses = self._collect_firewall_statuses()
        except Exception as e:
            firewall_lookup_failed = True
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not fetch bulk firewall status report: %s | Response: %s",
                                e, detail[:500])
            else:
                logger.warning("  Could not fetch bulk firewall status report: %s", e)

        # Same bulk-fetch-once, isolated-failure pattern as firewall status
        # above — one export report call for the whole tenant, never a
        # per-device fan-out, and a failure here must never take down the
        # main device list.
        mde_health: Dict[str, Dict[str, Optional[str]]] = {}
        mde_health_lookup_failed = False
        try:
            mde_health = self._collect_mde_health()
        except Exception as e:
            mde_health_lookup_failed = True
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not fetch bulk MDE device health report: %s | Response: %s",
                                e, detail[:500])
            else:
                logger.warning("  Could not fetch bulk MDE device health report: %s", e)

        try:
            for d in self.graph.get_all("deviceManagement/managedDevices", params=params):
                ep = self._map(d)
                device_id = d.get("id")
                if device_id:
                    software, failed = self._collect_detected_apps(device_id, ep.hostname)
                    ep.metadata["installed_software"] = software
                    # Distinct from "software == []" -- that could mean either
                    # a real, confirmed-empty inventory OR a failed lookup.
                    # Report code needs to tell those apart rather than
                    # showing "Not collected" for both, which was the actual
                    # bug behind "why does only one device show software?".
                    ep.metadata["software_collection_failed"] = failed

                azure_ad_device_id = d.get("azureADDeviceId")
                escrow_result = self._check_bitlocker_escrow(azure_ad_device_id, ep.hostname)
                ep.metadata.update(escrow_result)

                protection_result = self._check_realtime_protection(device_id, ep.hostname) if device_id else {
                    "defender_realtime_protection_enabled": None,
                    "defender_malware_protection_enabled": None,
                    "defender_signature_overdue": None,
                    "defender_protection_lookup_failed": False,
                }
                ep.metadata.update(protection_result)

                if device_id:
                    ep.metadata["owner_type"] = self._check_ownership_type(device_id, ep.hostname)

                # Cloud firewall status: real per-device state (not just a
                # compliance-policy requirement), from the bulk export
                # fetched once above, joined by hostname (see
                # _collect_firewall_statuses for why DeviceName is used as
                # the join key instead of DeviceId). Never guessed at if
                # the bulk fetch itself failed — every device gets the
                # same, honest lookup-failed flag in that case, rather
                # than silently reading as "no data" indistinguishably
                # from "not applicable".
                ep.metadata["cloud_firewall_status"] = firewall_statuses.get((ep.hostname or "").upper())
                ep.metadata["cloud_firewall_lookup_failed"] = firewall_lookup_failed

                # Microsoft Defender for Endpoint device health, same bulk
                # export + hostname join as firewall status above. A device
                # with no entry (whole export failed, or this device isn't
                # onboarded to MDE at all) reads as None for every field —
                # never guessed at — with mde_health_lookup_failed telling
                # the caller WHY: a real lookup failure, versus this device
                # simply not being present in an otherwise-successful report.
                device_mde = mde_health.get((ep.hostname or "").upper()) or {}
                ep.metadata["mde_sensor_health"] = device_mde.get("sensor_health")
                ep.metadata["mde_onboarding_status"] = device_mde.get("onboarding_status")
                ep.metadata["mde_risk_level"] = device_mde.get("risk_level")
                ep.metadata["mde_exposure_level"] = device_mde.get("exposure_level")
                ep.metadata["mde_health_lookup_failed"] = mde_health_lookup_failed

                out.append(ep)
        except Exception as e:
            logger.error("Intune device collection failed: %s", e)
        logger.info("Intune device collection complete: %d device(s)", len(out))
        return out

    def _collect_firewall_statuses(self) -> Dict[str, str]:
        """Bulk-fetch real, per-device Windows Firewall status for every
        Intune-managed device via Intune's asynchronous export-report API
        (see GraphClient.run_export_job for the full mechanics of that
        pattern) — one export call for the whole tenant, rather than the
        per-device fan-out used elsewhere in this file (BitLocker,
        real-time protection, ownership).

        PILOT FINDING (real, confirmed): a first version of this method
        used deviceManagement/reports/getCachedReport, discovered via
        browser dev tools against a real tenant and confirmed working
        THAT way — but it 404'd when called from this unattended app-only
        collector. Root cause, confirmed via external review before
        chasing it further: getCachedReport requires a pre-existing
        cached report configuration, which only gets created as a side
        effect of a human clicking through the Intune admin center's own
        report UI ("Generate again") — an interactive, delegated-auth
        action this app-only collector never performs. The exportJobs API
        used here has no such prerequisite; it is fully self-contained,
        confirmed to work identically for any tenant (no per-client setup
        beyond the one-time app registration / admin consent this whole
        project already requires).

        Joins on DeviceName (case-insensitive), NOT DeviceId — DeviceId is
        offered in the Intune portal's own column picker for this report,
        but is not confirmed to actually be present in the export's real
        returned columns. DeviceName is the more reliably-present join
        key, matched against each managedDevice's own deviceName in
        collect() below.

        Uses Microsoft's own human-readable "_loc" column (e.g.
        "Enabled") for the status value, rather than the raw FirewallStatus
        integer code, whose exact numeric meaning per value isn't
        confidently known — reusing Microsoft's own translation avoids
        guessing at it.

        HONEST CONFIDENCE NOTE: the exact export column set
        (DeviceName, FirewallStatus, FirewallStatus_loc, _ManagedBy, UPN)
        is recalled with moderate confidence from external review, not
        independently verified against a live tenant as of this writing.
        The full set of possible "_loc" values beyond "Enabled" (the only
        one seen in real pilot data so far) is also not exhaustively
        verified. Required Graph permissions are expected to be the same
        DeviceManagementConfiguration.Read.All and
        DeviceManagementManagedDevices.Read.All already required elsewhere
        in this project — if this 403s, the real error text will say
        what's actually missing.

        Returns {hostname.upper(): status_label}. A device with no entry
        (the whole export failed, or a device simply isn't present in the
        report for some reason) must be treated as unknown by the caller
        — never silently read as a confirmed "Enabled" or "Disabled".
        """
        rows = self._beta_graph.run_export_job(
            report_name="FirewallStatus",
            select=["DeviceName", "FirewallStatus", "FirewallStatus_loc", "_ManagedBy", "UPN"],
        )
        result: Dict[str, str] = {}
        for row in rows:
            name = (row.get("DeviceName") or "").strip()
            if not name:
                continue
            status_label = row.get("FirewallStatus_loc") or row.get("FirewallStatus")
            result[name.upper()] = status_label
        logger.info("  Firewall status (export report): %d device(s)", len(result))
        return result

    # Column-name candidates per field, checked in order (a "_loc" variant
    # first, matching FirewallStatus's precedent that the human-readable
    # translated column is preferable to a raw code where both exist) —
    # NOT confirmed against a live tenant. Deliberately several guesses per
    # field rather than one, and no $select passed to the report at all
    # (see the module docstring's HONEST CONFIDENCE NOTE on MDE health for
    # why): an unknown report schema and an unknown report name are two
    # separate uncertainties, and compounding them into one request would
    # make a failure impossible to attribute to either cause.
    _MDE_COLUMN_CANDIDATES = {
        "sensor_health": ("SensorHealthState_loc", "SensorHealthState",
                           "SensorDataAgentHealthState_loc", "SensorDataAgentHealthState",
                           "AgentHealthStatus_loc", "AgentHealthStatus"),
        "onboarding_status": ("OnboardingStatus_loc", "OnboardingStatus",
                               "DeviceOnboardingStatus_loc", "DeviceOnboardingStatus"),
        "risk_level": ("RiskLevel_loc", "RiskLevel", "DeviceRiskLevel_loc", "DeviceRiskLevel"),
        "exposure_level": ("ExposureLevel_loc", "ExposureLevel", "DeviceExposureLevel_loc",
                            "DeviceExposureLevel"),
    }
    _MDE_DEVICE_NAME_CANDIDATES = ("DeviceName", "ComputerDnsName", "MachineName")

    def _collect_mde_health(self) -> Dict[str, Dict[str, Optional[str]]]:
        """Bulk-fetch Microsoft Defender for Endpoint (MDE) device health —
        sensor health state, onboarding status, risk level, exposure level
        — for every device, via the same Intune asynchronous export-report
        API used by _collect_firewall_statuses above (see that method's own
        docstring, and GraphClient.run_export_job, for the full mechanics).
        One export call for the whole tenant; never a per-device fan-out.

        Report name "DefenderAgentHealthStatus" is a best guess, not
        confirmed. If wrong, Graph's own error response is expected to name
        the actual valid report(s) — that response body is logged by the
        caller (collect() above) exactly so this can be corrected from real
        error text rather than guessed a second time, matching how every
        other wrong-endpoint-name mistake in this project has been fixed.

        No $select is sent, since the exact column names in this report are
        also unconfirmed — letting the report return its own default
        columns and reading several plausible candidate names per field
        (see _MDE_COLUMN_CANDIDATES) keeps the report-name question and the
        column-name question separable. If NONE of the candidate columns
        are found in a real, non-empty response, the actual column names
        from the first row are logged so the real schema is known instead
        of guessed at again.

        Returns {hostname.upper(): {"sensor_health": ..., "onboarding_status":
        ..., "risk_level": ..., "exposure_level": ...}}. A device with no
        entry (the whole export failed, this device isn't onboarded to MDE,
        or the tenant has no MDE/Intune connection at all — see the module
        docstring) must be treated as unknown by the caller, never silently
        read as a confirmed value.
        """
        rows = self._beta_graph.run_export_job(report_name="DefenderAgentHealthStatus")
        result: Dict[str, Dict[str, Optional[str]]] = {}
        any_field_matched = False
        for row in rows:
            name = None
            for name_key in self._MDE_DEVICE_NAME_CANDIDATES:
                name = (row.get(name_key) or "").strip()
                if name:
                    break
            if not name:
                continue

            device_result: Dict[str, Optional[str]] = {}
            for field, candidates in self._MDE_COLUMN_CANDIDATES.items():
                value = None
                for column in candidates:
                    value = row.get(column)
                    if value not in (None, ""):
                        any_field_matched = True
                        break
                    value = None
                device_result[field] = value
            result[name.upper()] = device_result

        if rows and not any_field_matched:
            sample_columns = sorted(rows[0].keys())
            logger.warning(
                "  MDE health report returned %d row(s) but none of the expected "
                "columns were found — real column names appear to be: %s. "
                "Update _MDE_COLUMN_CANDIDATES to match.", len(rows), sample_columns,
            )
        logger.info("  MDE device health (export report): %d device(s)", len(result))
        return result

    def _check_ownership_type(self, device_id: str, hostname: str) -> Optional[str]:
        """Fetch this one device's ownership type ("company" or "personal"/
        BYOD) in complete isolation from the main device-listing call.

        PILOT FINDING (real, confirmed): a first attempt added "ownerType"
        directly to the shared $select on the main deviceManagement/
        managedDevices LIST call and caused a 400 Bad Request that took
        down the ENTIRE device table for every device at once — a much
        worse failure mode than any other lookup in this file, since a bad
        field name there breaks the query that finds devices at all, not
        just one device's data. This method exists specifically to never
        repeat that mistake: it is a separate, per-device call that can
        fail in isolation (returning None for just this one device) without
        ever affecting the main device list again.

        HONEST CONFIDENCE NOTE: the property name used here,
        managedDeviceOwnerType (not the original wrong guess, "ownerType"),
        is recalled with better — but still not independently verified —
        confidence, based on this resource's own naming convention
        elsewhere (e.g. deviceEnrollmentType, not enrollmentType). If this
        also fails, the response body is logged; check it before guessing
        a third name.

        Returns the raw value ("company"/"personal"/"unknown") or None if
        not attempted or the lookup failed — never guessed at.
        """
        try:
            result = self.graph.get_one(
                f"deviceManagement/managedDevices/{device_id}",
                params={"$select": "id,managedDeviceOwnerType"},
            )
            return result.get("managedDeviceOwnerType")
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not check ownership type for device '%s': %s | Response: %s",
                                hostname, e, detail[:500])
            else:
                logger.warning("  Could not check ownership type for device '%s': %s", hostname, e)
            return None

    def _collect_detected_apps(self, device_id: str, hostname: str) -> tuple:
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

        Returns (apps, failed) — failed=True means the Graph call itself
        errored (network, permission, endpoint issue); failed=False with an
        empty apps list means the call succeeded and Intune genuinely has no
        inventoried software for this device (e.g. it hasn't completed an
        app-inventory sync yet — a real, non-error device state, not a bug).
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
            return [], True
        return apps, False

    def _check_bitlocker_escrow(self, azure_ad_device_id: Optional[str], hostname: str) -> Dict[str, Any]:
        """Check ONLY whether a BitLocker recovery key exists for this
        device — never reads, requests, or logs the key value itself (see
        the hard security constraint in the module docstring).

        Filters by the device's Entra ID (AAD) object ID, NOT the Intune
        managed-device ID used elsewhere in this file — these are two
        different identifiers for the same physical device, and recovery
        keys are tied to the Entra device object, not the Intune one.

        Returns a metadata dict with three keys, following the same
        three-state pattern already used for software collection (ok /
        confirmed-empty / failed, never conflating "no key" with "we
        couldn't check"):
          bitlocker_key_escrowed: True (>=1 key found) / False (checked,
            confirmed none) / None (not checked — no AAD device ID to
            filter on, or the lookup itself failed)
          bitlocker_key_count: how many key records were found
          bitlocker_lookup_failed: True only if the Graph call itself
            errored — distinct from a confirmed "escrowed=False"

        PILOT FINDING (real, confirmed): the URL path itself was wrong, not
        the API version. Captured directly from Intune's own working UI via
        browser dev tools (Network tab) against a real tenant: the correct
        path is informationProtection/bitlocker/recoveryKeys — note the
        extra "/bitlocker/" segment — not informationProtection/
        bitlockerRecoveryKeys as originally written. /beta was correct from
        the start; two earlier attempts (v1.0, then beta) both failed with
        "Resource not found for the segment 'bitlockerRecoveryKeys'"
        because the segment name itself was wrong, not because of version
        or permissions. Confirmed by inspecting Intune's own Recovery Keys
        page network traffic directly — not a guess this time.
        """
        if not azure_ad_device_id:
            return {"bitlocker_key_escrowed": None, "bitlocker_key_count": 0, "bitlocker_lookup_failed": False}
        try:
            params = {"$filter": f"deviceId eq '{azure_ad_device_id}'"}
            keys = list(self._beta_graph.get_all("informationProtection/bitlocker/recoveryKeys", params=params))
            return {
                "bitlocker_key_escrowed": len(keys) > 0,
                "bitlocker_key_count": len(keys),
                "bitlocker_lookup_failed": False,
            }
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not check BitLocker key escrow for device '%s': %s | Response: %s",
                                hostname, e, detail[:500])
            else:
                logger.warning("  Could not check BitLocker key escrow for device '%s': %s", hostname, e)
            return {"bitlocker_key_escrowed": None, "bitlocker_key_count": 0, "bitlocker_lookup_failed": True}

    def _check_realtime_protection(self, device_id: str, hostname: str) -> Dict[str, Any]:
        """Real-time Windows Defender health for this device — distinct from
        (and stronger evidence than) the compliance-policy REQUIREMENT
        checked elsewhere in this file. This is the device's actual current
        state: is malware protection running, is real-time protection on,
        are signatures overdue.

        HONEST CONFIDENCE NOTE: deviceManagement/managedDevices/{id}/
        windowsProtectionState is a real Intune Graph resource, but the
        exact field names below are recalled, not independently verified
        against current Graph documentation — same caveat class as every
        other new endpoint added this session. If this errors, the response
        body is logged; check that before assuming the field names are
        wrong versus the whole resource needing /beta.

        Three-state result per field, same pattern as everything else in
        this file: True/False are real, confirmed answers; None means the
        lookup wasn't attempted or failed — never silently treated as
        "protection is off."
        """
        try:
            state = self.graph.get_one(
                f"deviceManagement/managedDevices/{device_id}/windowsProtectionState"
            )
            return {
                "defender_realtime_protection_enabled": state.get("realTimeProtectionEnabled"),
                "defender_malware_protection_enabled": state.get("malwareProtectionEnabled"),
                "defender_signature_overdue": state.get("signatureUpdateOverdue"),
                "defender_protection_lookup_failed": False,
            }
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.warning("  Could not check real-time protection state for device '%s': %s | Response: %s",
                                hostname, e, detail[:500])
            else:
                logger.warning("  Could not check real-time protection state for device '%s': %s", hostname, e)
            return {
                "defender_realtime_protection_enabled": None,
                "defender_malware_protection_enabled": None,
                "defender_signature_overdue": None,
                "defender_protection_lookup_failed": True,
            }

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
                # NOTE: owner_type is NOT set here. It's fetched via a
                # separate, isolated per-device call in collect()
                # (_check_ownership_type) after _map() runs — deliberately
                # kept out of the main managedDevices $select after a real
                # pilot run confirmed that including "ownerType" there
                # caused a 400 that took down the ENTIRE device list.
            },
        )
