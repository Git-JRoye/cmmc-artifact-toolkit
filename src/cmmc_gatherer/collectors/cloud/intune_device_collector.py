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
        never letting one section's failure take down another."""
        apps: List[Dict[str, Any]] = []
        try:
            params = {"$select": "displayName,version,publisher", "$top": "999"}
            for app in self.graph.get_all(
                f"deviceManagement/managedDevices/{device_id}/detectedApps", params=params
            ):
                apps.append({
                    "name": app.get("displayName") or "Unknown",
                    "version": app.get("version") or "",
                    "publisher": app.get("publisher") or "",
                })
        except Exception as e:
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
