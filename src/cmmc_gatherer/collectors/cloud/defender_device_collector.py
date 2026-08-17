"""Microsoft Defender for Endpoint (MDE) device collector.

Genuinely NOT Microsoft Graph — this calls the separate Defender for
Endpoint API (api.securitycenter.microsoft.com and its gov-cloud
equivalents; see cloud_config.CloudEndpoints.mde_base and graph.MdeClient)
directly. Built specifically because intune_device_collector.py's
_collect_mde_health() — an earlier attempt to get this same evidence
(sensor health, risk, exposure) out of Intune's bulk export-report API —
was expected not to work: those fields genuinely are not part of any
Intune deviceManagement/reports/exportJobs report. They live in MDE's own
API, not Intune's, because MDE is a distinct product with its own device
inventory and risk model, layered on top of (but not exposed through)
Intune's device management surface.

api/machines is a real, publicly documented, stable Microsoft Defender for
Endpoint API resource — materially higher confidence than the guessed
Intune export-report column names in _collect_mde_health, since this is a
well-known, long-stable API contract, not a recalled/unconfirmed CSV
schema. Fields read here (healthStatus, riskScore, exposureLevel,
onboardingStatus, aadDeviceId, machineTags) are real, documented field
names on the Machine resource.

Joined by aadDeviceId, NOT hostname. This is the Entra (AAD) device object
id — the SAME identifier intune_device_collector.py already reads as
metadata['azure_ad_device_id'] from managedDevices.azureADDeviceId.
Hostname is deliberately not used as the join key here: MDE's own device
naming (computerDnsName) is not confirmed to match Intune's deviceName in
every case (short name vs. FQDN, for one), while aadDeviceId references
the same underlying Entra device object from both APIs.

ARCHITECTURE NOTE: this class does NOT subclass CollectorBase and does not
return a List[Endpoint] or any other artifact list. CollectorBase's
contract ("returns a list of artifacts") doesn't fit what this class
actually does — it fetches a bulk lookup table keyed by aadDeviceId, meant
to be joined into Endpoint records that IntuneDeviceCollector already
built, not to produce new artifact rows of its own. That join is the
orchestrator's job (orchestrator.py's _run_cloud(), the same place
_merge_endpoints already handles cross-collector joining for on-prem +
Intune device de-duplication) — this collector only fetches and shapes MDE
data; it never touches an Endpoint object directly. Forcing this into
CollectorBase's List[Any] shape would mean either wrapping the lookup
dict in a fake single-item list or returning something that isn't
actually an "artifact" in this project's sense (Endpoint/ADObject/
SecurityEvent/Policy) — neither is honest, so this deliberately doesn't
inherit that interface.

DELIBERATELY NOT reusing intune_device_collector.py's mde_sensor_health /
mde_onboarding_status / mde_risk_level / mde_exposure_level metadata keys
(the export-report attempt's fields) — those came from a much
lower-confidence, unconfirmed source (guessed CSV column names). This
collector's fields are namespaced mde_atp_* instead, so a report or a
future scoring rule can always tell which source actually produced a
given value, rather than one silently overwriting the other depending on
which collector happens to run or fail on a given tenant. If the
export-report path is later confirmed not to work at all, retiring those
fields in favor of these is a separate, deliberate cleanup decision — not
something this collector should do by silently overwriting them.

Graph/MDE application permission required: WindowsDefenderATP ->
Machine.Read.All. This is NOT a Microsoft Graph permission — it is granted
under the separate "WindowsDefenderATP" API in the app registration's API
permissions blade, with its own admin consent step. Do not confuse this
with any DeviceManagement*.Read.All Graph permission already required
elsewhere in this project; granting those does not grant this, and vice
versa.

HONEST CONFIDENCE NOTE: beyond the field names themselves (real, stable,
documented), the exact filter/paging query parameters api/machines accepts
are recalled with moderate confidence, not independently verified against
a live tenant — this collector calls it with no query parameters at all
(the full default machine list), the lowest-risk option, rather than
guessing at a $filter/$select syntax MDE's API may not even support the
same way Graph does.
"""

import logging
from typing import Any, Dict

from ...cloud.graph import MdeClient

logger = logging.getLogger(__name__)


class DefenderDeviceCollector:
    """Collects Microsoft Defender for Endpoint device health/risk data,
    keyed by Entra (AAD) device id, for joining into Intune-derived
    Endpoint records elsewhere. See this module's own ARCHITECTURE NOTE
    for why this doesn't subclass CollectorBase — it fetches and shapes
    MDE data only; it never touches an Endpoint object itself."""

    def __init__(self, mde: MdeClient):
        self.mde = mde

    def collect(self) -> Dict[str, Dict[str, Any]]:
        """Return {aad_device_id.lower(): {...}} for every machine MDE
        knows about in this tenant.

        A machine with a missing/empty aadDeviceId is skipped and counted
        (logged once, not per-machine) — without that identifier there is
        nothing to join it to, and guessing a fallback key would risk a
        false join later rather than simply not enriching that device.
        """
        result: Dict[str, Dict[str, Any]] = {}
        skipped_no_aad_id = 0
        try:
            for m in self.mde.get_all("api/machines"):
                aad_id = m.get("aadDeviceId")
                if not aad_id:
                    skipped_no_aad_id += 1
                    continue
                result[aad_id.strip().lower()] = {
                    "health_status": m.get("healthStatus"),
                    "risk_score": m.get("riskScore"),
                    "exposure_level": m.get("exposureLevel"),
                    "onboarding_status": m.get("onboardingStatus"),
                    "tags": m.get("machineTags") or [],
                }
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Defender for Endpoint device collection failed: %s | Response: %s",
                             e, detail[:500])
            else:
                logger.error("Defender for Endpoint device collection failed: %s", e)
            return result

        if skipped_no_aad_id:
            logger.warning(
                "  %d MDE machine(s) had no aadDeviceId and could not be joined to any device",
                skipped_no_aad_id,
            )
        logger.info("Defender for Endpoint device collection complete: %d device(s)", len(result))
        return result
