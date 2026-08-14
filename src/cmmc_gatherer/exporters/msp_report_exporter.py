"""MSP-specific compliance report exporter.

Fixes applied after reviewing the original implementation against real
collected data:

  - Findings no longer flag cloud (Intune) endpoints as "firewall disabled" /
    "antivirus inactive" — those fields are deliberately None for cloud
    endpoints (not applicable, not a failure). Only on-prem-sourced endpoints
    (identified the same way ComplianceScorer does: firewall_status is not
    None) are evaluated for those two findings.
  - Policy findings now reuse ComplianceScorer._policy_passes() instead of a
    naive status == "Disabled" check, so security-inverted settings (e.g.
    ClearTextPassword should be Disabled) are judged correctly instead of
    being flagged backwards.
  - Cloud endpoints get their own table showing the real Intune signals
    (compliance state, encryption, management state) instead of being
    invisible or rendered with blank on-prem-shaped columns.
  - Policy table coloring uses the same pass/fail logic instead of only
    recognizing the literal string "Enabled" as good — so real records like
    "Configured" or "Success and Failure" render correctly instead of as an
    ambiguous warning color.
  - Assessment Scope section describes only the plane(s) actually present in
    the data, instead of always describing an on-prem/AD engagement.

Further fixes after reviewing real generated reports:
  - Device encryption is now checked directly against metadata['is_encrypted']
    for cloud endpoints, independent of Intune's own 'compliant' verdict —
    that verdict reflects whatever compliance policy the tenant configured,
    which may not require encryption at all, so relying on it alone silently
    missed real unencrypted devices.
  - A "Coverage Notes" section now discloses when an entire category
    (policies or security events) has zero data for a plane that's actually
    present, so a clean score can't read as "everything was checked" when
    large categories were never assessed.
  - Failing policies are now grouped into separate findings by policy_type
    instead of one undifferentiated comma-separated list mixing e.g.
    password-policy failures with two dozen individual audit subcategories.

Further fixes after a real pilot run (device double-counting and misleading
full-coverage scores):
  - Endpoints merged across on-prem and Intune by the orchestrator (matched
    by hostname) now show their Intune compliance/encryption signal inline
    in the on-prem table (a new "Also Cloud-Managed" column) instead of that
    signal disappearing just because the device is counted once, not twice.
  - Non-compliance and encryption findings now check every endpoint with an
    Intune signal, standalone or merged (_intune_signal helper), so a hybrid
    device's failing status can't silently vanish because it moved out of
    the pure-cloud_eps list.
  - The overall score is now paired everywhere with a coverage figure
    (ComplianceScorer.calculate_coverage): a red "Coverage incomplete" banner
    under the score, plus a Scoring Coverage row in the Executive Summary,
    so a score based on only one or two of six categories can never read as
    a fully-assessed tenant.

Further fixes after reviewing the firewall finding and the missing AD data:
  - "Firewall Not Fully Enabled" now names which specific profile(s)
    (Domain/Private/Public) are disabled per host, from data the collector
    already gathers (metadata['firewall_profiles']) but the report wasn't
    surfacing. Includes a caveat that a third-party firewall/EDR product may
    be intentionally handling blocking instead.
  - AD/Entra user and group data was being collected but only used to
    compute the ad_security score number — never actually shown. Added two
    new tables (Users, Groups) covering both on-prem AD and Entra shapes,
    plus two new findings: "Privileged Account Without MFA" and "Stale
    Privileged Account".

Further fixes after adding real cloud policy/event collectors:
  - Coverage notes and Assessment Scope previously checked artifacts.policies
    / artifacts.security_events for emptiness in aggregate, and previously
    unconditionally claimed cloud policy/event review "is not yet
    implemented" — both are now real. Coverage notes check by SOURCE
    (_CLOUD_POLICY_TYPES / _CLOUD_EVENT_SOURCES) instead, so a tenant with
    real on-prem policy data but a failed/empty cloud policy collection is
    still correctly flagged (the old aggregate-emptiness check would have
    missed that), and the messaging no longer falsely claims something
    unimplemented when it simply returned no data this run.
  - New findings for the two new cloud policy types (Conditional Access,
    Intune Configuration Profile) so a failing policy of either type gets
    real, type-specific guidance instead of the generic "via Group Policy"
    fallback recommendation, which doesn't apply to cloud policies at all.

Further additions for CM.L2-3.4.1 (system baselining/inventory) and
AU.L2-3.3.7 (time synchronization):
  - Both endpoint tables (on-prem and Intune) now show an "Installed
    Software" column — a collapsed, expandable <details> list per device
    rather than always-visible rows, so a device with 100+ packages doesn't
    bloat the report by default while the full inventory is still genuinely
    present as evidence. _software_list() prefers the on-prem registry-based
    inventory over Intune's detectedApps for a merged hybrid device, since
    the two would otherwise mostly duplicate each other.
  - New finding type "Time Synchronization" (from the on-prem policy
    collector's new w32tm check) gets real, specific guidance instead of
    the generic policy-type fallback.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import ExporterBase
from ..utils.compliance import ComplianceScorer
from .. import control_mapping as cm

logger = logging.getLogger(__name__)

# Shared between coverage-note detection and Assessment Scope generation, so
# a cloud-sourced policy/event record is never mistaken for an on-prem one
# (or vice versa) in either place.
_CLOUD_POLICY_TYPES = ('Conditional Access', 'Intune Configuration Profile')
_CLOUD_EVENT_SOURCES = ('Entra Sign-In Logs', 'Entra Directory Audit Logs')

# Shared stylesheet for both the main report and the standalone software
# inventory page, so a visual change (or the "make it look more
# professional" redesign) only has to happen in one place, not be kept in
# sync by hand across two f-strings.
_BASE_CSS = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Calibri, 'Segoe UI', Arial, sans-serif;
                line-height: 1.6; color: #1f2937; background: #ffffff; }
        .header { background: #1e293b; color: #f1f5f9; padding: 36px 40px;
                   border-bottom: 4px solid #0f172a; }
        .header h1 { font-family: Georgia, 'Times New Roman', serif;
                      font-size: 2em; font-weight: normal; letter-spacing: 0.3px; }
        .header .subtitle { font-size: 1em; color: #94a3b8; margin-top: 6px;
                             text-transform: uppercase; letter-spacing: 1.5px; }
        .content { max-width: 920px; margin: 0 auto; padding: 40px 30px; }
        .section { margin: 34px 0; page-break-inside: avoid; }
        .section h2 { font-family: Georgia, 'Times New Roman', serif; font-weight: normal;
                       font-size: 1.3em; color: #1e293b; border-bottom: 1px solid #cbd5e1;
                       padding-bottom: 8px; margin-bottom: 14px; letter-spacing: 0.2px; }
        .domain-nav h3 { font-family: Georgia, 'Times New Roman', serif; font-weight: normal;
                          font-size: 1.15em; color: #1e293b; margin-bottom: 10px; }
        .score-card { display: flex; margin: 16px 0; }
        .score { background: #f8fafc; border: 1px solid #e2e8f0; padding: 24px;
                 text-align: center; flex: 1; }
        .score .number { font-size: 2.6em; font-weight: 600; color: #1e293b; }
        .score .label { color: #64748b; margin-top: 6px; font-size: 0.9em;
                        text-transform: uppercase; letter-spacing: 0.8px; }
        .score.good { border-left: 4px solid #2f7d4f; }
        .score.good .number { color: #2f7d4f; }
        .score.warning { border-left: 4px solid #b7791f; }
        .score.warning .number { color: #b7791f; }
        .score.critical { border-left: 4px solid #b3261e; }
        .score.critical .number { color: #b3261e; }
        .finding { margin: 12px 0; padding: 14px 16px; border-left: 3px solid #b7791f;
                   background: #fafaf9; }
        .finding.critical { border-left-color: #b3261e; background: #fdf7f6; }
        .finding.resolved { border-left-color: #2f7d4f; background: #f6faf7; }
        .finding h4 { margin-bottom: 4px; font-size: 1em; color: #1e293b; }
        .finding p { font-size: 0.92em; line-height: 1.5; color: #334155; }
        table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 0.92em; }
        th { background: #f1f5f9; color: #334155; padding: 10px 12px; text-align: left;
              border-bottom: 2px solid #cbd5e1; font-weight: 600; font-size: 0.85em;
              text-transform: uppercase; letter-spacing: 0.4px; }
        td { padding: 9px 12px; border-bottom: 1px solid #e2e8f0; }
        tr:nth-child(even) td { background: #fafbfc; }
        .recommendation { background: #f8fafc; padding: 12px 16px;
                          border-left: 3px solid #3b5b7a; margin: 8px 0 20px 0; font-size: 0.92em; }
        .alert-critical { border-left: 3px solid #b3261e; background: #fdf7f6;
                           padding: 12px 16px; margin-top: 14px; font-size: 0.92em; }
        .footer { background: #f8fafc; padding: 20px; text-align: center;
                  margin-top: 40px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 0.88em; }
        .summary-table td { padding: 7px 10px; }
        .summary-table td:first-child { font-weight: 600; width: 32%; color: #475569; }
        .na { color: #94a3b8; font-style: italic; }
        .status-good { color: #2f7d4f; font-weight: 600; }
        .status-bad { color: #b3261e; font-weight: 600; }
        .status-warn { color: #b7791f; font-weight: 600; }
        .status-neutral { color: #94a3b8; }
        .control-badges { margin: 4px 0 14px 0; font-size: 0.82em; }
        .badge { display: inline-block; padding: 1px 8px; border-radius: 3px;
                 margin-right: 6px; margin-bottom: 4px; font-weight: 600; font-size: 0.95em;
                 border: 1px solid; }
        .badge.direct { background: #f0f4f8; color: #2c4a6b; border-color: #c3d4e3; }
        .badge.supporting { background: #faf6ef; color: #8a5a1f; border-color: #e5d2b0; }
        .confidence-key { font-size: 0.85em; color: #64748b; margin: 8px 0 14px 0; }
        .domain-nav { background: #f8fafc; border: 1px solid #e2e8f0; padding: 18px 22px;
                       margin: 18px 0; }
        .domain-nav ul { margin: 0 0 10px 20px; }
        .domain-nav li { margin-bottom: 4px; }
        .domain-nav a { color: #2c4a6b; text-decoration: none; border-bottom: 1px dotted #2c4a6b; }
        .domain-nav a:hover { border-bottom-style: solid; }
        details summary { cursor: pointer; color: #2c4a6b; font-size: 0.92em; }
        .back-link { display: inline-block; margin-bottom: 20px; font-size: 0.92em; }
"""


class MSPReportExporter(ExporterBase):
    """Exports a professional HTML compliance report suitable for MSP client presentation."""

    def export(
        self,
        artifacts: Any,
        output_path: str,
        customer_name: Optional[str] = None,
        assessment_id: Optional[str] = None,
        **_,
    ) -> bool:
        try:
            # The software inventory lives in its own file, sitting next to
            # the main report, so it can be regenerated/updated on its own
            # without touching the main compliance report at all — it was
            # moved out because it will only keep growing as more devices
            # and software get collected. Filename is derived from the
            # main report's own path so the two always stay associated
            # without the caller needing to coordinate two separate paths.
            base, ext = os.path.splitext(output_path)
            ext = ext or '.html'
            software_path = f"{base}_software{ext}"
            main_filename = os.path.basename(output_path)
            software_filename = os.path.basename(software_path)

            onprem_eps = self._onprem_endpoints(artifacts)
            cloud_eps = self._cloud_endpoints(artifacts)
            ad_users = self._ad_users(artifacts)
            present_evidence = self._present_evidence_keys(artifacts, onprem_eps, cloud_eps, ad_users)
            has_software = 'installed_software' in present_evidence

            html_content = self._generate_msp_report(
                artifacts, customer_name, assessment_id,
                software_href=software_filename if has_software else None,
            )
            # Explicit UTF-8 write: without it, Python falls back to the
            # platform's default encoding (often cp1252 on Windows), which
            # mis-encodes the em-dashes used throughout this template. The
            # browser then renders those bytes as UTF-8 (its own default for
            # a local file with no declared charset) and produces garbled
            # "�" characters — confirmed against a real generated report.
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Exported MSP report: {output_path}")

            if has_software:
                software_html = self._generate_software_inventory_page(
                    artifacts, customer_name, assessment_id, back_href=main_filename,
                )
                with open(software_path, 'w', encoding='utf-8') as f:
                    f.write(software_html)
                logger.info(f"Exported software inventory: {software_path}")

            return True
        except Exception as e:
            logger.error(f"MSP report export failed: {e}")
            return False

    # -- plane helpers, matching ComplianceScorer's own split -----------------

    @staticmethod
    def _onprem_endpoints(artifacts: Any) -> List:
        return [ep for ep in artifacts.endpoints if ep.firewall_status is not None]

    @staticmethod
    def _cloud_endpoints(artifacts: Any) -> List:
        return [ep for ep in artifacts.endpoints
                if ep.firewall_status is None and (ep.metadata or {}).get('source') == 'intune']

    @staticmethod
    def _ad_users(artifacts: Any) -> List:
        return [o for o in artifacts.ad_objects if o.object_class == 'user']

    @staticmethod
    def _ad_groups(artifacts: Any) -> List:
        return [o for o in artifacts.ad_objects if o.object_class == 'group']

    def _generate_msp_report(
        self,
        artifacts: Any,
        customer_name: Optional[str],
        assessment_id: Optional[str],
        software_href: Optional[str] = None,
    ) -> str:
        compliance_score = ComplianceScorer.calculate_overall_score(artifacts)
        coverage = ComplianceScorer.calculate_coverage(artifacts)
        findings = self._generate_findings(artifacts)
        onprem_eps = self._onprem_endpoints(artifacts)
        cloud_eps = self._cloud_endpoints(artifacts)

        coverage_notes = self._generate_coverage_notes(artifacts, onprem_eps, cloud_eps)
        coverage_notes_html = ""
        if coverage_notes:
            notes_items = "\n".join(f"                <li>{note}</li>" for note in coverage_notes)
            coverage_notes_html = f"""
        <div class="section">
            <h2>Coverage Notes</h2>
            <div class="recommendation">
                <strong>The following was NOT evaluated in this assessment:</strong>
                <ul>
{notes_items}
                </ul>
            </div>
        </div>"""

        customer_name = customer_name or "Unnamed Customer"
        assessment_id = assessment_id or "CMMC-" + datetime.now().strftime("%Y%m%d%H%M%S")
        score_class = 'good' if compliance_score >= 80 else ('warning' if compliance_score >= 60 else 'critical')

        # A score renormalized across only the dimensions with data can look
        # like a full assessment when it isn't — this banner makes the actual
        # coverage impossible to miss, right next to the number it qualifies.
        coverage_banner_html = ""
        if coverage['assessed_weight_pct'] < 100:
            missing_labels = ', '.join(d.replace('_', ' ') for d in coverage['missing_dimensions'])
            coverage_banner_html = f"""
                <div class="alert-critical">
                    <strong>Coverage incomplete:</strong> this score is based on
                    {coverage['assessed_count']} of {coverage['total_count']} scoring categories
                    ({coverage['assessed_weight_pct']}% of total scoring weight).
                    Not assessed: {missing_labels}.
                </div>"""

        # Which evidence keys (from control_mapping.EVIDENCE_MAP) actually
        # have real data in THIS report — drives both the domain coverage
        # nav below and the per-section "Satisfies:" badges further down.
        # Adding a new evidence type later means adding its detection here
        # and one EvidenceMapping entry in control_mapping.py — nothing else
        # in this method needs to change for it to show up correctly.
        ad_users_for_evidence = self._ad_users(artifacts)
        present_evidence = self._present_evidence_keys(artifacts, onprem_eps, cloud_eps, ad_users_for_evidence)
        domain_coverage_html = self._build_domain_coverage_html(present_evidence)
        scoring_breakdown_html = self._build_scoring_breakdown_html(artifacts)

        # Purely data-derived — no TenantProfile reaches this exporter, so
        # this reflects what was actually collected, not what was
        # configured. The two can differ (e.g. a hybrid-configured tenant
        # where the on-prem plane happened to fail this run) — showing the
        # real collected shape is more honest than echoing the config.
        if onprem_eps and cloud_eps:
            collection_mode_label = "Hybrid (On-Prem + Cloud)"
        elif onprem_eps:
            collection_mode_label = "On-Prem Only"
        elif cloud_eps:
            collection_mode_label = "Cloud Only"
        else:
            collection_mode_label = "No Endpoint Data Collected"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CMMC Compliance Assessment Report</title>
    <style>{_BASE_CSS}</style>
</head>
<body>
    <div class="header">
        <h1>CMMC Compliance Assessment Report</h1>
        <div class="subtitle">Third-Party Audit Ready</div>
    </div>

    <div class="content">
        <div class="section">
            <h2>Executive Summary</h2>
            <table class="summary-table">
                <tr><td>Customer:</td><td>{customer_name}</td></tr>
                <tr><td>Assessment ID:</td><td>{assessment_id}</td></tr>
                <tr><td>Assessment Date:</td><td>{datetime.now().strftime("%Y-%m-%d")}</td></tr>
                <tr><td>Collection Mode:</td><td>{collection_mode_label}</td></tr>
                <tr><td>Overall Compliance Score:</td><td>{compliance_score}%</td></tr>
                <tr><td>Scoring Coverage:</td><td>{coverage['assessed_count']} of {coverage['total_count']} categories
                    ({coverage['assessed_weight_pct']}% of scoring weight)</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Compliance Score</h2>
            <div class="score-card">
                <div class="score {score_class}">
                    <div class="number">{compliance_score}%</div>
                    <div class="label">Overall Compliance</div>
                </div>
            </div>{coverage_banner_html}
        </div>
{scoring_breakdown_html}
{domain_coverage_html}
        <div class="section">
            <h2>Infrastructure Overview</h2>
            <table>
                <tr><th>Metric</th><th>Count</th></tr>
                <tr><td>On-Prem Endpoints</td><td>{len(onprem_eps)}</td></tr>
                <tr><td>Cloud-Managed Devices (Intune)</td><td>{len(cloud_eps)}</td></tr>
                <tr><td>Active Directory / Identity Objects</td><td>{len(artifacts.ad_objects)}</td></tr>
                <tr><td>Security Policies</td><td>{len(artifacts.policies)}</td></tr>
                <tr><td>Security Events Analyzed</td><td>{len(artifacts.security_events)}</td></tr>
            </table>
        </div>
{coverage_notes_html}
"""

        if onprem_eps:
            html += f"""        <div class="section" id="sec-onprem-endpoints">
            <h2>On-Prem Endpoint Status</h2>
            {self._satisfies_badge_html(['firewall_status', 'antivirus_status', 'patch_level'], present_evidence)}
            <table>
                <tr>
                    <th>Hostname</th><th>IP Address</th><th>OS Version</th>
                    <th>Firewall</th><th>Antivirus</th><th>Also Cloud-Managed (Intune)</th>
                    <th>Installed Software</th>
                </tr>
"""
            for ep in onprem_eps:
                fw_color = 'status-good' if ep.firewall_status == 'Enabled' else ('status-warn' if ep.firewall_status == 'Partial' else 'status-bad')
                av_color = 'status-good' if ep.antivirus_status == 'Active' else 'status-bad'
                disabled_profiles = self._disabled_firewall_profiles(ep)
                fw_note = f" ({', '.join(disabled_profiles)} disabled)" if disabled_profiles else ""
                # A device merged from both planes (matched by hostname — see
                # orchestrator._merge_endpoints) carries its Intune record
                # under metadata['intune']. Surface that here so the signal
                # isn't lost just because it's reported once, not twice.
                intune = (ep.metadata or {}).get('intune')
                if intune:
                    compliant = intune.get('is_compliant')
                    enc = intune.get('is_encrypted')
                    cm_color = 'status-good' if compliant else 'status-bad'
                    enc_note = 'encrypted' if enc else ('not encrypted' if enc is False else 'encryption unknown')
                    cloud_cell = (f"<span class=\"{cm_color}\">"
                                  f"{intune.get('compliance_state', 'Unknown')} ({enc_note})</span>")
                else:
                    cloud_cell = '<span class="na">No</span>'
                html += (
                    f"                <tr><td>{ep.hostname}</td><td>{ep.ip_address}</td>"
                    f"<td>{ep.os_version}</td>"
                    f"<td><span class=\"{fw_color}\">{ep.firewall_status or 'Unknown'}{fw_note}</span></td>"
                    f"<td><span class=\"{av_color}\">{ep.antivirus_status or 'Unknown'}</span></td>"
                    f"<td>{cloud_cell}</td>"
                    f"<td>{self._software_cell(ep, software_href)}</td>"
                    f"</tr>\n"
                )
            html += "            </table>\n        </div>\n"

        if cloud_eps:
            html += f"""        <div class="section" id="sec-cloud-devices">
            <h2>Cloud-Managed Devices (Intune)</h2>
            <table>
                <tr>
                    <th>Hostname</th><th>OS Version</th><th>Compliance State</th>
                    <th>Encrypted</th><th>Management State</th><th>Owner</th>
                    <th>Installed Software</th>
                </tr>
"""
            for ep in cloud_eps:
                meta = ep.metadata or {}
                compliant = meta.get('is_compliant')
                comp_color = 'status-good' if compliant else 'status-bad'
                enc = meta.get('is_encrypted')
                enc_color = 'status-good' if enc else 'status-warn'
                html += (
                    f"                <tr><td>{ep.hostname}</td><td>{ep.os_version}</td>"
                    f"<td><span class=\"{comp_color}\">{meta.get('compliance_state', 'Unknown')}</span></td>"
                    f"<td><span class=\"{enc_color}\">{enc}</span></td>"
                    f"<td>{meta.get('management_state', 'Unknown')}</td>"
                    f"<td>{meta.get('owner_upn', 'Unknown')}</td>"
                    f"<td>{self._software_cell(ep, software_href)}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        ad_users = self._ad_users(artifacts)
        if ad_users:
            html += f"""        <div class="section" id="sec-ad-users">
            <h2>Active Directory / Identity Objects — Users</h2>
            {self._satisfies_badge_html(['mfa_registration', 'account_identification', 'privileged_role_tracking'], present_evidence)}
            <table>
                <tr>
                    <th>Name</th><th>Source</th><th>Status</th><th>Guest</th>
                    <th>Stale</th><th>Privileged</th><th>MFA Registered</th><th>Group Memberships</th>
                </tr>
"""
            for u in ad_users:
                attrs = u.attributes or {}
                source = attrs.get('source', 'unknown')
                is_cloud = source == 'entra'
                name = attrs.get('displayName') or attrs.get('sAMAccountName') or u.distinguished_name

                if is_cloud:
                    enabled = attrs.get('accountEnabled')
                else:
                    disabled = attrs.get('disabled')
                    enabled = (not disabled) if disabled is not None else None
                status_color = 'status-good' if enabled else ('status-bad' if enabled is False else 'status-neutral')
                status_label = 'Enabled' if enabled else ('Disabled' if enabled is False else 'Unknown')

                is_guest = attrs.get('isGuest')
                guest_cell = ('Yes' if is_guest else 'No') if is_guest is not None else '<span class="na">N/A</span>'

                stale = attrs.get('isStale')
                stale_color = 'status-bad' if stale else ('status-good' if stale is False else 'status-neutral')
                stale_label = 'Yes' if stale else ('No' if stale is False else 'Unknown')

                # Privileged: True/False is a real answer either plane produced;
                # None means the lookup itself failed/wasn't attempted — shown
                # as Unknown, never silently rendered as "No".
                privileged = attrs.get('isPrivileged')
                roles = attrs.get('privilegedRoles') or []
                if privileged is True:
                    priv_color = 'status-bad'
                    priv_label = 'YES' + (f" ({', '.join(roles)})" if roles else " (privileged AD group)")
                elif privileged is False:
                    priv_color, priv_label = 'status-good', 'No'
                else:
                    priv_color, priv_label = 'status-neutral', 'Unknown'

                # MFA is a cloud-only concept today — on-prem AD has no MFA
                # signal, so it's N/A, not a false "No".
                mfa = attrs.get('isMfaRegistered')
                methods = attrs.get('mfaMethods') or []
                if not is_cloud:
                    mfa_cell = '<span class="na">N/A (on-prem)</span>'
                elif mfa is True:
                    method_note = f" ({', '.join(methods)})" if methods else ""
                    mfa_cell = f'<span class="status-good">Yes{method_note}</span>'
                elif mfa is False:
                    mfa_cell = '<span class="status-bad">No</span>'
                else:
                    mfa_cell = '<span class="status-neutral">Unknown</span>'

                html += (
                    f"                <tr><td>{name}</td><td>{'Entra ID' if is_cloud else 'On-Prem AD'}</td>"
                    f"<td><span class=\"{status_color}\">{status_label}</span></td>"
                    f"<td>{guest_cell}</td>"
                    f"<td><span class=\"{stale_color}\">{stale_label}</span></td>"
                    f"<td><span class=\"{priv_color}\">{priv_label}</span></td>"
                    f"<td>{mfa_cell}</td><td>{self._group_memberships_cell(u)}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        ad_groups = self._ad_groups(artifacts)
        if ad_groups:
            html += f"""        <div class="section" id="sec-ad-groups">
            <h2>Active Directory / Identity Objects — Groups</h2>
            {self._satisfies_badge_html(['guest_group_membership'], present_evidence)}
            <table>
                <tr><th>Name</th><th>Source</th><th>Description</th><th>Detail</th></tr>
"""
            for g in ad_groups:
                attrs = g.attributes or {}
                source = attrs.get('source', 'unknown')
                is_cloud = source == 'entra'
                name = attrs.get('displayName') or attrs.get('sAMAccountName') or g.distinguished_name
                desc = attrs.get('description') or '<span class="na">None</span>'
                if is_cloud:
                    role_assignable = attrs.get('roleAssignable')
                    sec_enabled = attrs.get('securityEnabled')
                    detail = (f"Security-enabled: {'Yes' if sec_enabled else 'No'}; "
                              f"Role-assignable: {'Yes' if role_assignable else 'No'}")
                else:
                    member_count = attrs.get('memberCount')
                    detail = f"{member_count} member(s)" if member_count is not None else '<span class="na">Unknown</span>'
                html += (
                    f"                <tr><td>{name}</td><td>{'Entra ID' if is_cloud else 'On-Prem AD'}</td>"
                    f"<td>{desc}</td><td>{detail}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        html += """        <div class="section">
            <h2>Findings &amp; Recommendations</h2>
"""
        for finding in findings:
            finding_class = "finding critical" if finding['severity'] == 'Critical' else "finding"
            if finding['severity'] == 'Resolved':
                finding_class = "finding resolved"
            html += (
                f"            <div class=\"{finding_class}\">\n"
                f"                <h4>{finding['title']}</h4>\n"
                f"                <p><strong>Severity:</strong> {finding['severity']}</p>\n"
                f"                <p><strong>Description:</strong> {finding['description']}</p>\n"
                f"            </div>\n"
                f"            <div class=\"recommendation\">"
                f"<strong>Recommendation:</strong> {finding['recommendation']}</div>\n"
            )
        html += "        </div>\n"

        if artifacts.policies:
            html += f"""        <div class="section" id="sec-policy-compliance">
            <h2>Policy Compliance</h2>
            {self._satisfies_badge_html(['config_enforcement', 'time_sync'], present_evidence)}
            <table>
                <tr><th>Policy</th><th>Type</th><th>Status</th><th>Current Value</th></tr>
"""
            for policy in artifacts.policies:
                passes = ComplianceScorer._policy_passes(policy)
                if passes is True:
                    status_color = 'status-good'
                elif passes is False:
                    status_color = 'status-bad'
                else:
                    status_color = 'status-neutral'  # informational / no specific rule — not a warning
                html += (
                    f"                <tr><td>{policy.policy_name}</td><td>{policy.policy_type}</td>"
                    f"<td><span class=\"{status_color}\">{policy.status}</span></td>"
                    f"<td>{policy.value or 'N/A'}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        html += self._generate_software_summary_link_html(artifacts, present_evidence, software_href)
        html += self._generate_security_events_html(artifacts, present_evidence)

        scope_items = []
        if onprem_eps:
            scope_items.append("Windows endpoint security configurations")
        if any(e.source not in _CLOUD_EVENT_SOURCES for e in artifacts.security_events):
            scope_items.append("Windows security event logging and monitoring")
        if any(e.source in _CLOUD_EVENT_SOURCES for e in artifacts.security_events):
            scope_items.append("Entra sign-in and directory audit log review")
        if any(p.policy_type == 'Local Security Policy' for p in artifacts.policies):
            scope_items.append("Local security and account lockout policy")
        if any(p.policy_type == 'Group Policy' for p in artifacts.policies):
            scope_items.append("Group Policy compliance")
        if any(p.policy_type == 'Audit Policy' for p in artifacts.policies):
            scope_items.append("Audit policy configuration")
        if any(p.policy_type == 'Conditional Access' for p in artifacts.policies):
            scope_items.append("Entra Conditional Access policy configuration")
        if any(p.policy_type == 'Intune Configuration Profile' for p in artifacts.policies):
            scope_items.append("Intune device configuration profile deployment status")
        if any((o.attributes or {}).get('source') == 'entra' for o in artifacts.ad_objects):
            scope_items.append("Entra ID identity and access configuration")
        if any((o.attributes or {}).get('source') != 'entra' for o in artifacts.ad_objects):
            scope_items.append("Active Directory policy implementations")
        if cloud_eps:
            scope_items.append("Intune device compliance and management status")
        if onprem_eps:
            scope_items.append("Firewall and antivirus deployment status (on-prem)")
        if not scope_items:
            scope_items.append("No collection data was available for this assessment")

        scope_html = "\n".join(f"                <li>{item}</li>" for item in scope_items)

        html += f"""
        <div class="section">
            <h2>Assessment Scope</h2>
            <p>This assessment evaluated:</p>
            <ul>
{scope_html}
            </ul>
        </div>

        <div class="footer">
            <p><strong>Assessment Disclaimer:</strong> This report is generated for compliance
            assessment purposes. Recommendations should be reviewed by qualified security
            professionals before implementation.</p>
            <p>Generated by: CMMC Artifact Toolkit | Assessment ID: {assessment_id}</p>
        </div>
    </div>
</body>
</html>"""
        return html

    # Maps each evidence_key to the anchor id of the actual report section
    # that displays it — kept here, not in control_mapping.py, since this is
    # about THIS report's layout, not CMMC semantics. Update this whenever a
    # new section is added or an evidence type moves to a different one.
    _EVIDENCE_SECTION_ANCHORS: Dict[str, str] = {
        'firewall_status': 'sec-onprem-endpoints',
        'antivirus_status': 'sec-onprem-endpoints',
        'patch_level': 'sec-onprem-endpoints',
        'installed_software': 'sec-software-inventory',
        'config_enforcement': 'sec-policy-compliance',
        'time_sync': 'sec-policy-compliance',
        'audit_log_collection': 'sec-security-events',
        'audit_user_traceability': 'sec-security-events',
        'mfa_registration': 'sec-ad-users',
        'account_identification': 'sec-ad-users',
        'privileged_role_tracking': 'sec-ad-users',
        'guest_group_membership': 'sec-ad-groups',
    }

    def _present_evidence_keys(self, artifacts: Any, onprem_eps: List, cloud_eps: List, ad_users: List) -> List[str]:
        """Determine which control_mapping.EVIDENCE_MAP keys have real data
        in THIS specific report — not which evidence types the tool
        theoretically supports, but which ones actually fired this run. A
        cloud-only tenant shouldn't claim firewall-status evidence just
        because the on-prem collector exists in the codebase somewhere.

        To add a new evidence type later: add its detection line here, and
        one EvidenceMapping entry in control_mapping.py. Nothing else needs
        to change for it to appear in the domain coverage nav and section
        badges.
        """
        present = []

        if any(getattr(u, 'attributes', {}).get('isMfaRegistered') is not None for u in ad_users):
            present.append('mfa_registration')
        elif any(p.policy_type == 'Conditional Access' for p in artifacts.policies):
            present.append('mfa_registration')

        if any(p.policy_type == 'Time Synchronization' for p in artifacts.policies):
            present.append('time_sync')

        if any(self._software_list(ep) for ep in artifacts.endpoints):
            present.append('installed_software')

        if any(p.policy_type in ('UAC (Local Policy)', 'Local Security Policy', 'Intune Configuration Profile')
               for p in artifacts.policies):
            present.append('config_enforcement')

        if artifacts.security_events:
            present.append('audit_log_collection')

        if any(e.user for e in artifacts.security_events):
            present.append('audit_user_traceability')

        if any(ep.antivirus_status is not None for ep in onprem_eps):
            present.append('antivirus_status')

        if any(ep.installed_updates for ep in onprem_eps):
            present.append('patch_level')

        if ad_users:
            present.append('account_identification')

        if onprem_eps:
            present.append('firewall_status')

        if any(getattr(u, 'attributes', {}).get('isPrivileged') is not None for u in ad_users):
            present.append('privileged_role_tracking')

        if any(getattr(u, 'attributes', {}).get('isGuest') is not None for u in ad_users):
            present.append('guest_group_membership')

        return present

    def _build_scoring_breakdown_html(self, artifacts: Any) -> str:
        """Show the actual math behind the overall score — every category,
        its weight, its individual score (or N/A), and its weighted
        contribution. Previously this data was computed every run (visible
        in the console output) but never shown in the report at all — a
        client or assessor seeing only the final percentage has no way to
        verify or even understand how it was derived, which is a real
        problem the moment anyone asks "how did you get this number?"
        """
        scores = ComplianceScorer._all_dimension_scores(artifacts)
        weights = ComplianceScorer.SCORE_WEIGHTS
        descriptions = ComplianceScorer.DIMENSION_DESCRIPTIONS
        total_weight = sum(weights.values())
        applicable_weight = sum(weights[d] for d, s in scores.items() if s is not None)

        rows = []
        for dim, weight in weights.items():
            score = scores.get(dim)
            label = dim.replace('_', ' ').title()
            desc = descriptions.get(dim, '')
            if score is None:
                score_cell = '<span class="na">N/A — no applicable data</span>'
                contribution_cell = '<span class="na">excluded from calculation</span>'
            else:
                score_color = 'status-good' if score >= 80 else ('status-warn' if score >= 60 else 'status-bad')
                # Contribution shown as % of the FINAL score this category is
                # responsible for, i.e. its share of the applicable weight —
                # matches how calculate_overall_score actually renormalizes,
                # rather than showing a share of the full 100-point scale
                # that would be wrong whenever coverage is incomplete.
                share_of_applicable = (weight / applicable_weight * 100) if applicable_weight else 0
                score_cell = f'<span class="{score_color}">{score}/100</span>'
                contribution_cell = f'{share_of_applicable:.0f}% of final score'
            rows.append(
                f"                <tr><td>{label}</td><td>{weight}</td>"
                f"<td>{score_cell}</td><td>{contribution_cell}</td>"
                f"<td style=\"font-size:0.88em;color:#475569;\">{desc}</td></tr>\n"
            )

        note = ""
        if applicable_weight < total_weight:
            note = (
                f'<p style="font-size:0.88em;color:#64748b;margin-top:10px;">'
                f'Only categories with applicable data count toward the score — the weights '
                f'above are renormalized across those {applicable_weight} of {total_weight} '
                f'total weight points, not the full scale. This is why a tenant assessed on '
                f'fewer categories can still show a high score: see the Scoring Coverage figure '
                f'above for how much of the framework that represents.</p>'
            )

        return f"""        <div class="section">
            <h2>Scoring Breakdown</h2>
            <p style="font-size:0.92em;color:#475569;">
                The overall score is a weighted average across the six categories below.
                Each category is scored 0-100 independently; categories with no applicable
                data are excluded from the average entirely rather than counted as a failure.
            </p>
            <table>
                <tr><th>Category</th><th>Weight</th><th>Score</th><th>Share of Final Score</th><th>What It Measures</th></tr>
{"".join(rows)}
            </table>
            {note}
        </div>
"""

    def _build_domain_coverage_html(self, present_evidence_keys: List[str]) -> str:
        """Render the domain-family navigation section — the "sheets" view.
        Only domains with at least one practice actually evidenced in this
        report appear; a domain this toolkit collects nothing for (e.g. MP,
        PE, PS) is correctly absent rather than shown empty or padded out.

        Each evidence line links to the actual section that displays it
        (via _EVIDENCE_SECTION_ANCHORS), not a generic per-domain anchor —
        several existing sections span more than one domain's worth of
        evidence at once (the endpoint table alone covers SC, SI, and CM),
        so a single "domain anchor" wouldn't correctly point anywhere.
        """
        coverage = cm.domain_coverage(present_evidence_keys)
        if not coverage:
            return ""

        # Reverse-lookup: for a given practice+evidence label, find which
        # evidence_key produced it, so we can look up its section anchor.
        label_to_key = {ev.label: ev.evidence_key for ev in cm.EVIDENCE_MAP}

        sections = []
        for domain, entries in coverage.items():
            items = []
            for entry in entries:
                practice = entry["practice"]
                has_supporting = any(conf == cm.Confidence.SUPPORTING for _, conf in entry["evidence"])
                badge_class = "supporting" if has_supporting else "direct"
                evidence_links = []
                for label, _ in entry["evidence"]:
                    key = label_to_key.get(label)
                    anchor = self._EVIDENCE_SECTION_ANCHORS.get(key, "")
                    if anchor:
                        evidence_links.append(f'<a href="#{anchor}">{label}</a>')
                    else:
                        evidence_links.append(label)
                items.append(
                    f'<li><span class="badge {badge_class}">{practice.practice_id}</span> '
                    f'{practice.short_name} — {"; ".join(evidence_links)}</li>'
                )
            sections.append(
                f'<li><strong>{domain} — {cm.DOMAIN_NAMES[domain]}</strong>'
                f'<ul>{"".join(items)}</ul></li>'
            )

        return f"""
        <div class="section domain-nav">
            <h3>Practices Evidenced in This Assessment</h3>
            <p class="confidence-key">
                <span class="badge direct">Direct</span> = evidence maps one-to-one to the practice's
                assessment objective &nbsp;&nbsp;
                <span class="badge supporting">Supporting</span> = real, relevant evidence that
                partially — not fully — satisfies the practice
            </p>
            <ul>
{"".join(sections)}
            </ul>
        </div>"""

    @staticmethod
    def _satisfies_badge_html(evidence_keys: List[str], present_evidence_keys: List[str]) -> str:
        """Render the "Satisfies:" badge line shown under a section heading.
        Filters to only the keys actually present in this report, so a
        badge never claims coverage the data doesn't back up.

        A practice's badge is DIRECT if any active evidence mapped to it is
        DIRECT, otherwise SUPPORTING — i.e. shown at the best confidence
        level the evidence actually present in this report can support.
        """
        active_keys = [k for k in evidence_keys if k in present_evidence_keys]
        if not active_keys:
            return ""

        practice_confidence: Dict[str, cm.Confidence] = {}
        for key in active_keys:
            ev = cm.get_evidence(key)
            for pid in ev.practice_ids:
                if practice_confidence.get(pid) != cm.Confidence.DIRECT:
                    practice_confidence[pid] = ev.confidence

        if not practice_confidence:
            return ""
        badges = "".join(
            f'<span class="badge {conf.value}">{pid}</span>'
            for pid, conf in sorted(practice_confidence.items())
        )
        return f'<div class="control-badges">Satisfies: {badges}</div>'

    def _software_inventory_data(self, artifacts: Any) -> tuple:
        """Shared computation for both the main report's short summary and
        the standalone software-inventory page, so the two can never
        disagree about counts or which devices are missing and why.

        Returns (grouped, by_status):
          grouped   — {(name, version, publisher): [hostnames]}, deduplicated
          by_status — {status: [hostnames]} for every non-'ok' endpoint,
                      grouped by _software_status
        """
        grouped: Dict[tuple, List[str]] = {}
        for ep in artifacts.endpoints:
            for s in self._software_list(ep):
                key = (s.get('name', 'Unknown'), s.get('version') or '', s.get('publisher') or '')
                grouped.setdefault(key, []).append(ep.hostname)

        by_status: Dict[str, List[str]] = {}
        for ep in artifacts.endpoints:
            status = self._software_status(ep)
            if status != 'ok':
                by_status.setdefault(status, []).append(ep.hostname)

        return grouped, by_status

    @staticmethod
    def _software_status_notes_html(by_status: Dict[str, List[str]]) -> str:
        """Explain any device NOT contributing to the software inventory,
        grouped by why — so a client/assessor (or you, six months from now)
        doesn't have to guess whether "only one device shows software" is a
        bug or a real device state."""
        status_notes = []
        if by_status.get('failed'):
            status_notes.append(
                f"<li><strong>Collection failed</strong> for: {', '.join(sorted(by_status['failed']))}. "
                f"The collector's Graph/PowerShell call errored for these devices — check the "
                f"collection console log for the specific error.</li>"
            )
        if by_status.get('empty_confirmed'):
            status_notes.append(
                f"<li><strong>Confirmed empty</strong> for: {', '.join(sorted(by_status['empty_confirmed']))}. "
                f"Collection succeeded, but no software was inventoried — for Intune-managed devices this "
                f"commonly means the device hasn't completed an app-inventory sync yet, which is a real "
                f"device state, not a collection error.</li>"
            )
        if by_status.get('not_attempted'):
            status_notes.append(
                f"<li><strong>Not attempted</strong> for: {', '.join(sorted(by_status['not_attempted']))}.</li>"
            )
        if not status_notes:
            return ""
        return (
            '<div class="recommendation"><strong>Devices not contributing to the inventory above, and why:</strong>'
            f'<ul>{"".join(status_notes)}</ul></div>'
        )

    @staticmethod
    def _software_table_rows_html(grouped: Dict[tuple, List[str]]) -> str:
        rows = []
        for (name, version, publisher), hosts in sorted(grouped.items(), key=lambda kv: kv[0][0].lower()):
            unique_hosts = sorted(set(hosts))
            rows.append(
                f"                <tr><td>{name}</td><td>{version or '<span class=\"na\">N/A</span>'}</td>"
                f"<td>{publisher or '<span class=\"na\">Unknown</span>'}</td>"
                f"<td>{', '.join(unique_hosts)}</td></tr>\n"
            )
        return "".join(rows)

    def _generate_software_summary_link_html(self, artifacts: Any, present_evidence: List[str],
                                              software_href: Optional[str]) -> str:
        """Short in-main-report summary: counts, the "why is a device
        missing" disclosure (kept inline since it's short and directly
        answers a real question), and a link out to the standalone page
        that holds the full, potentially very long table. Previously the
        full table lived inline here too — moved out because it will only
        keep growing as more devices/software get collected, and updating
        the software list shouldn't require regenerating the whole
        compliance report."""
        if 'installed_software' not in present_evidence:
            return ""

        grouped, by_status = self._software_inventory_data(artifacts)
        if not grouped:
            return ""

        badge = self._satisfies_badge_html(['installed_software'], present_evidence)
        notes_html = self._software_status_notes_html(by_status)
        href = software_href or "software_inventory.html"
        return f"""        <div class="section" id="sec-software-inventory">
            <h2>Installed Software Inventory</h2>
            {badge}
            <p>{len(grouped)} unique software package(s) across {len(artifacts.endpoints)} endpoint(s) —
            see the full list in <a href="{href}">{href}</a>.</p>
            {notes_html}
        </div>
"""

    def _generate_software_inventory_page(self, artifacts: Any, customer_name: Optional[str],
                                           assessment_id: Optional[str], back_href: str) -> str:
        """The standalone software-inventory page itself — a complete,
        self-contained HTML document (same shared stylesheet as the main
        report) so it can be regenerated and updated independently without
        touching the main compliance report at all."""
        grouped, by_status = self._software_inventory_data(artifacts)
        rows_html = self._software_table_rows_html(grouped)
        notes_html = self._software_status_notes_html(by_status)
        customer_name = customer_name or "Unnamed Customer"
        assessment_id = assessment_id or "CMMC-" + datetime.now().strftime("%Y%m%d%H%M%S")

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Installed Software Inventory — {customer_name}</title>
    <style>{_BASE_CSS}</style>
</head>
<body>
    <div class="header">
        <h1>Installed Software Inventory</h1>
        <div class="subtitle">{customer_name} — {assessment_id}</div>
    </div>
    <div class="content">
        <p class="back-link"><a href="{back_href}">&larr; Back to main compliance report</a></p>
        <div class="section" id="sec-software-inventory-table">
            <h2>Software Packages</h2>
            <p>{len(grouped)} unique software package(s) across {len(artifacts.endpoints)} endpoint(s).</p>
            <table>
                <tr><th>Name</th><th>Version</th><th>Publisher</th><th>Found On</th></tr>
{rows_html}
            </table>
            {notes_html}
        </div>
        <p class="back-link"><a href="{back_href}">&larr; Back to main compliance report</a></p>
    </div>
</body>
</html>"""

    def _generate_security_events_html(self, artifacts: Any, present_evidence: List[str]) -> str:
        """Security events were being collected and scored but never
        actually shown anywhere in the report — same blind spot the AD
        tables had before. Can't dump potentially thousands of raw events
        into one HTML file, so this shows EVERY Critical/Error event (the
        actual audit-relevant ones) up to a sane cap, plus a small sample of
        Information-level events for context — with an explicit disclosure
        of exactly how much is shown out of the real total, so this never
        reads as a complete dump when it isn't.
        """
        if 'audit_log_collection' not in present_evidence:
            return ""

        events = artifacts.security_events
        if not events:
            return ""

        MAX_SEVERE_ROWS = 200
        SAMPLE_INFO_ROWS = 10

        severe = [e for e in events if e.level in ('Critical', 'Error')]
        informational = [e for e in events if e.level not in ('Critical', 'Error')]
        shown_severe = severe[:MAX_SEVERE_ROWS]
        shown_info = informational[:SAMPLE_INFO_ROWS]

        by_level: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for e in events:
            by_level[e.level] = by_level.get(e.level, 0) + 1
            by_source[e.source] = by_source.get(e.source, 0) + 1

        summary_rows = "".join(
            f"                <tr><td>{level}</td><td>{count}</td></tr>\n"
            for level, count in sorted(by_level.items(), key=lambda kv: -kv[1])
        )
        source_rows = "".join(
            f"                <tr><td>{source}</td><td>{count}</td></tr>\n"
            for source, count in sorted(by_source.items(), key=lambda kv: -kv[1])
        )

        def event_row(e) -> str:
            level_color = {'Critical': 'status-bad', 'Error': 'status-bad', 'Warning': 'status-warn'}.get(e.level, 'status-neutral')
            msg = (e.message or '').replace('\r\n', ' ').replace('\n', ' ')
            if len(msg) > 150:
                msg = msg[:150] + "…"
            return (
                f"                <tr><td>{e.timestamp}</td><td>{e.source}</td>"
                f"<td><span class=\"{level_color}\">{e.level}</span></td>"
                f"<td>{e.user or '<span class=\"na\">N/A</span>'}</td><td>{msg}</td></tr>\n"
            )

        disclosure_bits = []
        if len(severe) > MAX_SEVERE_ROWS:
            disclosure_bits.append(f"{MAX_SEVERE_ROWS} of {len(severe)} Critical/Error events shown")
        else:
            disclosure_bits.append(f"all {len(severe)} Critical/Error event(s) shown")
        disclosure_bits.append(f"{len(shown_info)} of {len(informational)} Information-level event(s) shown as a sample")

        badge = self._satisfies_badge_html(['audit_log_collection', 'audit_user_traceability'], present_evidence)
        html = f"""        <div class="section" id="sec-security-events">
            <h2>Security Events</h2>
            {badge}
            <p>{len(events)} total event(s) collected. {'; '.join(disclosure_bits)}.</p>
            <table>
                <tr><th>Level</th><th>Count</th></tr>
{summary_rows}
            </table>
            <table>
                <tr><th>Source</th><th>Count</th></tr>
{source_rows}
            </table>
"""
        if shown_severe:
            html += """            <h3>Critical / Error Events</h3>
            <table>
                <tr><th>Timestamp</th><th>Source</th><th>Level</th><th>User</th><th>Message</th></tr>
"""
            html += "".join(event_row(e) for e in shown_severe)
            html += "            </table>\n"

        if shown_info:
            html += """            <h3>Sample Information-Level Events</h3>
            <table>
                <tr><th>Timestamp</th><th>Source</th><th>Level</th><th>User</th><th>Message</th></tr>
"""
            html += "".join(event_row(e) for e in shown_info)
            html += "            </table>\n"

        html += "        </div>\n"
        return html

    @staticmethod
    def _intune_signal(ep: Any) -> Dict[str, Any]:
        """Return this endpoint's Intune metadata regardless of whether it's a
        pure cloud device or a hybrid device merged with its on-prem record
        (orchestrator._merge_endpoints nests the Intune data under
        metadata['intune'] for merges). Returns {} when there's no Intune
        signal at all, so callers can treat a merged and a standalone Intune
        device identically without duplicating a check for each shape."""
        meta = ep.metadata or {}
        return meta.get('intune') or (meta if meta.get('source') == 'intune' else {})

    @staticmethod
    def _disabled_firewall_profiles(ep: Any) -> List[str]:
        """Return which specific Windows Firewall profile(s) (Domain/Private/
        Public) are disabled on this endpoint, from the per-profile detail
        the collector already gathers (metadata['firewall_profiles']) but the
        report wasn't previously surfacing — 'Partial' alone doesn't tell an
        MSP or client which profile needs attention, or whether it's the
        Public profile (internet-facing, higher risk) or Domain (usually
        lower risk on a managed network).

        NOTE: this reflects only the built-in Windows Firewall profile
        toggle. A profile showing disabled does NOT necessarily mean the
        machine is unprotected — a third-party firewall/EDR product may be
        enforcing blocking instead, intentionally with Windows Firewall
        turned off to avoid rule conflicts. This method can't tell the two
        apart; that judgment call belongs to whoever reviews the finding.
        """
        profiles = (ep.metadata or {}).get('firewall_profiles') or []
        return [p.get('Name', 'Unknown') for p in profiles if not p.get('Enabled')]

    @staticmethod
    def _software_list(ep: Any) -> List[Dict[str, Any]]:
        """Return this endpoint's installed-software inventory (CM.L2-3.4.1
        evidence) regardless of whether it came from the on-prem registry
        scan or Intune's detectedApps, and regardless of whether this is a
        standalone or merged (orchestrator._merge_endpoints) record.

        For a merged hybrid device, the on-prem list (top-level metadata) is
        preferred over the nested Intune one — the registry-based on-prem
        scan is generally more complete than Intune's detected-apps list, so
        showing both would mostly just duplicate the same entries twice
        rather than add real information.
        """
        meta = ep.metadata or {}
        direct = meta.get('installed_software')
        if direct:
            return direct
        intune = meta.get('intune') or {}
        return intune.get('installed_software') or []

    @staticmethod
    def _software_status(ep: Any) -> str:
        """Distinguish WHY an endpoint's software list might be empty —
        previously "collection failed" and "genuinely no software
        inventoried yet" both collapsed into the same "Not collected" cell,
        which is exactly what made it impossible to tell, from the report
        alone, whether only one device out of several showing software was
        a real bug or a real gap in that device's own Intune inventory sync.

        Returns one of:
          'ok'               — real software data present
          'empty_confirmed'  — collection succeeded; device genuinely has
                                no inventoried software (e.g. hasn't
                                completed an Intune app-inventory sync yet —
                                a real device state, not an error)
          'failed'           — the collection attempt itself errored
          'not_attempted'    — no software collection ran for this endpoint
                                at all (e.g. a plane/collector that doesn't
                                gather this)
        """
        meta = ep.metadata or {}
        intune = meta.get('intune') or {}

        for source in (meta, intune):
            if 'installed_software' in source:
                if source.get('software_collection_failed'):
                    return 'failed'
                return 'ok' if source['installed_software'] else 'empty_confirmed'

        # On-prem: a software-section failure shows up in collection_errors
        # (Try-Section prefixes it "software: ..."), which is already
        # collected but wasn't being checked here.
        errors = meta.get('collection_errors') or []
        if any('software' in e.lower() for e in errors):
            return 'failed'
        return 'not_attempted'

    @staticmethod
    def _software_cell(ep: Any, software_href: Optional[str] = None) -> str:
        """A count + jump-link to the consolidated Installed Software
        Inventory — now the standalone page, linked via software_href, not
        an in-page anchor (the full table no longer lives in the main
        report at all). Falls back to a same-page anchor only if no href
        was supplied (e.g. a direct call bypassing export())."""
        status = MSPReportExporter._software_status(ep)
        if status == 'ok':
            count = len(MSPReportExporter._software_list(ep))
            href = f"{software_href}#sec-software-inventory-table" if software_href else "#sec-software-inventory"
            return f'<a href="{href}">{count} package(s)</a>'
        if status == 'empty_confirmed':
            return '<span class="na">None detected</span>'
        if status == 'failed':
            return '<span class="status-bad">Collection failed</span>'
        return '<span class="na">Not collected</span>'

    @staticmethod
    def _group_names_from_memberships(memberships: List[str]) -> List[str]:
        """Extract a readable group name from each raw group_memberships
        entry. On-prem AD gives full distinguished names (e.g.
        "CN=Domain Admins,OU=Groups,DC=corp,DC=local") — only the CN=
        component is shown. Entra's group_memberships already contain plain
        display names (no DN to parse), so anything without a leading "CN="
        passes through unchanged."""
        names = []
        for m in memberships or []:
            if m.upper().startswith("CN="):
                names.append(m.split(",", 1)[0][3:])
            else:
                names.append(m)
        return names

    @staticmethod
    def _group_memberships_cell(u: Any) -> str:
        """Render a collapsed, expandable group-membership list for one user
        row — same <details>/<summary> pattern as _software_cell, since a
        user can belong to many groups and an always-visible list would
        make the table unreadable. On-prem: this data was already being
        collected (LDAP returns memberOf directly, essentially free) but
        never displayed. Entra: collected via a per-user memberOf call
        added alongside this display change."""
        names = MSPReportExporter._group_names_from_memberships(getattr(u, 'group_memberships', None))
        if not names:
            return '<span class="na">None recorded</span>'
        unique_names = sorted(set(names))
        items = "".join(f"<li>{n}</li>" for n in unique_names)
        return (
            f'<details><summary>{len(unique_names)} group(s)</summary>'
            f'<ul style="margin:6px 0 0 18px;font-size:0.85em;max-height:150px;'
            f'overflow-y:auto;">{items}</ul></details>'
        )

    def _generate_findings(self, artifacts: Any) -> List[Dict[str, str]]:
        findings = []
        onprem_eps = self._onprem_endpoints(artifacts)
        cloud_eps = self._cloud_endpoints(artifacts)
        # Every device with an Intune signal, whether reported standalone
        # (cloud_eps) or merged into an on-prem record — so a hybrid device's
        # non-compliance/encryption status is never silently dropped just
        # because it's now counted once instead of twice.
        intune_eps = [ep for ep in artifacts.endpoints if self._intune_signal(ep)]

        # On-prem-only checks: cloud endpoints deliberately have these fields
        # set to None (not applicable), so they must never be evaluated here.
        disabled_firewalls = [
            ep.hostname for ep in onprem_eps if ep.firewall_status != "Enabled"
        ]
        if disabled_firewalls:
            # Per-host detail on WHICH profile(s) are off, not just that the
            # status is "Partial" — a client/MSP can't act on "not fully
            # enabled" alone, but "Public profile disabled on ROYEPC" is
            # actionable (and Public vs. Domain carries very different risk).
            detail_lines = []
            for ep in onprem_eps:
                if ep.firewall_status == "Enabled":
                    continue
                disabled_profiles = self._disabled_firewall_profiles(ep)
                if disabled_profiles:
                    detail_lines.append(f"{ep.hostname}: {', '.join(disabled_profiles)} profile(s) disabled")
                else:
                    detail_lines.append(f"{ep.hostname}: status '{ep.firewall_status}' (profile detail unavailable)")
            findings.append({
                'title': 'Firewall Not Fully Enabled',
                'severity': 'Critical',
                'description': (f'Firewall is not fully enabled on: {", ".join(disabled_firewalls)}. '
                                 + ' | '.join(detail_lines)),
                'recommendation': 'Enable Windows Firewall on all profiles for all on-prem endpoints. '
                                   'NOTE: this reflects the built-in Windows Firewall profile toggle only — '
                                   'if a third-party firewall or EDR product is intentionally handling '
                                   'blocking on the affected profile(s), confirm that before remediating, '
                                   'rather than assuming the device is unprotected.',
            })

        inactive_av = [
            ep.hostname for ep in onprem_eps if ep.antivirus_status != "Active"
        ]
        if inactive_av:
            findings.append({
                'title': 'Antivirus Not Active',
                'severity': 'Critical',
                'description': f'Antivirus is inactive on: {", ".join(inactive_av)}',
                'recommendation': 'Deploy and activate antivirus protection on all on-prem endpoints',
            })

        # Identity findings: privileged-account and MFA data was collected
        # specifically to satisfy IA.L2-3.5.3's evidence requirement
        # ("privileged accounts are identified"), but until now it only fed
        # the ad_security score number — it was never surfaced as an actual
        # finding. A privileged account without MFA is a real, high-severity
        # gap on its own, independent of the overall AD/identity score.
        ad_users = self._ad_users(artifacts)
        privileged_no_mfa = [
            (u.attributes or {}).get('displayName') or (u.attributes or {}).get('sAMAccountName') or u.distinguished_name
            for u in ad_users
            if (u.attributes or {}).get('isPrivileged') is True
            and (u.attributes or {}).get('isMfaRegistered') is False
        ]
        if privileged_no_mfa:
            findings.append({
                'title': 'Privileged Account Without MFA',
                'severity': 'Critical',
                'description': f'The following privileged accounts do not have MFA registered: '
                                f'{", ".join(privileged_no_mfa)}',
                'recommendation': 'Enforce MFA registration for all privileged accounts immediately '
                                   '(Conditional Access policy for Entra, or a compensating on-prem '
                                   'control). A privileged account without MFA is one of the highest-'
                                   'value targets for compromise and directly implicates IA.L2-3.5.3.',
            })

        # Stale accounts still holding privileged roles — the isStale flag
        # alone is scored, but a privileged + stale combination is worth its
        # own finding: it means someone with elevated access hasn't signed
        # in recently, which is exactly the kind of orphaned-access risk
        # CMMC account-management controls are meant to catch.
        stale_privileged = [
            (u.attributes or {}).get('displayName') or (u.attributes or {}).get('sAMAccountName') or u.distinguished_name
            for u in ad_users
            if (u.attributes or {}).get('isPrivileged') is True
            and (u.attributes or {}).get('isStale') is True
        ]
        if stale_privileged:
            findings.append({
                'title': 'Stale Privileged Account',
                'severity': 'High',
                'description': f'The following privileged accounts have not signed in recently: '
                                f'{", ".join(stale_privileged)}',
                'recommendation': 'Review whether these privileged accounts are still needed. If not, '
                                   'disable or remove them. If needed but inactive, confirm the account '
                                   'is not orphaned from a departed employee or unused service account.',
            })

        # Cloud-native finding, using the real Intune compliance signal instead
        # of borrowing on-prem checks that don't apply to these devices.
        # Checked against every device with Intune data (intune_eps), not
        # just cloud_eps, so a hybrid on-prem+Intune device's non-compliance
        # still surfaces here even though it's no longer counted separately.
        noncompliant_cloud = [
            ep.hostname for ep in intune_eps if not self._intune_signal(ep).get('is_compliant')
        ]
        if noncompliant_cloud:
            findings.append({
                'title': 'Intune Device Non-Compliant',
                'severity': 'Critical',
                'description': f'The following managed devices are non-compliant per Intune: '
                                f'{", ".join(noncompliant_cloud)}',
                'recommendation': 'Review the failing compliance policy in Intune for each device '
                                   'and remediate (encryption, OS version, or configuration drift).',
            })

        # Encryption checked directly, independent of Intune's own 'compliant'
        # verdict — that verdict reflects whatever compliance policy the
        # tenant configured, which may not require encryption at all. Only
        # flag when we affirmatively know it's False (metadata is not None),
        # never when the value is unknown. Same intune_eps basis as above.
        unencrypted_cloud = [
            ep.hostname for ep in intune_eps
            if self._intune_signal(ep).get('is_encrypted') is False
        ]
        if unencrypted_cloud:
            findings.append({
                'title': 'Device Not Encrypted',
                'severity': 'Critical',
                'description': f'The following managed devices are not encrypted: '
                                f'{", ".join(unencrypted_cloud)}',
                'recommendation': 'Enable BitLocker (or platform-equivalent encryption) via an '
                                   'Intune disk encryption policy. Data at rest on unencrypted '
                                   'devices is a direct risk to CUI protection requirements, '
                                   'regardless of the device\'s overall Intune compliance state.',
            })

        # Policy findings reuse the same pass/fail rules as the scorer, so an
        # inverted setting (e.g. ClearTextPassword should be Disabled) is
        # judged correctly instead of a blind status == "Disabled" check.
        # Grouped by policy_type instead of one flat list, so a report
        # doesn't mix e.g. password-policy failures with two dozen individual
        # audit subcategories in a single unreadable blob.
        failing_by_type: Dict[str, List[str]] = {}
        for p in artifacts.policies:
            if ComplianceScorer._policy_passes(p) is False:
                failing_by_type.setdefault(p.policy_type, []).append(p.policy_name)

        type_config = {
            'Local Security Policy': (
                'Password & Account Lockout Policy Below Baseline', 'High',
                'Review and strengthen password and account lockout settings via Local '
                'Security Policy or Group Policy.',
            ),
            'UAC (Local Policy)': (
                'UAC Settings Below Baseline', 'High',
                'Review User Account Control settings via Local Security Policy or Group Policy.',
            ),
            'Audit Policy': (
                None, 'High',  # title built dynamically below with the real count
                'Enable auditing for these subcategories via auditpol or Group Policy '
                '(Advanced Audit Policy Configuration). Comprehensive audit logging is '
                'directly relevant to the Audit and Accountability (AU) CMMC practice family.',
            ),
            'Conditional Access': (
                'Conditional Access Policy Not Enforced', 'High',
                'Review the affected Conditional Access polic(ies) in the Entra admin '
                'center. A policy in "report-only" or "disabled" state provides no real '
                'enforcement — move it to enabled once validated, or confirm the disabled '
                'state is intentional (e.g. a deprecated policy pending removal).',
            ),
            'Intune Configuration Profile': (
                'Intune Configuration Profile Deployment Failing', 'High',
                'Review the failing device(s) for the affected configuration profile(s) '
                'in the Intune admin center. Common causes include a device being '
                'offline, failing a prerequisite, or an OS version incompatible with the '
                'profile\'s settings.',
            ),
            'Time Synchronization': (
                'Time Synchronization Not Configured', 'Medium',
                'Configure the Windows Time service (w32tm) to synchronize with a '
                'reliable time source — an NTP server, or the domain hierarchy if '
                'domain-joined. Accurate, synchronized time stamps are required for '
                'meaningful audit log correlation across systems (AU.L2-3.3.7).',
            ),
        }
        for policy_type, names in failing_by_type.items():
            title, severity, recommendation = type_config.get(
                policy_type,
                (f'{policy_type} Settings Below Baseline', 'High',
                 'Review and remediate these settings via Group Policy or local security policy.'),
            )
            if policy_type == 'Audit Policy':
                title = f'Audit Policy: {len(names)} Categor{"y" if len(names) == 1 else "ies"} Not Logging'
            findings.append({
                'title': title,
                'severity': severity,
                'description': f'The following settings do not meet the recommended baseline: '
                                f'{", ".join(names)}',
                'recommendation': recommendation,
            })

        if not findings:
            findings.append({
                'title': 'Security Baseline Met',
                'severity': 'Resolved',
                'description': 'All monitored security controls are properly configured',
                'recommendation': 'Continue regular compliance monitoring and updates',
            })

        return findings

    @staticmethod
    def _generate_coverage_notes(artifacts: Any, onprem_eps: List, cloud_eps: List) -> List[str]:
        """Disclose categories with zero data for a plane that's actually
        present, so a clean score never reads as 'everything was checked'
        when large categories were never assessed. Returns an empty list
        when there's nothing to disclose.

        Checks by SOURCE (cloud vs. on-prem policy_type / event source), not
        by whether artifacts.policies/security_events is empty overall — a
        tenant running both planes could have real on-prem policy data while
        the cloud policy collector returned nothing, and the original
        aggregate-emptiness check would have missed that gap entirely.
        """
        notes = []

        has_cloud_policies = any(p.policy_type in _CLOUD_POLICY_TYPES for p in artifacts.policies)
        has_cloud_events = any(e.source in _CLOUD_EVENT_SOURCES for e in artifacts.security_events)
        has_onprem_policies = any(p.policy_type not in _CLOUD_POLICY_TYPES for p in artifacts.policies)
        has_onprem_events = any(e.source not in _CLOUD_EVENT_SOURCES for e in artifacts.security_events)

        if cloud_eps and not has_cloud_policies:
            notes.append(
                'Cloud-managed policy configuration (Entra Conditional Access, Intune '
                'configuration profiles) returned no data for this assessment. This may '
                'mean none are configured in this tenant, or that the collector could not '
                'reach them — check for a Policy.Read.All / '
                'DeviceManagementConfiguration.Read.All permission gap before assuming '
                'the tenant genuinely has no policies configured.'
            )
        if cloud_eps and not has_cloud_events:
            notes.append(
                'Cloud identity sign-in and audit log review returned no data for this '
                'assessment. This may reflect a genuine sign-in log retention limit on '
                'the tenant\'s Entra ID license tier, an empty lookback window, or an '
                'AuditLog.Read.All permission gap.'
            )
        if onprem_eps and not has_onprem_policies:
            notes.append(
                'On-prem security policy data was not available for this assessment '
                '(no records were returned by the collector).'
            )
        if onprem_eps and not has_onprem_events:
            notes.append(
                'On-prem security event log data was not available for this assessment '
                '(no records were returned by the collector).'
            )

        return notes
