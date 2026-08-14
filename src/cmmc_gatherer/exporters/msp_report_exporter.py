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
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import ExporterBase
from ..utils.compliance import ComplianceScorer

logger = logging.getLogger(__name__)

# Shared between coverage-note detection and Assessment Scope generation, so
# a cloud-sourced policy/event record is never mistaken for an on-prem one
# (or vice versa) in either place.
_CLOUD_POLICY_TYPES = ('Conditional Access', 'Intune Configuration Profile')
_CLOUD_EVENT_SOURCES = ('Entra Sign-In Logs', 'Entra Directory Audit Logs')


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
            html_content = self._generate_msp_report(artifacts, customer_name, assessment_id)
            # Explicit UTF-8 write: without it, Python falls back to the
            # platform's default encoding (often cp1252 on Windows), which
            # mis-encodes the em-dashes used throughout this template. The
            # browser then renders those bytes as UTF-8 (its own default for
            # a local file with no declared charset) and produces garbled
            # "�" characters — confirmed against a real generated report.
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Exported MSP report: {output_path}")
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
                <div class="recommendation" style="border-left-color:#f44336;background:#ffebee;margin-top:15px;">
                    <strong>Coverage incomplete:</strong> this score is based on
                    {coverage['assessed_count']} of {coverage['total_count']} scoring categories
                    ({coverage['assessed_weight_pct']}% of total scoring weight).
                    Not assessed: {missing_labels}.
                </div>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CMMC Compliance Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6; color: #333; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .content {{ max-width: 900px; margin: 0 auto; padding: 30px; }}
        .section {{ margin: 30px 0; page-break-inside: avoid; }}
        .section h2 {{ color: #667eea; border-bottom: 3px solid #667eea;
                       padding-bottom: 10px; margin-bottom: 15px; }}
        .score-card {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .score {{ background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center;
                 flex: 1; margin: 0 10px; }}
        .score .number {{ font-size: 3em; font-weight: bold; color: #667eea; }}
        .score .label {{ color: #666; margin-top: 5px; }}
        .score.good {{ background: #e8f5e9; }}
        .score.good .number {{ color: #4caf50; }}
        .score.warning {{ background: #fff3e0; }}
        .score.warning .number {{ color: #ff9800; }}
        .score.critical {{ background: #ffebee; }}
        .score.critical .number {{ color: #f44336; }}
        .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid #ff9800;
                   background: #fff9c4; border-radius: 4px; }}
        .finding.critical {{ border-left-color: #f44336; background: #ffebee; }}
        .finding.resolved {{ border-left-color: #4caf50; background: #e8f5e9; }}
        .finding h4 {{ margin-bottom: 5px; }}
        .finding p {{ font-size: 0.95em; line-height: 1.5; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background-color: #f5f5f5; padding: 12px; text-align: left;
              border-bottom: 2px solid #ddd; }}
        td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .recommendation {{ background: #e3f2fd; padding: 15px;
                          border-left: 4px solid #2196F3; margin: 10px 0; }}
        .footer {{ background: #f5f5f5; padding: 20px; text-align: center;
                  margin-top: 40px; border-top: 1px solid #ddd; color: #999; }}
        .summary-table td {{ padding: 8px; }}
        .summary-table td:first-child {{ font-weight: bold; width: 30%; }}
        .na {{ color: #999; font-style: italic; }}
    </style>
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
            html += """        <div class="section">
            <h2>On-Prem Endpoint Status</h2>
            <table>
                <tr>
                    <th>Hostname</th><th>IP Address</th><th>OS Version</th>
                    <th>Firewall</th><th>Antivirus</th><th>Also Cloud-Managed (Intune)</th>
                    <th>Installed Software</th>
                </tr>
"""
            for ep in onprem_eps:
                fw_color = 'green' if ep.firewall_status == 'Enabled' else ('orange' if ep.firewall_status == 'Partial' else 'red')
                av_color = 'green' if ep.antivirus_status == 'Active' else 'red'
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
                    cm_color = 'green' if compliant else 'red'
                    enc_note = 'encrypted' if enc else ('not encrypted' if enc is False else 'encryption unknown')
                    cloud_cell = (f"<span style=\"color:{cm_color}\">"
                                  f"{intune.get('compliance_state', 'Unknown')} ({enc_note})</span>")
                else:
                    cloud_cell = '<span class="na">No</span>'
                html += (
                    f"                <tr><td>{ep.hostname}</td><td>{ep.ip_address}</td>"
                    f"<td>{ep.os_version}</td>"
                    f"<td><span style=\"color:{fw_color}\">{ep.firewall_status or 'Unknown'}{fw_note}</span></td>"
                    f"<td><span style=\"color:{av_color}\">{ep.antivirus_status or 'Unknown'}</span></td>"
                    f"<td>{cloud_cell}</td>"
                    f"<td>{self._software_cell(ep)}</td>"
                    f"</tr>\n"
                )
            html += "            </table>\n        </div>\n"

        if cloud_eps:
            html += """        <div class="section">
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
                comp_color = 'green' if compliant else 'red'
                enc = meta.get('is_encrypted')
                enc_color = 'green' if enc else 'orange'
                html += (
                    f"                <tr><td>{ep.hostname}</td><td>{ep.os_version}</td>"
                    f"<td><span style=\"color:{comp_color}\">{meta.get('compliance_state', 'Unknown')}</span></td>"
                    f"<td><span style=\"color:{enc_color}\">{enc}</span></td>"
                    f"<td>{meta.get('management_state', 'Unknown')}</td>"
                    f"<td>{meta.get('owner_upn', 'Unknown')}</td>"
                    f"<td>{self._software_cell(ep)}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        ad_users = self._ad_users(artifacts)
        if ad_users:
            html += """        <div class="section">
            <h2>Active Directory / Identity Objects — Users</h2>
            <table>
                <tr>
                    <th>Name</th><th>Source</th><th>Status</th><th>Guest</th>
                    <th>Stale</th><th>Privileged</th><th>MFA Registered</th>
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
                status_color = 'green' if enabled else ('red' if enabled is False else '#999')
                status_label = 'Enabled' if enabled else ('Disabled' if enabled is False else 'Unknown')

                is_guest = attrs.get('isGuest')
                guest_cell = ('Yes' if is_guest else 'No') if is_guest is not None else '<span class="na">N/A</span>'

                stale = attrs.get('isStale')
                stale_color = 'red' if stale else ('green' if stale is False else '#999')
                stale_label = 'Yes' if stale else ('No' if stale is False else 'Unknown')

                # Privileged: True/False is a real answer either plane produced;
                # None means the lookup itself failed/wasn't attempted — shown
                # as Unknown, never silently rendered as "No".
                privileged = attrs.get('isPrivileged')
                roles = attrs.get('privilegedRoles') or []
                if privileged is True:
                    priv_color = 'red'
                    priv_label = 'YES' + (f" ({', '.join(roles)})" if roles else " (privileged AD group)")
                elif privileged is False:
                    priv_color, priv_label = 'green', 'No'
                else:
                    priv_color, priv_label = '#999', 'Unknown'

                # MFA is a cloud-only concept today — on-prem AD has no MFA
                # signal, so it's N/A, not a false "No".
                mfa = attrs.get('isMfaRegistered')
                methods = attrs.get('mfaMethods') or []
                if not is_cloud:
                    mfa_cell = '<span class="na">N/A (on-prem)</span>'
                elif mfa is True:
                    method_note = f" ({', '.join(methods)})" if methods else ""
                    mfa_cell = f'<span style="color:green">Yes{method_note}</span>'
                elif mfa is False:
                    mfa_cell = '<span style="color:red">No</span>'
                else:
                    mfa_cell = '<span style="color:#999">Unknown</span>'

                html += (
                    f"                <tr><td>{name}</td><td>{'Entra ID' if is_cloud else 'On-Prem AD'}</td>"
                    f"<td><span style=\"color:{status_color}\">{status_label}</span></td>"
                    f"<td>{guest_cell}</td>"
                    f"<td><span style=\"color:{stale_color}\">{stale_label}</span></td>"
                    f"<td><span style=\"color:{priv_color}\">{priv_label}</span></td>"
                    f"<td>{mfa_cell}</td></tr>\n"
                )
            html += "            </table>\n        </div>\n"

        ad_groups = self._ad_groups(artifacts)
        if ad_groups:
            html += """        <div class="section">
            <h2>Active Directory / Identity Objects — Groups</h2>
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

        if artifacts.policies:
            html += """        </div>

        <div class="section">
            <h2>Policy Compliance</h2>
            <table>
                <tr><th>Policy</th><th>Type</th><th>Status</th><th>Current Value</th></tr>
"""
            for policy in artifacts.policies:
                passes = ComplianceScorer._policy_passes(policy)
                if passes is True:
                    status_color = 'green'
                elif passes is False:
                    status_color = 'red'
                else:
                    status_color = '#999'  # informational / no specific rule — not a warning
                html += (
                    f"                <tr><td>{policy.policy_name}</td><td>{policy.policy_type}</td>"
                    f"<td><span style=\"color:{status_color}\">{policy.status}</span></td>"
                    f"<td>{policy.value or 'N/A'}</td></tr>\n"
                )
            html += "            </table>\n"

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
    def _software_cell(ep: Any) -> str:
        """Render a collapsed, expandable software list for one table cell.
        Uses a plain <details>/<summary> element — valid, semantic HTML5
        that needs no JavaScript to expand/collapse, so it works the same in
        a static exported report as it would in a live browser tab."""
        software = MSPReportExporter._software_list(ep)
        if not software:
            return '<span class="na">Not collected</span>'
        items = "".join(
            "<li>" + s.get('name', 'Unknown')
            + (f" — {s.get('version')}" if s.get('version') else "")
            + (f" ({s.get('publisher')})" if s.get('publisher') else "")
            + "</li>"
            for s in software
        )
        return (
            f'<details><summary>{len(software)} package(s)</summary>'
            f'<ul style="margin:6px 0 0 18px;font-size:0.85em;max-height:200px;'
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
