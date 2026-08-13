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
    large categories were never assessed (this is currently the case for the
    cloud plane — there is no cloud policy or event collector yet).
  - Failing policies are now grouped into separate findings by policy_type
    instead of one undifferentiated comma-separated list mixing e.g.
    password-policy failures with two dozen individual audit subcategories.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import ExporterBase
from ..utils.compliance import ComplianceScorer

logger = logging.getLogger(__name__)


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
            with open(output_path, 'w') as f:
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

    def _generate_msp_report(
        self,
        artifacts: Any,
        customer_name: Optional[str],
        assessment_id: Optional[str],
    ) -> str:
        compliance_score = ComplianceScorer.calculate_overall_score(artifacts)
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

        html = f"""<!DOCTYPE html>
<html>
<head>
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
            </table>
        </div>

        <div class="section">
            <h2>Compliance Score</h2>
            <div class="score-card">
                <div class="score {score_class}">
                    <div class="number">{compliance_score}%</div>
                    <div class="label">Overall Compliance</div>
                </div>
            </div>
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
                    <th>Firewall</th><th>Antivirus</th>
                </tr>
"""
            for ep in onprem_eps:
                fw_color = 'green' if ep.firewall_status == 'Enabled' else ('orange' if ep.firewall_status == 'Partial' else 'red')
                av_color = 'green' if ep.antivirus_status == 'Active' else 'red'
                html += (
                    f"                <tr><td>{ep.hostname}</td><td>{ep.ip_address}</td>"
                    f"<td>{ep.os_version}</td>"
                    f"<td><span style=\"color:{fw_color}\">{ep.firewall_status or 'Unknown'}</span></td>"
                    f"<td><span style=\"color:{av_color}\">{ep.antivirus_status or 'Unknown'}</span></td>"
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
                    f"<td>{meta.get('owner_upn', 'Unknown')}</td></tr>\n"
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
        if onprem_eps or artifacts.security_events:
            scope_items.append("Windows endpoint security configurations")
            scope_items.append("Security event logging and monitoring")
        if any(p.policy_type == 'Local Security Policy' for p in artifacts.policies):
            scope_items.append("Local security and account lockout policy")
        if any(p.policy_type == 'Group Policy' for p in artifacts.policies):
            scope_items.append("Group Policy compliance")
        if any(p.policy_type == 'Audit Policy' for p in artifacts.policies):
            scope_items.append("Audit policy configuration")
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

    def _generate_findings(self, artifacts: Any) -> List[Dict[str, str]]:
        findings = []
        onprem_eps = self._onprem_endpoints(artifacts)
        cloud_eps = self._cloud_endpoints(artifacts)

        # On-prem-only checks: cloud endpoints deliberately have these fields
        # set to None (not applicable), so they must never be evaluated here.
        disabled_firewalls = [
            ep.hostname for ep in onprem_eps if ep.firewall_status != "Enabled"
        ]
        if disabled_firewalls:
            findings.append({
                'title': 'Firewall Not Fully Enabled',
                'severity': 'Critical',
                'description': f'Firewall is not fully enabled on: {", ".join(disabled_firewalls)}',
                'recommendation': 'Enable Windows Firewall on all profiles for all on-prem endpoints',
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

        # Cloud-native finding, using the real Intune compliance signal instead
        # of borrowing on-prem checks that don't apply to these devices.
        noncompliant_cloud = [
            ep.hostname for ep in cloud_eps if not (ep.metadata or {}).get('is_compliant')
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
        # never when the value is unknown.
        unencrypted_cloud = [
            ep.hostname for ep in cloud_eps
            if (ep.metadata or {}).get('is_encrypted') is False
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
        when there's nothing to disclose (e.g. a plane with real, present
        policy/event data, or a plane not run at all)."""
        notes = []

        if cloud_eps and not artifacts.policies:
            notes.append(
                'Cloud-managed policy configuration (Entra Conditional Access, Intune '
                'configuration profiles) was not evaluated. This capability is not yet '
                'implemented for the cloud plane.'
            )
        if cloud_eps and not artifacts.security_events:
            notes.append(
                'Cloud identity sign-in and audit log review was not evaluated. This '
                'capability is not yet implemented for the cloud plane.'
            )
        if onprem_eps and not artifacts.policies:
            notes.append(
                'On-prem security policy data was not available for this assessment '
                '(no records were returned by the collector).'
            )
        if onprem_eps and not artifacts.security_events:
            notes.append(
                'On-prem security event log data was not available for this assessment '
                '(no records were returned by the collector).'
            )

        return notes
