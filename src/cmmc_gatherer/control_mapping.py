"""Central CMMC / NIST 800-171 control-mapping registry.

This is the single source of truth connecting each type of evidence this
toolkit collects to the specific CMMC practice(s) it supports. Two design
choices matter here, both aimed at this file staying correct as more
evidence types get added over time:

1. Report-generation code (msp_report_exporter.py) never hardcodes a
   practice ID or statement inline — it always looks evidence up here.
   Adding a new collector's evidence to the report's control coverage is
   meant to be: add one EvidenceMapping entry below, done. No changes to
   report-rendering logic should be required for that alone.

2. Every mapping is tagged with a Confidence level, shown differently in
   the report:

   - DIRECT: a textbook, one-to-one mapping between the evidence and the
     practice's literal assessment objective (e.g. MFA registration data
     -> IA.L2-3.5.3, which is literally about multifactor authentication).

   - SUPPORTING: a reasonable, commonly-used mapping where the evidence is
     real and relevant but doesn't cover the full practice by itself (e.g.
     host-based Windows Firewall status as evidence toward SC.L1-3.13.1,
     which is really about boundary protection more broadly — a host
     firewall is part of that story, not the whole thing).

   Collapsing these two into one undifferentiated "this satisfies X" claim
   would overstate what the tool actually proves. An assessor (or the
   client relying on this report) should be able to tell the difference at
   a glance.

   THE RULE THAT ACTUALLY MATTERS, stated explicitly after a real
   inconsistency in applying it was caught by external review: an Intune
   compliance policy REQUIREMENT (e.g. "storage encryption is required")
   is NOT the same epistemic class as OBSERVED DEVICE STATE (e.g.
   "real-time protection is currently running on this specific device").
   A requirement with no observation that any device actually meets it is
   SUPPORTING at best — it shows intent, not fact. Only evidence of an
   actual, observed state on a real device earns DIRECT. This project
   previously marked storage_encryption_requirement and
   malware_protection_requirement as DIRECT while correctly marking the
   equivalent firewall_policy_requirement as SUPPORTING — the same
   requirement-vs-state distinction applies to all three identically, and
   the first two were wrong. Corrected below; if a future evidence type's
   confidence is ever in question, this is the test to apply: does this
   prove something IS true on a device, or only that something is
   DEMANDED of it?

HONEST SCOPE NOTE: this registry only contains practices for evidence this
toolkit actually collects today. It is not, and does not attempt to be, a
complete CMMC Level 1/2 practice list — a large fraction of CMMC practices
are policy/process/documentation evidence (physical security, personnel
screening, training records, incident response plans) that a collector
like this fundamentally cannot produce. Practice statements below are
paraphrased for report readability from the CMMC Level 2 Assessment Guide
v2.0 / NIST SP 800-171 — verify exact current wording against the official
assessment guide before using this in front of a real assessor.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class Confidence(str, Enum):
    DIRECT = "direct"
    SUPPORTING = "supporting"


@dataclass(frozen=True)
class Practice:
    practice_id: str       # e.g. "IA.L2-3.5.3"
    domain: str             # e.g. "IA"
    level: int              # 1 or 2
    short_name: str         # e.g. "Multifactor Authentication"
    statement: str          # paraphrased practice statement


@dataclass(frozen=True)
class EvidenceMapping:
    evidence_key: str        # stable internal key referenced from report code
    label: str                # human-readable evidence description
    practice_ids: List[str]
    confidence: Confidence


DOMAIN_NAMES: Dict[str, str] = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Security Assessment",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MP": "Media Protection",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Display order for domain sections in the report. Extend this list (and
# DOMAIN_NAMES above) the day a new domain's evidence actually gets added —
# until then, a domain with zero mapped evidence simply never renders, so
# there's no harm in this list being ahead of what's collected today.
DOMAIN_ORDER: List[str] = ["AC", "AU", "CA", "CM", "IA", "IR", "MP", "RA", "SC", "SI"]

PRACTICES: Dict[str, Practice] = {
    "IA.L2-3.5.3": Practice(
        "IA.L2-3.5.3", "IA", 2, "Multifactor Authentication",
        "Use multifactor authentication for local and network access to "
        "privileged accounts and for network access to non-privileged accounts.",
    ),
    "IA.L1-3.5.1": Practice(
        "IA.L1-3.5.1", "IA", 1, "Identification",
        "Identify system users, processes acting on behalf of users, and devices.",
    ),
    "IA.L1-3.5.2": Practice(
        "IA.L1-3.5.2", "IA", 1, "Authentication",
        "Authenticate (or verify) the identities of users, processes, or "
        "devices, as a prerequisite to allowing access to systems.",
    ),
    "AU.L2-3.3.7": Practice(
        "AU.L2-3.3.7", "AU", 2, "Time Synchronization",
        "Provide a system capability that compares and synchronizes internal "
        "system clocks with an authoritative source to generate time stamps "
        "for audit records.",
    ),
    "AU.L2-3.3.1": Practice(
        "AU.L2-3.3.1", "AU", 2, "System Auditing",
        "Create and retain system audit logs and records to the extent needed "
        "to enable monitoring, analysis, investigation, and reporting of "
        "unlawful or unauthorized system activity.",
    ),
    "AU.L2-3.3.2": Practice(
        "AU.L2-3.3.2", "AU", 2, "User Accountability",
        "Ensure that the actions of individual system users can be uniquely "
        "traced to those users, so they can be held accountable for their actions.",
    ),
    "CM.L2-3.4.1": Practice(
        "CM.L2-3.4.1", "CM", 2, "System Baselining",
        "Establish and maintain baseline configurations and inventories of "
        "systems (including hardware, software, firmware, and documentation) "
        "throughout the respective system development life cycles.",
    ),
    "CM.L2-3.4.2": Practice(
        "CM.L2-3.4.2", "CM", 2, "Security Configuration Enforcement",
        "Establish and enforce security configuration settings for information "
        "technology products employed in organizational systems.",
    ),
    "SI.L1-3.14.1": Practice(
        "SI.L1-3.14.1", "SI", 1, "Flaw Remediation",
        "Identify, report, and correct information and system flaws in a "
        "timely manner.",
    ),
    "SI.L1-3.14.2": Practice(
        "SI.L1-3.14.2", "SI", 1, "Malicious Code Protection",
        "Provide protection from malicious code at appropriate locations "
        "within organizational systems.",
    ),
    "SC.L1-3.13.1": Practice(
        "SC.L1-3.13.1", "SC", 1, "Boundary Protection",
        "Monitor, control, and protect organizational communications at the "
        "external boundary and key internal boundaries of organizational systems.",
    ),
    "AC.L2-3.1.7": Practice(
        "AC.L2-3.1.7", "AC", 2, "Privileged Functions",
        "Prevent non-privileged users from executing privileged functions and "
        "capture the execution of such functions in audit logs.",
    ),
    "AC.L2-3.1.5": Practice(
        "AC.L2-3.1.5", "AC", 2, "Least Privilege",
        "Employ the principle of least privilege, including for specific "
        "security functions and privileged accounts.",
    ),
    "AC.L1-3.1.1": Practice(
        "AC.L1-3.1.1", "AC", 1, "Authorized Access Control",
        "Limit system access to authorized users, processes acting on behalf "
        "of authorized users, and devices (including other systems).",
    ),
    "AC.L1-3.1.2": Practice(
        "AC.L1-3.1.2", "AC", 1, "Transaction & Function Control",
        "Limit system access to the types of transactions and functions that "
        "authorized users are permitted to execute.",
    ),
    "AC.L2-3.1.8": Practice(
        "AC.L2-3.1.8", "AC", 2, "Unsuccessful Logon Attempts",
        "Limit unsuccessful logon attempts.",
    ),
    "IA.L2-3.5.7": Practice(
        "IA.L2-3.5.7", "IA", 2, "Password Complexity",
        "Enforce a minimum password complexity and change of characters when "
        "new passwords are created.",
    ),
    "IA.L2-3.5.8": Practice(
        "IA.L2-3.5.8", "IA", 2, "Password Reuse",
        "Prohibit password reuse for a specified number of generations.",
    ),
    "SC.L2-3.13.16": Practice(
        "SC.L2-3.13.16", "SC", 2, "Data at Rest",
        "Protect the confidentiality of CUI at rest.",
    ),
    "SC.L2-3.13.10": Practice(
        "SC.L2-3.13.10", "SC", 2, "Key Management",
        "Establish and manage cryptographic keys for cryptography employed "
        "in organizational systems.",
    ),
    "MP.L1-3.8.3": Practice(
        "MP.L1-3.8.3", "MP", 1, "Media Disposal",
        "Sanitize or destroy information system media containing Federal "
        "Contract Information before disposal or release for reuse.",
    ),
    "SI.L2-3.14.3": Practice(
        "SI.L2-3.14.3", "SI", 2, "Security Alerts & Advisories",
        "Monitor system security alerts and advisories and take action in response.",
    ),
    "SI.L2-3.14.6": Practice(
        "SI.L2-3.14.6", "SI", 2, "Monitor Communications for Attacks",
        "Monitor organizational systems, including inbound and outbound "
        "communications traffic, to detect attacks and indicators of potential attacks.",
    ),
    "SI.L2-3.14.7": Practice(
        "SI.L2-3.14.7", "SI", 2, "Identify Unauthorized Use",
        "Identify unauthorized use of organizational systems.",
    ),
    "SI.L1-3.14.4": Practice(
        "SI.L1-3.14.4", "SI", 1, "Update Malicious Code Protection",
        "Update malicious code protection mechanisms when new releases are available.",
    ),
    "SI.L1-3.14.5": Practice(
        "SI.L1-3.14.5", "SI", 1, "System & File Scanning",
        "Perform periodic scans of the information system and real-time scans "
        "of files from external sources as files are downloaded, opened, or executed.",
    ),
    "RA.L2-3.11.2": Practice(
        "RA.L2-3.11.2", "RA", 2, "Vulnerability Scan",
        "Scan for vulnerabilities in organizational systems and applications "
        "periodically and when new vulnerabilities affecting those systems "
        "and applications are identified.",
    ),
    "RA.L2-3.11.3": Practice(
        "RA.L2-3.11.3", "RA", 2, "Vulnerability Remediation",
        "Remediate vulnerabilities in accordance with risk assessments.",
    ),
    "IR.L2-3.6.1": Practice(
        "IR.L2-3.6.1", "IR", 2, "Incident Handling",
        "Establish an operational incident-handling capability for organizational "
        "systems that includes preparation, detection, analysis, containment, "
        "recovery, and user response activities.",
    ),
    "CA.L2-3.12.1": Practice(
        "CA.L2-3.12.1", "CA", 2, "Security Control Assessment",
        "Periodically assess the security controls in organizational systems "
        "to determine if the controls are effective in their application.",
    ),
    "CA.L2-3.12.2": Practice(
        "CA.L2-3.12.2", "CA", 2, "Plan of Action",
        "Develop and implement plans of action designed to correct deficiencies "
        "and reduce or eliminate vulnerabilities in organizational systems.",
    ),
}

EVIDENCE_MAP: List[EvidenceMapping] = [
    EvidenceMapping(
        "mfa_registration", "MFA registration status and Conditional Access MFA policies",
        ["IA.L2-3.5.3"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "time_sync", "Time synchronization source (w32tm)",
        ["AU.L2-3.3.7"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "installed_software", "Installed software inventory (on-prem registry scan + Intune detected apps)",
        ["CM.L2-3.4.1"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "config_enforcement", "UAC settings, Local Security Policy, and Intune configuration profiles",
        ["CM.L2-3.4.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "password_complexity_enforcement", "Minimum password length / complexity policy",
        ["IA.L2-3.5.7"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "password_reuse_enforcement", "Password history (reuse prevention) policy",
        ["IA.L2-3.5.8"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "account_lockout_enforcement", "Account lockout threshold policy",
        ["AC.L2-3.1.8"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "storage_encryption_requirement", "Storage encryption required by Intune compliance policy",
        ["SC.L2-3.13.16"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "firewall_policy_requirement", "Active firewall required by Intune compliance policy",
        ["SC.L1-3.13.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "malware_protection_requirement", "Antivirus / real-time protection required by Intune compliance policy",
        ["SI.L1-3.14.2"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "patch_management_policy", "Windows Update Ring deferral and automatic-install configuration",
        ["SI.L1-3.14.1"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "bitlocker_key_escrow", "BitLocker recovery key escrow status (existence check only, never the key itself)",
        ["SC.L2-3.13.10"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "cloud_realtime_malware_protection", "Real-time Windows Defender health for Intune-managed devices",
        ["SI.L1-3.14.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "enterprise_app_inventory", "Enterprise application / service principal inventory (processes acting on behalf of users)",
        ["IA.L1-3.5.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "high_privilege_app_permission", "Service principal holding a high-privilege application permission",
        ["AC.L2-3.1.7"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "intune_rbac_assignment", "Intune-specific administrative role assignment (distinct from Entra directory roles)",
        ["AC.L2-3.1.7"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "app_protection_policy", "Intune App Protection Policy (MAM) settings for personally-owned/BYOD devices",
        ["AC.L1-3.1.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "auth_method_detail", "Granular per-user authentication method type (FIDO2, Authenticator, SMS, etc.)",
        ["IA.L2-3.5.3"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "security_alerts", "Security alerts from the unified Microsoft Graph Security API",
        ["AU.L2-3.3.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "device_sanitization_events", "Record of remote wipe/retire actions actually taken (Intune device-management audit log)",
        ["MP.L1-3.8.3"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "audit_log_collection", "Security event and audit log collection (on-prem Event Log + Entra sign-in/audit logs)",
        ["AU.L2-3.3.1"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "audit_user_traceability", "Security events attributed to a specific user account",
        ["AU.L2-3.3.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "antivirus_status", "Antivirus / Windows Defender real-time protection status",
        ["SI.L1-3.14.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "patch_level", "Installed patch / hotfix level",
        ["SI.L1-3.14.1"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "account_identification", "AD/Entra account existence and enabled/disabled state",
        ["IA.L1-3.5.1", "IA.L1-3.5.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "firewall_status", "Windows Firewall profile status (Domain/Private/Public)",
        ["SC.L1-3.13.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "cloud_firewall_status", "Real per-device Windows Firewall status for Intune-managed devices (bulk report)",
        ["SC.L1-3.13.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "privileged_role_tracking", "Privileged role / group membership tracking",
        ["AC.L2-3.1.7", "AC.L2-3.1.5"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "guest_group_membership", "Guest account and group membership status",
        ["AC.L1-3.1.1", "AC.L1-3.1.2"], Confidence.SUPPORTING,
    ),

    # ── MDE Alert Collector ──────────────────────────────────────────────
    EvidenceMapping(
        "mde_alerts_lifecycle",
        "MDE alert monitoring, investigation, and resolution lifecycle",
        ["SI.L2-3.14.3"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "mde_attack_detection",
        "MDE detection of attacks and indicators of potential attacks",
        ["SI.L2-3.14.6"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "mde_unauthorized_use_detection",
        "MDE detection of unauthorized use of systems",
        ["SI.L2-3.14.7"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "mde_incident_handling",
        "MDE alert triage, assignment, and investigation as incident handling evidence",
        ["IR.L2-3.6.1"], Confidence.SUPPORTING,
    ),

    # ── MDE Vulnerability Collector ──────────────────────────────────────
    EvidenceMapping(
        "mde_vulnerability_findings",
        "MDE TVM per-device vulnerability findings (continuous scanning)",
        ["RA.L2-3.11.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "mde_flaw_identification",
        "MDE identification of software vulnerabilities as system flaws",
        ["SI.L1-3.14.1"], Confidence.SUPPORTING,
    ),

    # ── MDE Remediation Collector ────────────────────────────────────────
    EvidenceMapping(
        "mde_vulnerability_remediation_tracking",
        "MDE TVM remediation tasks with status, deadlines, and device progress",
        ["RA.L2-3.11.3"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "mde_flaw_remediation",
        "MDE remediation tasks as evidence of timely flaw correction",
        ["SI.L1-3.14.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "mde_remediation_plans",
        "MDE TVM remediation tasks as tracked corrective actions (POA&M subset)",
        ["CA.L2-3.12.2"], Confidence.SUPPORTING,
    ),

    # ── MDE Secure Config Collector ──────────────────────────────────────
    EvidenceMapping(
        "mde_security_config_assessment",
        "MDE per-device security configuration compliance (observed state)",
        ["CM.L2-3.4.2"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "mde_security_config_baseline_support",
        "MDE configuration assessment as implicit baseline documentation",
        ["CM.L2-3.4.1"], Confidence.SUPPORTING,
    ),

    # ── MDE Baseline Collector ───────────────────────────────────────────
    EvidenceMapping(
        "mde_baseline_compliance",
        "MDE security baseline profile compliance per device",
        ["CM.L2-3.4.1"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "mde_baseline_enforcement_support",
        "MDE baseline compliance as evidence of configuration enforcement",
        ["CM.L2-3.4.2"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "mde_security_control_assessment",
        "MDE configuration and baseline assessments as security control effectiveness evidence",
        ["CA.L2-3.12.1"], Confidence.SUPPORTING,
    ),
]

_EVIDENCE_BY_KEY: Dict[str, EvidenceMapping] = {e.evidence_key: e for e in EVIDENCE_MAP}

# ── Policy-to-CMMC-practice mapping ──────────────────────────────────────
#
# Maps individual policies (by policy_name first, then by policy_type as a
# fallback) to the CMMC practice(s) they satisfy or support. Used by the
# report exporter to show a "CMMC Controls" column in the policy table and
# to filter out policies with no CMMC relevance.
#
# A policy can map to multiple practices (e.g. MinimumPasswordLength
# supports both IA.L2-3.5.7 and CM.L2-3.4.2). The mapping includes the
# confidence level so the report can distinguish "satisfies" from
# "supports".

# By policy_name (most specific — checked first)
_POLICY_NAME_TO_CONTROLS: Dict[str, List[tuple]] = {
    # Password & account policies
    "MinimumPasswordLength": [("IA.L2-3.5.7", Confidence.DIRECT), ("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "PasswordComplexity": [("IA.L2-3.5.7", Confidence.DIRECT), ("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "PasswordHistorySize": [("IA.L2-3.5.8", Confidence.DIRECT), ("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "LockoutBadCount": [("AC.L2-3.1.8", Confidence.DIRECT), ("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "LockoutDuration": [("AC.L2-3.1.8", Confidence.SUPPORTING)],
    "ResetLockoutCount": [("AC.L2-3.1.8", Confidence.SUPPORTING)],
    "MaximumPasswordAge": [("IA.L2-3.5.7", Confidence.SUPPORTING)],
    "MinimumPasswordAge": [("IA.L2-3.5.7", Confidence.SUPPORTING)],
    "ClearTextPassword": [("IA.L2-3.5.7", Confidence.SUPPORTING), ("SC.L2-3.13.16", Confidence.SUPPORTING)],
    # Intune compliance policy requirements
    "StorageRequireEncryption": [("SC.L2-3.13.16", Confidence.SUPPORTING)],
    "ActiveFirewallRequired": [("SC.L1-3.13.1", Confidence.SUPPORTING)],
    "DefenderEnabled": [("SI.L1-3.14.2", Confidence.SUPPORTING)],
    "RealTimeProtectionRequired": [("SI.L1-3.14.2", Confidence.SUPPORTING)],
}

# By policy_type (fallback — used when policy_name isn't in the map above)
_POLICY_TYPE_TO_CONTROLS: Dict[str, List[tuple]] = {
    "UAC (Local Policy)": [("CM.L2-3.4.2", Confidence.DIRECT)],
    "Local Security Policy": [("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "Audit Policy": [("AU.L2-3.3.1", Confidence.DIRECT)],
    "Group Policy": [("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "Conditional Access": [("IA.L2-3.5.3", Confidence.DIRECT), ("AC.L1-3.1.1", Confidence.SUPPORTING)],
    "Intune Configuration Profile": [("CM.L2-3.4.2", Confidence.DIRECT)],
    "Intune Compliance Policy": [("CM.L2-3.4.2", Confidence.SUPPORTING)],
    "Intune Update Ring": [("SI.L1-3.14.1", Confidence.DIRECT)],
    "Intune App Protection Policy": [("AC.L1-3.1.1", Confidence.SUPPORTING)],
    "Time Synchronization": [("AU.L2-3.3.7", Confidence.DIRECT)],
}


def controls_for_policy(policy_name: str, policy_type: str) -> List[tuple]:
    """Return [(practice_id, confidence), ...] for a given policy.

    Checks by policy_name first (most specific), then falls back to
    policy_type. Returns an empty list if the policy has no CMMC mapping
    — the caller can use this to filter out unmapped policies.
    """
    result = _POLICY_NAME_TO_CONTROLS.get(policy_name)
    if result:
        return result
    return _POLICY_TYPE_TO_CONTROLS.get(policy_type, [])

# Catch a typo'd or forgotten practice_id at IMPORT time, not at report-render
# time. Without this, a bad practice_id in a new EvidenceMapping entry surfaces
# as a bare KeyError deep inside practices_for_evidence/domain_coverage, only
# once a report happens to render that specific evidence — i.e. well after
# collection has already run. Failing fast here means a typo is caught the
# moment this module is imported, not discovered mid-assessment.
_unknown_practice_ids = {
    pid for ev in EVIDENCE_MAP for pid in ev.practice_ids
} - PRACTICES.keys()
assert not _unknown_practice_ids, (
    f"control_mapping.EVIDENCE_MAP references practice_id(s) not present in "
    f"PRACTICES: {sorted(_unknown_practice_ids)} — add them to PRACTICES or "
    f"fix the typo before this evidence type can be used anywhere."
)


def get_practice(practice_id: str) -> Practice:
    return PRACTICES[practice_id]


def get_evidence(evidence_key: str) -> EvidenceMapping:
    return _EVIDENCE_BY_KEY[evidence_key]


def practices_for_evidence(evidence_keys: List[str]) -> List[Practice]:
    """Return the (deduplicated, order-preserving) list of Practice objects
    covered by the given evidence keys — the lookup report code actually
    needs when rendering a "Satisfies:" badge for a section."""
    seen = []
    for key in evidence_keys:
        for pid in _EVIDENCE_BY_KEY[key].practice_ids:
            if pid not in seen:
                seen.append(pid)
    return [PRACTICES[pid] for pid in seen]


def domain_coverage(present_evidence_keys: List[str]) -> Dict[str, List[Dict]]:
    """Group the practices actually evidenced in THIS report by domain, in
    DOMAIN_ORDER, each with its supporting evidence label(s) and confidence.
    Returns only domains with at least one practice present — a domain this
    toolkit has zero evidence for today (e.g. MP, PE) never appears rather
    than showing an empty, misleading section.

    Shape: {domain_code: [{"practice": Practice, "evidence": [(label, confidence), ...]}]}
    """
    present = set(present_evidence_keys)
    by_practice: Dict[str, List] = {}
    for ev in EVIDENCE_MAP:
        if ev.evidence_key not in present:
            continue
        for pid in ev.practice_ids:
            by_practice.setdefault(pid, []).append((ev.label, ev.confidence))

    result: Dict[str, List[Dict]] = {}
    for domain in DOMAIN_ORDER:
        domain_practices = [
            {"practice": PRACTICES[pid], "evidence": ev_list}
            for pid, ev_list in by_practice.items()
            if PRACTICES[pid].domain == domain
        ]
        if domain_practices:
            domain_practices.sort(key=lambda d: d["practice"].practice_id)
            result[domain] = domain_practices
    return result
