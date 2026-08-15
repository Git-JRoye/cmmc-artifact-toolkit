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
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Display order for domain sections in the report. Extend this list (and
# DOMAIN_NAMES above) the day a new domain's evidence actually gets added —
# until then, a domain with zero mapped evidence simply never renders, so
# there's no harm in this list being ahead of what's collected today.
DOMAIN_ORDER: List[str] = ["AC", "AU", "CM", "IA", "SC", "SI"]

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
        ["SC.L2-3.13.16"], Confidence.DIRECT,
    ),
    EvidenceMapping(
        "firewall_policy_requirement", "Active firewall required by Intune compliance policy",
        ["SC.L1-3.13.1"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "malware_protection_requirement", "Antivirus / real-time protection required by Intune compliance policy",
        ["SI.L1-3.14.2"], Confidence.DIRECT,
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
        "privileged_role_tracking", "Privileged role / group membership tracking",
        ["AC.L2-3.1.7"], Confidence.SUPPORTING,
    ),
    EvidenceMapping(
        "guest_group_membership", "Guest account and group membership status",
        ["AC.L1-3.1.1", "AC.L1-3.1.2"], Confidence.SUPPORTING,
    ),
]

_EVIDENCE_BY_KEY: Dict[str, EvidenceMapping] = {e.evidence_key: e for e in EVIDENCE_MAP}


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
