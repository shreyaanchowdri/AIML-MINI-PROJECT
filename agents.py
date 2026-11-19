import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "processed"
MODEL_PATH = DATA / "agent1_best_model_v1.joblib"
DB_PATH = ROOT / "data" / "purple_team_memory.db"

MODEL = joblib.load(MODEL_PATH)

# ---------------- AGENT 1: ATTACK INTELLIGENCE ----------------

def agent1_classify(title, description):
    text = f"{title} {description}".strip().lower()

    if len(text) < 15:
        return {
            "status": "INSUFFICIENT_INPUT",
            "attack_families": [],
            "operational_context": "UNKNOWN",
            "activity": "UNKNOWN",
            "confidence": None,
            "warning": "Provide a more detailed scenario."
        }

    attack_rules = [
        ("RANSOMWARE", ("ransomware", "encrypted files", "files were encrypted")),
        ("PHISHING", ("phishing", "suspicious email", "credential harvesting", "malicious email attachment", "opened a malicious email")),
        ("SQL_INJECTION", ("sql injection", "sql query injection")),
        ("DATA_EXFILTRATION", (
            "data exfiltration", "data theft", "stolen database",
            "exfiltrated data", "data was exfiltrated",
            "sensitive data was exfiltrated",
            "data was also exfiltrated",
            "exfiltrated to an external server",
            "unauthorized outbound data transfer"
        )),
        ("DENIAL_OF_SERVICE", ("denial of service", "ddos")),
        ("PRIVILEGE_ESCALATION", ("privilege escalation", "elevated privileges", "gained administrator access")),
        ("LATERAL_MOVEMENT", ("lateral movement", "moved laterally", "movement between systems")),
        ("CREDENTIAL_ATTACK", ("credential stuffing", "password spraying", "brute force login", "credential theft", "stolen credentials", "stole employee credentials", "compromised credentials", "account takeover")),
        ("REMOTE_EXECUTION", ("remote code execution", "remote execution", "remote service execution")),
        ("COMMAND_AND_CONTROL", ("command and control", "command-and-control", "c2 communication", "beaconing")),
        ("PERSISTENCE", ("persistence mechanism", "startup modification", "scheduled task abuse")),
        ("EXPLOITATION", ("exploited vulnerability", "vulnerability exploitation")),
        ("MALWARE", ("malware", "malicious process", "trojan", "worm")),
        ("BUFFER_OVERFLOW", ("buffer overflow",))
    ]

    attack_families = []

    # Assess evidence status separately for each attack family.
    # Use scenario description only; generated titles are not evidence.
    import re

    description_text = description.lower()
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", description_text)
        if sentence.strip()
    ]

    research_terms = (
        "malware analysis laboratory", "malware analysis lab",
        "malware analysis in a laboratory", "academic research",
        "security research", "laboratory experiment", "research experiment"
    )
    attempt_terms = (
        "attempted", "attempt to", "tried to exploit",
        "unsuccessful attack", "blocked attack attempt"
    )
    suspected_terms = (
        "suspected", "suspicious", "possible", "possibly",
        "potential", "may have", "might have", "likely", "malicious email attachment", "opened a malicious email"
    )
    observed_terms = (
        "confirmed", "successfully", "observed", "detected",
        "encrypted files", "files were encrypted", "executed malware", "malware was executed",
        "stole employee credentials", "moved laterally",
        "exfiltrated data", "deployed ransomware",
        "encrypted the company's", "encrypted production files",
        "encrypted the production files",
        "was also exfiltrated",
        "exfiltrated to an external server"
    )

    for family, indicators in attack_rules:
        matched = [term for term in indicators if term in text]
        if not matched:
            continue

        evidence_sentences = [
            sentence for sentence in sentences
            if any(term in sentence for term in matched)
        ]

        evidence_text = " ".join(evidence_sentences)

        matched_text = " ".join(matched)

        negative_terms = (
            "no evidence of", "no indication of",
            "not observed", "not detected",
            "has not been established", "has not yet established whether", "has not occurred",
            "was not detected", "was not observed"
        )

        if any(term in evidence_text for term in research_terms):
            evidence_status = "RESEARCH_CONTEXT"
        elif any(term in evidence_text for term in negative_terms):
            evidence_status = "NOT_ESTABLISHED"
        elif any(term in evidence_text for term in attempt_terms):
            evidence_status = "ATTEMPTED"
        elif any(term in evidence_text for term in observed_terms):
            evidence_status = "OBSERVED"
        elif any(term in evidence_text for term in suspected_terms):
            evidence_status = "SUSPECTED"
        else:
            evidence_status = "MENTIONED_UNVERIFIED"

        attack_families.append({
            "family": family,
            "matched_evidence": matched,
            "evidence_status": evidence_status,
            "evidence_basis": evidence_sentences
        })

    # Context precedence: explicit authorized/research context
    # takes precedence over generic attack-related terminology.
    if any(term in text for term in (
        "authorized penetration test", "authorized red team",
        "approved security assessment", "authorized security testing",
        "approved penetration test"
    )):
        operational_context = "AUTHORIZED_SECURITY_TESTING"
    elif any(term in text for term in (
        "malware analysis laboratory", "malware analysis lab",
        "malware analysis in a laboratory", "academic research",
        "security research", "laboratory experiment", "research experiment"
    )):
        operational_context = "RESEARCH_OR_EXPERIMENTATION"
    elif any(term in text for term in (
        "security monitoring", "defensive operation",
        "blocked the attack", "detected and contained",
        "incident investigation"
    )):
        operational_context = "DEFENSIVE_OPERATION"
    elif any(term in text for term in (
        "ransomware", "phishing", "malware", "unauthorized access",
        "attacker", "data theft", "credential theft", "exploited"
    )):
        operational_context = "MALICIOUS_ACTIVITY"
    else:
        operational_context = "UNKNOWN"

    probabilities = MODEL.predict_proba([text])[0]
    classes = MODEL.classes_
    index = probabilities.argmax()
    confidence = float(probabilities[index])
    predicted = str(classes[index])

    status = "PROVISIONAL" if confidence >= 0.40 else "LOW_CONFIDENCE"

    context_activity = {
        "AUTHORIZED_SECURITY_TESTING": "OFFENSIVE_SECURITY_AND_ATTACK_SIMULATION",
        "RESEARCH_OR_EXPERIMENTATION": "SECURITY_RESEARCH_AND_VULNERABILITY_DISCOVERY"
    }

    if operational_context == "MALICIOUS_ACTIVITY":
        activity = "NOT_APPLICABLE"
        activity_status = "NOT_APPLICABLE"
        activity_warning = (
            "This is a malicious incident, not an authorized security activity. "
            "The ML candidate is retained for diagnostic purposes only."
        )
    elif operational_context in context_activity:
        activity = context_activity[operational_context]
        activity_status = "CONTEXT_RULE_BASED"
        activity_warning = (
            "Activity assigned from explicitly detected operational context; "
            "human validation is still required."
        )
    else:
        activity = predicted if confidence >= 0.40 else "UNKNOWN"
        activity_status = status
        activity_warning = (
            "Experimental activity classifier. Prediction requires human validation."
            if confidence >= 0.40 else
            "Low model confidence. Manual activity classification required."
        )

    return {
        "status": status,
        "attack_families": attack_families,
        "operational_context": operational_context,
        "activity": activity,
        "activity_status": activity_status,
        "activity_candidate": predicted,
        "confidence": round(confidence, 4),
        "warning": activity_warning,
        "classification_basis": {
            "attack_families": "Multi-label rule-based identification with matched evidence.",
            "operational_context": "Contextual rule-based identification; human validation required.",
            "activity": "Experimental six-class ML model."
        },
        "alternatives": [
            {"class": str(classes[i]), "probability": round(float(probabilities[i]), 4)}
            for i in probabilities.argsort()[::-1][:3]
        ]
    }


# ---------------- AGENT 2: RISK ASSESSMENT ----------------

def agent2_assess_risk(severity=None, likelihood=None, asset_criticality=None, exposure=None, title="", description=""):
    text = f"{title} {description}".lower()

    def infer(value, rules, default):
        if value is not None:
            if not isinstance(value, int) or not 1 <= value <= 5:
                raise ValueError("Risk inputs must be integers from 1 to 5.")
            return value
        return next((score for terms, score in rules if any(term in text for term in terms)), default)

    severity = infer(severity, [
        (("ransomware", "data exfiltration", "production database", "critical infrastructure", "remote code execution"), 5),
        (("malware", "privilege escalation", "system compromise", "unauthorized access"), 4),
        (("suspicious", "attempt", "phishing", "vulnerability"), 3)
    ], 2)

    likelihood = infer(likelihood, [
        (("successfully", "successful", "confirmed compromise", "data was accessed", "attacker gained", "encrypted files", "files were encrypted"), 5),
        (("detected", "observed", "unauthorized access", "exploited"), 4),
        (("suspicious", "possible", "attempt", "suspected"), 3)
    ], 2)

    asset_criticality = infer(asset_criticality, [
        (("critical infrastructure", "production database", "payment system", "domain controller"), 5),
        (("server", "cloud", "workstation", "endpoint", "database"), 4)
    ], 3)

    exposure = infer(exposure, [
        (("internet-facing", "publicly exposed", "public access"), 5),
        (("remote access", "external network", "cloud", "public api"), 4),
        (("internal network", "internal system"), 3)
    ], 2)

    score = round((severity * likelihood * asset_criticality * exposure) / 5, 2)

    if score >= 60:
        level = "CRITICAL"
    elif score >= 35:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "inputs": {
            "severity": severity,
            "likelihood": likelihood,
            "asset_criticality": asset_criticality,
            "exposure": exposure
        },
        "assessment_type": "AUTOMATED_HEURISTIC_ESTIMATE",
        "evidence_basis": "Keyword-based estimates from the incident title and description; analyst validation required.",
        "method": "Transparent project-specific rubric; not CVSS."
    }


# ---------------- AGENT 3: DEFENSE RECOMMENDATIONS ----------------

DEFENSE_KNOWLEDGE = {
    "sql injection": [
        "Use parameterized database queries.",
        "Validate inputs using allowlists.",
        "Apply least-privilege database permissions.",
        "Monitor unusual database query patterns and database access.",
        "Block malicious requests and temporarily restrict the vulnerable endpoint.",
        "Patch the vulnerable application and verify database integrity."
    ],
    "phishing": [
        "Deploy phishing-resistant MFA.",
        "Implement email authentication, filtering, and attachment scanning.",
        "Provide user awareness training.",
        "Monitor suspicious authentication activity and unusual mailbox rules.",
        "Quarantine malicious emails and block confirmed phishing URLs and domains.",
        "Revoke compromised sessions and reset affected credentials.",
        "Restore affected accounts and verify mailbox and account integrity."
    ],
    "ransomware": [
        "Maintain isolated and regularly tested backups.",
        "Deploy endpoint detection and response (EDR) across critical endpoints and servers.",
        "Restrict unnecessary administrative privileges and enforce least privilege.",
        "Implement email security filtering and block suspicious attachments.",
        "Monitor unusual file modifications, mass encryption behaviour, and abnormal process activity.",
        "Isolate confirmed affected servers and endpoints from the network.",
        "Restrict unnecessary east-west network traffic to limit lateral movement.",
        "Restore systems from verified clean backups and validate system integrity."
    ],
    "denial of service": [
        "Apply rate limiting and traffic filtering.",
        "Use network-layer monitoring.",
        "Implement redundancy and DDoS protection.",
        "Establish service availability alerts."
    ],
    "privilege escalation": [
        "Enforce least privilege.",
        "Patch vulnerable operating systems and software.",
        "Audit privileged account activity.",
        "Enable endpoint security monitoring."
    ],
    "lateral movement": [
        "Segment critical network zones.",
        "Restrict unnecessary east-west traffic.",
        "Monitor unusual authentication and remote access.",
        "Use privileged access management."
    ],
    "data exfiltration": [
        "Apply data loss prevention controls.",
        "Restrict access to sensitive data using least privilege.",
        "Monitor unusual outbound traffic and large data transfers.",
        "Investigate abnormal DNS, network, and cloud access activity.",
        "Block confirmed malicious outbound destinations and suspend compromised accounts.",
        "Preserve relevant logs and determine the scope of exposed information.",
        "Validate data integrity and follow applicable breach-response procedures."
    ],
    "credential": [
        "Use phishing-resistant MFA.",
        "Rotate exposed credentials and revoke active sessions.",
        "Store secrets in a managed secrets vault.",
        "Monitor abnormal login activity."
    ],
    "malware": [
        "Restrict application execution using application control.",
        "Keep endpoint protection and operating systems updated.",
        "Use endpoint detection and response.",
        "Investigate persistence mechanisms and indicators of compromise.",
        "Isolate confirmed infected endpoints from the network.",
        "Remove malicious components and rebuild compromised systems when necessary.",
        "Restore verified clean data and validate system integrity."
    ],
    "buffer overflow": [
        "Patch vulnerable software.",
        "Enable memory safety protections such as ASLR and DEP.",
        "Use compiler hardening.",
        "Perform secure code review and testing."
    ]
}

def agent3_recommend_defense(title, description, risk):
    text = f"{title} {description}".lower()

    priority_rules = [
        ("ransomware", ("ransomware", "encrypted files", "files were encrypted")),
        ("data exfiltration", ("data exfiltration", "data theft", "sensitive data was accessed", "exfiltrated", "unauthorized outbound transfer")),
        ("sql injection", ("sql injection", "database query", "unsanitized input")),
        ("denial of service", ("denial of service", "ddos")),
        ("privilege escalation", ("privilege escalation",)),
        ("lateral movement", ("lateral movement",)),
        ("malware", ("malware", "malicious process")),
        ("phishing", ("phishing", "suspicious email")),
        ("credential", ("credential theft", "stolen credentials", "password theft"))
    ]

    matched_threats = [
        keyword for keyword, indicators in priority_rules
        if any(indicator in text for indicator in indicators)
    ]

    primary_keyword = matched_threats[0] if matched_threats else None

    prevention, detection, containment, recovery, response_actions = [], [], [], [], []

    for threat in matched_threats:
        for recommendation in DEFENSE_KNOWLEDGE.get(threat, []):
            item = recommendation.lower()

            if any(term in item for term in ("preserve relevant logs", "determine the scope", "investigate persistence", "investigate abnormal")):
                response_actions.append(recommendation)
            elif any(term in item for term in ("backup", "restore", "recovery", "reset affected credentials", "patch the vulnerable application", "remove malicious", "rebuild compromised", "validate data integrity", "restore affected accounts")):
                recovery.append(recommendation)
            elif any(term in item for term in ("isolate", "containment", "contain affected", "quarantine", "revoke", "block malicious", "suspend compromised", "restrict the vulnerable endpoint")):
                containment.append(recommendation)
            elif any(term in item for term in ("monitor", "detect", "alert", "investigate", "audit")):
                detection.append(recommendation)
            else:
                prevention.append(recommendation)

    if not matched_threats:
        prevention = [
            "Preserve relevant logs and evidence.",
            "Restrict unnecessary access to the affected system.",
            "Investigate the suspected attack vector.",
            "Apply security updates after validating applicability."
        ]

    threat_response = {
        "ransomware": "Investigate the initial access vector and assess whether data theft also occurred.",
        "phishing": "Identify affected recipients, determine credential exposure, and review suspicious account activity.",
        "sql injection": "Review application and database logs to determine which records may have been accessed or modified.",
        "malware": "Determine the malware entry point, affected hosts, persistence, and scope of compromise.",
        "data exfiltration": "Establish the scope of exposed data, affected accounts, destinations, and relevant reporting obligations.",
        "denial of service": "Determine the attack duration, affected services, traffic sources, and availability impact.",
        "privilege escalation": "Review privilege changes and identify accounts or systems affected.",
        "lateral movement": "Identify compromised hosts, accessed systems, and authentication paths.",
        "credential": "Identify compromised accounts, revoke affected sessions, and assess credential exposure."
    }

    return {
        "primary_threat": primary_keyword or "UNDETERMINED",
        "identified_threats": matched_threats,
        "prevention": list(dict.fromkeys(prevention)),
        "detection": list(dict.fromkeys(detection)),
        "containment": list(dict.fromkeys(containment)),
        "recovery": list(dict.fromkeys(recovery)),
        "response": list(dict.fromkeys([
            "Validate the incident using available evidence.",
            "Preserve relevant forensic evidence before remediation.",
            *response_actions,
            *(threat_response[t] for t in matched_threats if t in threat_response),
            "Verify recovery and monitor for recurrence."
        ])),
        "priority": risk["level"],
        "basis": "Multi-threat rule-based recommendations; applicability requires security analyst review."
    }


# ---------------- AGENT 4: RESPONSE EVALUATION ----------------

def agent4_evaluate_response(event_id=None):
    path = DATA / "purple_response_metrics.csv"
    df = pd.read_csv(path)

    if event_id is not None:
        df = df[df["event_id"] == int(event_id)]

    if df.empty:
        return {"status": "NO_RESPONSE_METRICS", "records": 0}

    return {
        "status": "HISTORICAL_DATA_AVAILABLE",
        "records": int(len(df)),
        "mean_detection_seconds": round(float(df["detection_time_seconds"].mean()), 2),
        "mean_response_seconds": round(float(df["response_time_seconds"].mean()), 2),
        "mean_false_positive_rate": round(float(df["false_positive_rate"].mean()), 4),
        "mean_missed_detection_rate": round(float(df["missed_detection_rate"].mean()), 4),
        "source": "Secondary purple-team response metrics",
        "warning": "Historical dataset statistics, not measurements of the current incident."
    }


# ---------------- AGENT 5: FEEDBACK VALIDATION ----------------

def agent5_validate_feedback(recommended, actual, evidence, incident_id):
    if not actual or not actual.strip() or not evidence or not evidence.strip():
        return {
            "status": "INSUFFICIENT_EVIDENCE",
            "learning_approved": False
        }

    init_memory()
    feedback_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        incident = conn.execute(
            "SELECT 1 FROM incidents WHERE incident_id = ?",
            (incident_id,)
        ).fetchone()

        if incident is None:
            return {
                "status": "INCIDENT_NOT_FOUND",
                "learning_approved": False
            }

        conn.execute("""
            INSERT INTO incident_feedback
            (feedback_id, incident_id, created_at, recommended_action,
             actual_action, evidence, review_status, learning_approved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback_id, incident_id, created_at, recommended,
            actual, evidence, "PENDING_HUMAN_REVIEW", 0
        ))

    return {
        "feedback_id": feedback_id,
        "incident_id": incident_id,
        "status": "PENDING_HUMAN_REVIEW",
        "evidence_supplied": True,
        "learning_approved": False,
        "message": "Feedback saved. Human validation is required; automatic retraining is disabled."
    }


# ---------------- AGENT 6: SECURITY GAP ANALYSIS ----------------

def agent6_analyze_gaps(title, description):
    import re

    text = f"{title} {description}".lower()
    findings = []

    control_rules = {
        "authentication": {
            "terms": ("mfa", "multi-factor authentication", "authentication", "credentials"),
            "present": ("mfa is enabled", "multi-factor authentication is enabled", "phishing-resistant mfa is enabled"),
            "absent": ("mfa is disabled", "mfa is not enabled", "no mfa", "authentication controls are absent")
        },
        "access_control": {
            "terms": ("privilege", "permission", "access control", "authorization"),
            "present": ("least privilege is enforced", "access controls are enforced", "role-based access control is enabled"),
            "absent": ("excessive privileges", "unrestricted access", "access controls are disabled", "no access restrictions")
        },
        "network_monitoring": {
            "terms": ("network", "traffic", "dns", "lateral movement"),
            "present": ("network monitoring is enabled", "network traffic is monitored", "ids is deployed", "intrusion detection is enabled"),
            "absent": ("network monitoring is disabled", "no network monitoring", "network traffic is not monitored")
        },
        "data_protection": {
            "terms": ("exfiltration", "data leakage", "encryption", "sensitive data"),
            "present": ("data loss prevention is enabled", "dlp is deployed", "sensitive data is encrypted"),
            "absent": ("data loss prevention is disabled", "no data loss prevention", "sensitive data is unencrypted")
        },
        "endpoint_security": {
            "terms": ("malware", "endpoint", "ransomware", "execution", "edr"),
            "present": ("edr is deployed", "endpoint protection is enabled", "endpoint detection is active", "uses endpoint protection", "organization uses endpoint protection"),
            "absent": ("edr is disabled", "no endpoint protection", "endpoint protection is disabled")
        },
        "backup_recovery": {
            "terms": ("backup", "backups", "recovery", "restore"),
            "present": ("backup integrity is verified", "backups are regularly tested", "isolated backups are maintained", "recovery has been tested"),
            "absent": ("no backups", "backups are unavailable", "backup integrity failed", "backups are not isolated")
        },
        "patch_management": {
            "terms": ("vulnerability", "exploit", "unpatched", "software", "patch"),
            "present": ("security patches are applied", "systems are patched", "patch management is active"),
            "absent": ("unpatched system", "security patches are missing", "patch management is absent")
        }
    }

    for control, rules in control_rules.items():
        relevant = [term for term in rules["terms"] if term in text]
        if not relevant:
            continue

        absent = [term for term in rules["absent"] if term in text]

        present = []
        for term in rules["present"]:
            for match in re.finditer(re.escape(term), text):
                overlaps_negative = any(
                    neg_match.start() <= match.start() < neg_match.end()
                    for negative_term in absent
                    for neg_match in re.finditer(re.escape(negative_term), text)
                )
                if not overlaps_negative:
                    present.append(term)
                    break


        if present and absent:
            status = "CONFLICTING_EVIDENCE"
            reason = "The scenario contains both positive and negative control indicators."
        elif absent:
            status = "GAP_CONFIRMED"
            reason = "The scenario explicitly describes an absent or ineffective control; analyst verification is still required."
        elif present:
            status = "EVIDENCE_PRESENT"
            reason = "The scenario reports that the control is present; its effectiveness still requires validation."
        else:
            status = "REVIEW_REQUIRED"
            reason = "The scenario mentions this control area but does not establish whether the control is effective."

        findings.append({
            "control_area": control,
            "status": status,
            "matched_context": relevant + present + absent,
            "reason": reason
        })

    if not findings:
        findings.append({
            "control_area": "GENERAL_SECURITY",
            "status": "REVIEW_REQUIRED",
            "matched_context": [],
            "reason": "Insufficient scenario detail to identify specific control gaps."
        })

    return {
        "findings": findings,
        "limitation": "Keyword-based evidence screening, not a security control audit. GAP_CONFIRMED requires explicit scenario evidence and analyst verification."
    }


# ---------------- AGENT 7: INCIDENT MEMORY ----------------

def init_memory():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                output_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_feedback (
                feedback_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                recommended_action TEXT,
                actual_action TEXT NOT NULL,
                evidence TEXT NOT NULL,
                review_status TEXT NOT NULL,
                learning_approved INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
            )
        """)

def agent7_store_incident(title, description, result):
    init_memory()
    incident_id = str(uuid.uuid4())

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO incidents
            VALUES (?, ?, ?, ?, ?)""",
            (
                incident_id,
                datetime.now(timezone.utc).isoformat(),
                title,
                description,
                json.dumps(result, default=str)
            )
        )

    return incident_id

def agent7_get_history(limit=50):
    init_memory()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """SELECT incident_id, created_at, title, description, output_json
            FROM incidents ORDER BY created_at DESC LIMIT ?""",
            (int(limit),)
        ).fetchall()

    return [
        {
            "incident_id": r[0],
            "created_at": r[1],
            "title": r[2],
            "description": r[3],
            "result": json.loads(r[4])
        }
        for r in rows
    ]


# ---------------- AGENT 0: ORCHESTRATOR ----------------

def generate_incident_title(description):
    text = description.lower()

    ransomware = any(term in text for term in (
        "ransomware", "encrypted files", "files were encrypted",
        "encrypted production files", "encrypted the production files"
    ))
    exfiltration = any(term in text for term in (
        "data exfiltration", "data theft", "exfiltrated data",
        "data was exfiltrated", "was also exfiltrated",
        "exfiltrated to an external server"
    ))

    if ransomware and exfiltration:
        return "Ransomware and Data Exfiltration Incident"
    if ransomware:
        return "Ransomware Incident"
    if exfiltration:
        return "Data Exfiltration Incident"

    title_rules = [
        (("sql injection", "database query", "unsanitized input"), "Suspected SQL Injection Incident"),
        (("phishing", "suspicious email"), "Suspected Phishing Incident"),
        (("privilege escalation",), "Suspected Privilege Escalation Incident"),
        (("lateral movement",), "Suspected Lateral Movement Incident"),
        (("denial of service", "ddos"), "Suspected Denial-of-Service Incident"),
        (("malware", "malicious process"), "Suspected Malware Incident"),
    ]
    for terms, label in title_rules:
        if any(term in text for term in terms):
            return label

    words = description.strip().split()
    return " ".join(words[:7]).rstrip(".,;:") or "Unclassified Security Incident"


def run_pipeline(
    title,
    description,
    severity=None,
    likelihood=None,
    asset_criticality=None,
    exposure=None,
    historical_event_id=None
):
    if not description or not description.strip():
        raise ValueError("Scenario description is required.")

    title = title.strip() if title and title.strip() else generate_incident_title(description)

    classification = agent1_classify(title, description)
    risk = agent2_assess_risk(
        severity, likelihood, asset_criticality, exposure, title, description
    )
    defense = agent3_recommend_defense(title, description, risk)
    response = agent4_evaluate_response(historical_event_id)
    gaps = agent6_analyze_gaps(title, description)

    result = {
        "incident_title": title,
        "classification": classification,
        "risk_assessment": risk,
        "defense_recommendations": defense,
        "response_evaluation": response,
        "security_gap_analysis": gaps,
        "feedback_status": "AWAITING_ACTUAL_RESPONSE_AND_EVIDENCE",
        "execution_status": "COMPLETED_WITH_PROVISIONAL_CLASSIFICATION"
    }

    incident_id = agent7_store_incident(title, description, result)
    result["incident_id"] = incident_id

    required = [
        "classification", "risk_assessment",
        "defense_recommendations", "response_evaluation",
        "security_gap_analysis"
    ]
    if not all(k in result for k in required):
        raise RuntimeError("Orchestrator output validation failed.")

    return result
