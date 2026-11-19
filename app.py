import streamlit as st
import pandas as pd
import json
from pathlib import Path

import agents

st.set_page_config(
    page_title="Adaptive Purple Team AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI-Driven Adaptive Purple Team Cybersecurity System")
st.caption("Evidence-first multi-agent cybersecurity analysis platform")

# Project data locations
ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
PROCESSED = agents.DATA

AGENT_ROLES = [
    ("Agent 0 — Orchestrator", "Coordinates execution, checks required outputs, and consolidates the pipeline result."),
    ("Agent 1 — Attack Intelligence", "Identifies attack families from scenario evidence, determines operational context, and produces a provisional ML activity classification."),
    ("Agent 2 — Risk Assessment", "Estimates severity, likelihood, asset criticality, and exposure using a transparent heuristic rubric."),
    ("Agent 3 — Adaptive Defense", "Generates threat-specific prevention, detection, containment, recovery, and response recommendations."),
    ("Agent 4 — Response Evaluation", "Summarizes historical detection and response metrics; these are reference baselines, not measurements of the current incident."),
    ("Agent 5 — Feedback Validation", "Checks actual response evidence and records feedback for human review; it does not automatically retrain the model."),
    ("Agent 6 — Security Gap Analysis", "Screens the scenario for explicit control evidence and flags confirmed, conflicting, or unresolved findings."),
    ("Agent 7 — Incident Memory", "Stores and retrieves incident records and feedback using a local SQLite database.")
]

st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Select module",
    ["Overview", "Incident Analysis", "Incident History", "Dataset Insights", "System Information"]
)

def load_csv(path):
    return pd.read_csv(path)

# ---------------- OVERVIEW ----------------

if page == "Overview":
    st.header("Project Overview")
    st.markdown(
        "A coordinated, evidence-first purple-team workflow that analyzes a supplied security scenario, "
        "assesses risk, recommends defensive actions, evaluates historical response data, and stores "
        "incident records for analyst review."
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("Specialized agents", "8")
    c2.metric("Primary attack records", "14,133")
    c3.metric("Secondary records", "50,000")

    st.subheader("System Architecture and Data Flow")
    architecture_dot = r"""
digraph PurpleTeam {
  graph [rankdir=TB, bgcolor="transparent", pad="0.25", nodesep="0.35", ranksep="0.55"];
  node [shape=box, style="rounded,filled", fillcolor="#EAF1F8", color="#35506B", fontname="Arial", fontsize=10];
  edge [color="#526579", fontname="Arial", fontsize=9, arrowsize=0.7];
  analyst [label="Analyst input\\nScenario + optional evidence", fillcolor="#DCEBFA"];
  orchestrator [label="Agent 0\\nOrchestrator", fillcolor="#C8DCF2"];
  primary [label="Primary dataset\\nAttack_Dataset.csv", shape=cylinder, fillcolor="#E5F2E5"];
  secondary [label="Secondary dataset\\nPurple Team tables", shape=cylinder, fillcolor="#FFF0D8"];
  a1 [label="Agent 1\\nAttack intelligence + ML"];
  a2 [label="Agent 2\\nRisk assessment"];
  a3 [label="Agent 3\\nAdaptive defense"];
  a4 [label="Agent 4\\nResponse evaluation"];
  a6 [label="Agent 6\\nSecurity gap analysis"];
  output [label="Consolidated incident analysis", fillcolor="#DCEBFA"];
  a5 [label="Agent 5\\nFeedback validation"];
  human [label="Analyst review\\nActual response + evidence", fillcolor="#F1E7FA"];
  memory [label="Agent 7\\nSQLite incident memory", shape=cylinder, fillcolor="#F1E7FA"];
  analyst -> orchestrator;
  orchestrator -> a1; orchestrator -> a2; orchestrator -> a3; orchestrator -> a4; orchestrator -> a6;
  primary -> a1 [label="classifier knowledge"];
  secondary -> a4 [label="historical metrics"];
  secondary -> a3 [style=dashed, label="supporting context"];
  a1 -> output; a2 -> output; a3 -> output; a4 -> output; a6 -> output;
  output -> memory [label="store incident"];
  output -> a5;
  human -> a5;
  a5 -> memory [label="pending human review"];
  memory -> orchestrator [style=dashed, label="retrieve history"];
  a5 -> a1 [style=dotted, label="approved curation only"];
}
"""
    st.graphviz_chart(architecture_dot, use_container_width=True)
    st.caption(
        "The primary dataset is reserved for Agent 1's attack-intelligence workflow. "
        "The secondary dataset is supporting historical data for response evaluation and other supporting analysis. "
        "The datasets are not merged."
    )

    st.subheader("Eight-Agent Responsibilities")
    for name, role in AGENT_ROLES:
        with st.expander(name):
            st.write(role)

    st.subheader("Datasets")
    d1, d2 = st.columns(2)
    with d1:
        st.markdown("**Primary dataset — `Attack_Dataset.csv`**")
        st.metric("Records", "14,133")
        st.write("Role: primary attack knowledge and provisional activity-classification source for Agent 1.")
        st.write("Local project file: `data/raw/Attack_Dataset.csv`")
        primary_path = RAW / "Attack_Dataset.csv"
        if primary_path.exists():
            st.download_button(
                "Download primary dataset",
                data=primary_path.read_bytes(),
                file_name="Attack_Dataset.csv",
                mime="text/csv",
                key="download_primary_overview"
            )
        st.caption("The project archive does not contain a verified original dataset download URL. Source references embedded in the CSV are descriptive source names, not a single canonical download link.")
    with d2:
        st.markdown("**Secondary dataset — `purple_team_dataset.csv`**")
        st.metric("Records", "50,000 across five tables")
        st.write("Role: supporting events, response actions, security logs, network traffic, and response metrics.")
        st.write("Local project file: `data/raw/purple_team_dataset.csv`")
        secondary_path = RAW / "purple_team_dataset.csv"
        if secondary_path.exists():
            st.download_button(
                "Download secondary dataset",
                data=secondary_path.read_bytes(),
                file_name="purple_team_dataset.csv",
                mime="text/csv",
                key="download_secondary_overview"
            )
        st.caption("The project archive does not contain a verified original dataset download URL.")

    st.markdown("**Framework references**")
    st.markdown(
        "- [MITRE ATT&CK](https://attack.mitre.org/) — adversary tactics and techniques reference.\n"
        "- [MITRE ATLAS](https://atlas.mitre.org/) — AI/ML threat reference."
    )

    st.subheader("Dataset Previews")
    st.markdown("**Primary dataset: Attack knowledge**")
    primary_path = RAW / "Attack_Dataset.csv"
    if primary_path.exists():
        primary = load_csv(primary_path)
        st.write("Columns:", ", ".join(map(str, primary.columns)))
        preview_cols = [c for c in ["ID", "Title", "Category", "Attack Type", "Scenario Description", "MITRE Technique", "Impact", "Source"] if c in primary.columns]
        st.dataframe(primary[preview_cols].head(8), use_container_width=True, hide_index=True)
        p1, p2, p3 = st.columns(3)
        p1.metric("Unique categories", f"{primary['Category'].nunique(dropna=True):,}" if "Category" in primary else "N/A")
        p2.metric("Unique attack types", f"{primary['Attack Type'].nunique(dropna=True):,}" if "Attack Type" in primary else "N/A")
        p3.metric("Missing source values", f"{primary['Source'].isna().sum():,}" if "Source" in primary else "N/A")
        if "Category" in primary:
            st.markdown("Top categories by record count")
            st.bar_chart(primary["Category"].fillna("Missing").value_counts().head(10))
    else:
        st.warning("Primary dataset file is missing from data/raw.")

    st.markdown("**Secondary dataset: five supporting tables**")
    secondary_tables = [
        ("Events", "purple_events.csv", "Attack event records and target systems."),
        ("Responses", "purple_responses.csv", "Detection and response actions associated with events."),
        ("Logs", "purple_logs.csv", "Security log records and event references."),
        ("Network Traffic", "purple_network_traffic.csv", "Network-flow observations associated with events."),
        ("Response Metrics", "purple_response_metrics.csv", "Detection/response timing and aggregate quality metrics.")
    ]
    tabs = st.tabs([item[0] for item in secondary_tables])
    for tab, (label, filename, description) in zip(tabs, secondary_tables):
        with tab:
            path = PROCESSED / filename
            st.caption(description)
            if path.exists():
                df = load_csv(path)
                st.metric(f"{label} records", f"{len(df):,}")
                st.dataframe(df.head(10), use_container_width=True, hide_index=True)
                st.caption(f"Processed table: data/processed/{filename}")
            else:
                st.error(f"Missing processed table: {filename}")

    st.info(
        "Governance boundary: the secondary dataset is not used as Agent 1 classifier input. "
        "Model predictions and heuristic findings are provisional and require analyst validation."
    )

# ---------------- INCIDENT ANALYSIS ----------------

elif page == "Incident Analysis":
    st.header("New Security Incident")

    with st.form("incident_form"):
        title = st.text_input(
            "Incident Title (Optional)",
            placeholder="Leave blank to generate automatically"
        )

        description = st.text_area(
            "What happened? Describe what you observed (Required)",
            height=150,
            placeholder="Example: An employee received a suspicious email attachment. After opening it, unusual processes appeared on the workstation."
        )

        st.subheader("Automated Risk Assessment")
        st.info(
            "Agent 2 estimates severity, likelihood, asset criticality and exposure "
            "from the incident description. An analyst should validate the estimate."
        )
        severity = likelihood = criticality = exposure = None

        st.subheader("Historical Response Comparison")
        event_id = st.number_input(
            "Optional historical event ID",
            min_value=0,
            value=0,
            help="Leave at zero to use aggregate historical response metrics."
        )

        submitted = st.form_submit_button(
            "Run Eight-Agent Analysis",
            type="primary",
            use_container_width=True
        )

    if submitted:
        if not description.strip():
            st.error("Please describe what happened.")
        else:
            try:
                with st.spinner("Executing the multi-agent pipeline..."):
                    result = agents.run_pipeline(
                        title,
                        description,
                        severity,
                        likelihood,
                        criticality,
                        exposure,
                        int(event_id) if event_id else None
                    )
                st.session_state["latest_result"] = result
                st.success("Incident analysis completed.")
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    result = st.session_state.get("latest_result")

    if result:
        st.divider()
        st.header("Analysis Results")

        classification = result["classification"]
        risk = result["risk_assessment"]

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Final Activity Assessment", classification["activity"].replace("_", " "))
        with c2:
            candidate = classification.get("activity_candidate")
            confidence = classification.get("confidence")
            st.metric(
                "Experimental ML Candidate",
                candidate.replace("_", " ") if candidate else "Unavailable",
                f"Model score: {confidence:.2%}" if confidence is not None else None
            )
        with c3:
            st.metric("Risk Level", risk["level"], f"Score: {risk['score']}")

        st.warning(classification["warning"])

        with st.expander("Agent 1 — Attack Intelligence and Classification", expanded=True):
            st.markdown("### Attack Families")
            families = classification.get("attack_families", [])
            if families:
                for item in families:
                    st.markdown(f"**{item['family'].replace('_', ' ')}**")
                    st.write("Evidence:", ", ".join(item["matched_evidence"]))
                    st.write("Evidence status:", item["evidence_status"])
                    st.divider()
            else:
                st.info("No attack family identified from the available scenario text.")

            st.markdown("### Operational Context")
            st.write(classification.get("operational_context", "UNKNOWN").replace("_", " "))
            st.markdown("### Final Activity Assessment")
            st.write(classification.get("activity", "UNKNOWN").replace("_", " "))
            st.write("Assignment basis:", classification.get("activity_status", "UNSPECIFIED").replace("_", " "))
            st.markdown("### Experimental ML Candidate (diagnostic)")
            st.write(classification.get("activity_candidate", "UNAVAILABLE").replace("_", " "))
            confidence = classification.get("confidence")
            if confidence is not None:
                st.metric("Uncalibrated ML model score", f"{confidence * 100:.2f}%")
            st.markdown("### Alternative ML Predictions")
            for alternative in classification.get("alternatives", []):
                st.write(
                    f"- {alternative['class'].replace('_', ' ')}: "
                    f"{alternative['probability'] * 100:.2f}%"
                )
            st.caption(classification.get("warning", ""))
            st.caption(
                "Attack-family and evidence-status outputs use keyword rules. "
                "Operational context uses contextual rules. The ML activity candidate is experimental "
                "and its score is not a calibrated probability of correctness."
            )

        with st.expander("Agent 2 — Risk Assessment", expanded=True):
            st.json(risk)

        with st.expander("Agent 3 — Adaptive Defense Recommendations", expanded=True):
            defense = result["defense_recommendations"]
            for section in ("prevention", "detection", "containment", "recovery", "response"):
                st.markdown(f"**{section.replace('_', ' ').title()}**")
                items = defense.get(section, [])
                if items:
                    for item in items:
                        st.write("•", item)
                else:
                    st.caption("No specific recommendation generated.")
            st.caption(defense["basis"])

        with st.expander("Agent 4 — Response Evaluation"):
            st.json(result["response_evaluation"])

        with st.expander("Agent 5 — Feedback and Learning"):
            st.write("Current status:", result["feedback_status"])
            st.markdown("**Submit actual response and supporting evidence**")
            with st.form("feedback_form"):
                actual = st.text_area("Actual response taken")
                evidence = st.text_area("Evidence supporting the response")
                recommended = st.text_area("Recommended action", value="; ".join(
                    item
                    for section in ("prevention", "detection", "containment", "recovery", "response")
                    for item in result["defense_recommendations"].get(section, [])
                ))
                feedback_submit = st.form_submit_button("Validate Feedback")
            if feedback_submit:
                feedback = agents.agent5_validate_feedback(
                    recommended, actual, evidence, result["incident_id"]
                )
                st.json(feedback)

        with st.expander("Agent 6 — Security Gap Analysis"):
            st.json(result["security_gap_analysis"])

        with st.expander("Agent 7 — Incident Memory"):
            st.write("Incident ID:", result["incident_id"])
            st.write("Incident saved to SQLite memory.")

        with st.expander("Agent 0 — Orchestrator Output"):
            st.json(result)

# ---------------- INCIDENT HISTORY ----------------

elif page == "Incident History":
    st.header("Incident Memory")
    history = agents.agent7_get_history(100)
    if not history:
        st.info("No incidents have been stored.")
    else:
        st.metric("Stored Incidents", len(history))
        rows = []
        for incident in history:
            result = incident["result"]
            classification = result.get("classification", {})
            risk = result.get("risk_assessment", {})
            rows.append({
                "Date": incident["created_at"][:19],
                "Incident": incident["title"],
                "Activity": classification.get("activity", "UNKNOWN"),
                "ML Candidate": classification.get("activity_candidate", "Unavailable"),
                "ML Score": classification.get("confidence"),
                "Risk": risk.get("level", "UNKNOWN"),
                "Incident ID": incident["incident_id"]
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        selected = st.selectbox(
            "Inspect incident",
            options=range(len(history)),
            format_func=lambda i: history[i]["title"] + " — " + history[i]["incident_id"][:8]
        )
        st.json(history[selected]["result"])

# ---------------- DATASET INSIGHTS ----------------

elif page == "Dataset Insights":
    st.header("Supporting Dataset Insights")
    files = {
        "Attack Events": "purple_events.csv",
        "Response Records": "purple_responses.csv",
        "Security Logs": "purple_logs.csv",
        "Network Traffic": "purple_network_traffic.csv",
        "Response Metrics": "purple_response_metrics.csv"
    }
    for label, filename in files.items():
        try:
            df = pd.read_csv(PROCESSED / filename)
            st.metric(label, f"{len(df):,} records")
        except Exception as e:
            st.error(f"{label}: {e}")
    try:
        events = pd.read_csv(PROCESSED / "purple_events_taxonomy_enriched.csv")
        st.subheader("Historical Attack Categories")
        counts = events["attack_category"].value_counts().head(12)
        st.bar_chart(counts)
    except Exception as e:
        st.warning(f"Could not load taxonomy statistics: {e}")
    st.caption(
        "These are supporting historical datasets. They are not used to train Agent 1."
    )

# ---------------- SYSTEM INFORMATION ----------------

elif page == "System Information":
    st.header("System Architecture")
    for name, description in AGENT_ROLES:
        st.markdown(f"**{name}** — {description}")
    st.divider()
    st.subheader("Model Information")
    st.write("Model:", "TF-IDF + Logistic Regression")
    st.write("Model file:", str(agents.MODEL_PATH))
    st.write("Training status:", "PROVISIONAL EXPERIMENTAL")
    st.write("Human approval:", "PENDING")
    st.write("Automatic retraining:", "DISABLED")
    st.subheader("Data Governance")
    st.write("- Primary Attack Dataset: Agent 1 attack-intelligence/classification source.")
    st.write("- Secondary Purple Dataset: supporting agents and historical analysis only.")
    st.write("- The two datasets are not merged.")
    st.write("- Uncertain predictions: flagged for human validation.")
    st.write("- Historical metrics: distinguished from current incident measurements.")
    st.write("- Model learning: requires validated human feedback.")

st.sidebar.divider()
st.sidebar.caption("AIML Project | Purple Team System")
st.sidebar.caption("Experimental prototype — not a production SOC platform")
