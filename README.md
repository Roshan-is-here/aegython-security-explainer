# AEGYTHON 2026: Grounded Security Alert Explainer

**Track 4: Grounded Explanations for Synthetic Security Signals**
**Author:** Roshan (GitHub: Roshan-is-here), solo participant

**Demo video:** [ADD LINK]

## 1. What This Project Does

Security tools raise alerts full of technical detail. This tool takes a synthetic security alert (JSON) and produces:

1. A plain-English **explanation** built only from fields in the alert
2. An **uncertainty rating** (Low / Medium / High) with a written reason
3. **Cautious guidance** for a Tier 1 SOC analyst (verify, escalate, request approval)

## 2. Approach

The engine is **deterministic and rule-based**. It does not call any AI model, runs fully offline, and gives the same output for the same input. Every conclusion can be traced to a specific rule, which is what "grounded" means here.

## 3. Pipeline

| Stage | What happens | Where |
|---|---|---|
| 1. Ingestion | Load a test profile from JSON, or paste custom JSON | `alerts_data.json`, `app.py` |
| 2. Signal extraction | Read alert type, severity, source IP, target asset, payload; classify the source as internal or external | `explainer_engine.py` |
| 3. Explanation + uncertainty | Match rules, write the explanation from alert fields, rate uncertainty with a reason | `explainer_engine.py` |
| 4. Safety guidance | Output cautious, ordered next steps for a Tier 1 analyst | `explainer_engine.py` |

## 4. How to Run

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

Use `python -m streamlit` rather than `streamlit` if the command is not recognized on Windows. The app opens at `http://localhost:8501`. Pick a test profile, or paste your own alert JSON, then click **Process Alert**.

To test the engine alone: `python explainer_engine.py`

## 5. Project Structure

```
aegython-security-explainer/
├── app.py                # Streamlit dashboard
├── explainer_engine.py   # rule-based analysis engine (no external dependencies)
├── alerts_data.json      # synthetic test alerts
├── requirements.txt
└── README.md
```

## 6. Input Format

```json
{
  "alert_type": "SQL Injection Attempt",
  "severity": "High",
  "source_ip": "203.0.113.45",
  "target_asset": "Production-Customer-DB",
  "payload_signal": "' OR '1'='1"
}
```

`alert_type` is required. Other fields are optional, but missing fields raise the uncertainty rating. Source IPs use reserved documentation ranges (`203.0.113.x`, `198.51.100.x`).

## 7. Rules

- **SQL injection:** strong signatures (always-true conditions like `OR '1'='1'`, `UNION SELECT`, stacked destructive statements, `SELECT ... FROM`) and weak indicators (comment markers, lone SQL keywords). Patterns use word-boundary regex, so ordinary text such as `ORDER` or `FOR` does not trigger them.
- **Failed logins:** a trusted internal source (private IP ranges or a VPN mention) conflicts with brute-force behavior, so the rating is High.
- **Unknown alert types:** no interpretation is offered; the alert is escalated.
- **Missing fields:** uncertainty is raised by one level and the missing fields are listed.

## 8. Test Cases and Results

| Profile | Scenario | Uncertainty | Reason |
|---|---|---|---|
| `test_case_1_normal` | SQL injection (`OR '1'='1'`) from an external IP against `Production-Customer-DB` | **Low** | Clear signature and external source |
| `test_case_2_edge` | 5 failed logins in 2 seconds from internal VPN IP `10.0.0.12` | **High** | Brute-force pattern conflicts with a trusted source |
| `test_case_3_invalid` | Corrupted log with no `alert_type` | **High** | Cannot be explained reliably; flagged as malformed |
| `test_case_4_weak_signal` | SQL injection label, payload with only a comment marker | **Medium** | Only a weak indicator |
| `test_case_5_unknown_type` | Port scan alert | **High** | No rule covers this alert type |
| `test_case_6_missing_fields` | Failed logins with no severity or target | **High** | Missing fields raised the rating |

Screenshots of each result: [ADD SCREENSHOTS]

## 9. Safety and Design Principles

- **Grounded:** explanations quote the alert's own fields and the rule that matched. Nothing is invented.
- **Explainable uncertainty:** every rating has a written reason.
- **Graceful failure:** invalid input produces a clear "cannot reliably explain" message and no guessed explanation.
- **Cautious guidance:** steps are to verify, escalate, and request approval. The tool never advises drastic actions such as isolating production systems without approval.

## 10. Known Limitations

- Rule-based: it only recognizes patterns that were explicitly coded.
- Tested on synthetic data only, not real SIEM or firewall logs.
- Small test set (six profiles).
- Uncertainty levels are heuristic, not statistical.
- Does not correlate multiple alerts over time.
- Internal/external classification uses standard private IP ranges only.

## 11. Future Work

- More alert types and signatures
- Multi-alert correlation
- Optional AI layer for wording, with the rules kept as a safety check
- Exportable analyst reports
