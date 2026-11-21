"""
Rule-based, grounded explainer for synthetic security alerts (AEGYTHON 2026, Track 4).

Design rules:
- Every sentence in the explanation comes from fields in the alert or from a rule that matched.
- Every uncertainty rating comes with a reason.
- Guidance is cautious: verify, escalate, request approval. No drastic actions for Tier 1.
"""
import ipaddress
import re

LEVELS = ["Low", "Medium", "High"]

# Explicit private ranges. We do NOT use ip.is_private because Python treats
# documentation ranges such as 203.0.113.0/24 as private.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
     "::1/128", "fc00::/7", "fe80::/10")
]

# (regex, human-readable label)
STRONG_SQLI = [
    (r"\b(or|and)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\2\b", "always-true condition (e.g. OR '1'='1')"),
    (r"\bunion\b\s+(all\s+)?select\b", "UNION SELECT"),
    (r";\s*(drop|delete|insert|update)\b", "stacked destructive statement"),
    (r"\bselect\b.+\bfrom\b", "SELECT ... FROM query"),
]
WEAK_SQLI = [
    (r"(--|/\*|;)", "SQL comment or statement separator"),
    (r"\b(select|union|drop|insert|update|delete)\b", "SQL keyword"),
]


def _bump(level):
    """Raise uncertainty by one level (Low -> Medium -> High)."""
    return LEVELS[min(LEVELS.index(level) + 1, len(LEVELS) - 1)]


def _is_internal(ip_text):
    """True = internal, False = external, None = not a valid IP."""
    try:
        ip = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return None
    return any(ip in net for net in INTERNAL_NETWORKS if net.version == ip.version)


def _first_match(patterns, text):
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return label
    return None


def analyze_security_alert(alert_data):
    result = {
        "signals": {},
        "explanation": "",
        "uncertainty": "Low",
        "uncertainty_reason": "",
        "proposed_action": "",
    }

    # ---- Invalid / corrupted input -------------------------------------
    if (
        not isinstance(alert_data, dict)
        or not isinstance(alert_data.get("alert_type"), str)
        or not alert_data["alert_type"].strip()
    ):
        result["signals"] = {"status": "MALFORMED_OR_INVALID_LOG"}
        result["uncertainty"] = "High"
        result["uncertainty_reason"] = "Required field 'alert_type' is missing or the input is not a valid alert object."
        result["explanation"] = (
            "The input does not match the expected alert structure, so no reliable "
            "explanation can be produced. Nothing has been inferred from it."
        )
        result["proposed_action"] = (
            "1. Flag the log source for pipeline inspection.\n"
            "2. Do not act on this entry until a valid copy of the alert is available."
        )
        return result

    # ---- Signal extraction ----------------------------------------------
    alert_type = alert_data["alert_type"].strip()
    severity = alert_data.get("severity") or "Unknown"
    source_ip = alert_data.get("source_ip") or "Unknown"
    target_asset = alert_data.get("target_asset") or "Unknown"
    payload = str(alert_data.get("payload_signal") or "")[:300]

    t = alert_type.lower()
    is_sqli = "sql injection" in t or "sqli" in t
    is_login = "failed login" in t

    required = ["severity", "source_ip", "target_asset"] + (["payload_signal"] if is_sqli else [])
    missing = [k for k in required if not alert_data.get(k)]

    internal = _is_internal(source_ip)
    source_desc = {True: "internal", False: "external", None: "unverifiable"}[internal]

    result["signals"] = {
        "detected_attack": alert_type,
        "impact_level": severity,
        "origin_address": source_ip,
        "compromised_node": target_asset,  # kept for app.py compatibility; value is the alert's target
        "payload_signal": payload,
        "source_type": source_desc,
    }

    # ---- Rule: SQL injection ---------------------------------------------
    if is_sqli:
        strong = _first_match(STRONG_SQLI, payload)
        weak = _first_match(WEAK_SQLI, payload)

        if strong:
            result["explanation"] = (
                f"The alert reports a SQL injection attempt from {source_ip} ({source_desc} address) "
                f"against {target_asset}. The payload {payload!r} matches the pattern: {strong}."
            )
            if internal is False:
                result["uncertainty"] = "Low"
                result["uncertainty_reason"] = (
                    f"The payload contains a clear SQL injection signature ({strong}) "
                    "and the source is an external address."
                )
                result["proposed_action"] = (
                    "1. Escalate to Tier 2 / the incident owner now; this matches a known injection pattern.\n"
                    f"2. Request approval to block {source_ip} at the perimeter firewall.\n"
                    f"3. Check web and database logs for {target_asset} around the alert time for signs the query succeeded.\n"
                    "4. Do not isolate the production database without approval from the asset owner or incident lead.\n"
                    "5. Notify the application team to review the endpoint for unparameterized queries."
                )
            else:
                result["uncertainty"] = "Medium"
                result["uncertainty_reason"] = (
                    f"The payload contains a clear SQL injection signature ({strong}), but the source "
                    f"is {source_desc}, so it could be an authorized scanner or a compromised internal host."
                )
                result["proposed_action"] = (
                    "1. Check whether the source is an approved vulnerability scanner or a pen-test host.\n"
                    f"2. If not approved, escalate to Tier 2 and investigate the host at {source_ip}.\n"
                    f"3. Review logs for {target_asset} for signs the query succeeded."
                )
        elif weak:
            result["uncertainty"] = "Medium"
            result["explanation"] = (
                f"The alert is labelled as SQL injection against {target_asset} from {source_ip}, "
                f"but the payload {payload!r} only shows a weak indicator ({weak}). "
                "It is not enough on its own to confirm an injection attempt."
            )
            result["uncertainty_reason"] = f"Only a weak indicator was found in the payload ({weak})."
            result["proposed_action"] = (
                "1. Review the application log around this event to decide whether it is a true positive.\n"
                "2. Do not block or isolate anything until the pattern is confirmed.\n"
                "3. Escalate to Tier 2 if the review is inconclusive."
            )
        else:
            result["uncertainty"] = "High"
            result["explanation"] = (
                f"The alert is labelled as SQL injection against {target_asset} from {source_ip}, "
                "but the payload contains no recognizable SQL syntax, so the label is not supported by the evidence."
            )
            result["uncertainty_reason"] = "The alert type and the payload contradict each other."
            result["proposed_action"] = (
                "1. Treat the alert label as unverified.\n"
                "2. Escalate to Tier 2 with the raw log for signature review."
            )

    # ---- Rule: failed logins ---------------------------------------------
    elif is_login:
        vpn_mentioned = "vpn" in payload.lower()
        result["explanation"] = f"The alert reports multiple failed logins against {target_asset} from {source_ip} ({source_desc} address)."
        if payload:
            result["explanation"] += f" Payload note: {payload!r}."

        if internal is True or vpn_mentioned:
            result["uncertainty"] = "High"
            result["uncertainty_reason"] = (
                "Repeated failed logins can indicate brute force, but the source is "
                "internal/VPN, which is normally trusted. The signals conflict, so a human must decide."
            )
            result["proposed_action"] = (
                "1. Do not lock out the account or block the source yet.\n"
                "2. Contact the owner of the internal source to check for forgotten credentials or a misconfigured client.\n"
                "3. If the owner cannot explain it, escalate to Tier 2 as possible account compromise."
            )
        else:
            result["uncertainty"] = "Medium"
            result["uncertainty_reason"] = (
                "Failed logins from an external source fit brute force, but the alert alone "
                "cannot separate it from user error."
            )
            result["proposed_action"] = (
                f"1. Check the source {source_ip} against threat-intelligence blocklists.\n"
                "2. Ask the account owner whether they were trying to sign in.\n"
                "3. If unexplained, request approval to temporarily lock the account and escalate to Tier 2."
            )

    # ---- Unknown alert type ----------------------------------------------
    else:
        result["uncertainty"] = "High"
        result["explanation"] = (
            f"The alert type {alert_type!r} does not match any rule in this engine, "
            "so no interpretation is offered."
        )
        result["uncertainty_reason"] = "No rule covers this alert type."
        result["proposed_action"] = "Forward the full alert to Tier 2 SOC engineers for manual review."

    # ---- Missing fields raise uncertainty --------------------------------
    if missing:
        result["uncertainty"] = _bump(result["uncertainty"])
        result["uncertainty_reason"] += f" Fields missing from the alert: {', '.join(missing)}."

    return result


if __name__ == "__main__":
    import json

    samples = {
        "normal": {"alert_type": "SQL Injection Attempt", "severity": "High", "source_ip": "203.0.113.45",
                   "target_asset": "Production-Customer-DB", "payload_signal": "' OR '1'='1"},
        "edge": {"alert_type": "Failed Logins", "severity": "Medium", "source_ip": "10.0.0.12",
                 "target_asset": "HR-Portal-Server", "payload_signal": "5 failed logins in 2 seconds via VPN"},
        "invalid": "ERROR_MALFORMED_PACKET...",
        "false_positive_check": {"alert_type": "SQL Injection Attempt", "severity": "Low", "source_ip": "203.0.113.9",
                                 "target_asset": "Shop-DB", "payload_signal": "ORDER BY name, FOR sale, COLOR red"},
    }
    for name, sample in samples.items():
        print(f"=== {name} ===")
        print(json.dumps(analyze_security_alert(sample), indent=2))