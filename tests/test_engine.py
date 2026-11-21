"""
Unit tests for the rule-based alert explainer (standard library only).

Run from the project root:
    python -m unittest discover -s tests -v
"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from explainer_engine import LEVELS, _is_internal, analyze_security_alert  # noqa: E402

REQUIRED_KEYS = {"signals", "explanation", "uncertainty", "uncertainty_reason", "proposed_action"}


def sqli(payload, ip="203.0.113.45", **extra):
    alert = {
        "alert_type": "SQL Injection Attempt",
        "severity": "High",
        "source_ip": ip,
        "target_asset": "Customer-DB",
        "payload_signal": payload,
    }
    alert.update(extra)
    return alert


def logins(ip, payload="5 failed attempts within 2 seconds", **extra):
    alert = {
        "alert_type": "Multiple Failed Logins",
        "severity": "Medium",
        "source_ip": ip,
        "target_asset": "HR-Portal-Server",
        "payload_signal": payload,
    }
    alert.update(extra)
    return alert


class TestSqlInjection(unittest.TestCase):
    def test_clear_signature_from_external_ip_is_low(self):
        r = analyze_security_alert(sqli("' OR '1'='1"))
        self.assertEqual(r["uncertainty"], "Low")
        self.assertIn("external", r["uncertainty_reason"])

    def test_same_signature_from_internal_ip_is_only_medium(self):
        r = analyze_security_alert(sqli("' OR '1'='1", ip="192.168.1.55"))
        self.assertEqual(r["uncertainty"], "Medium")

    def test_each_strong_signature_is_detected(self):
        payloads = [
            "' OR '1'='1",
            "admin' OR 1=1 --",
            "1 UNION SELECT username, password FROM users",
            "x'; DROP TABLE users;--",
            "SELECT * FROM users WHERE id = 1",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertEqual(analyze_security_alert(sqli(payload))["uncertainty"], "Low")

    def test_ordinary_words_containing_or_are_not_a_signature(self):
        r = analyze_security_alert(sqli("ORDER BY name, FOR sale, COLOR red"))
        self.assertNotEqual(r["uncertainty"], "Low")
        self.assertIn("contradict", r["uncertainty_reason"])

    def test_weak_indicator_is_medium(self):
        r = analyze_security_alert(sqli("search=report; -- end of query"))
        self.assertEqual(r["uncertainty"], "Medium")

    def test_explanation_quotes_the_real_payload(self):
        payload = "1 UNION SELECT a FROM b"
        r = analyze_security_alert(sqli(payload))
        self.assertIn(payload, r["explanation"])

    def test_explanation_never_invents_an_example_payload(self):
        r = analyze_security_alert(sqli("search=report; -- end of query"))
        self.assertNotIn("'1'='1", r["explanation"])

    def test_guidance_is_cautious_for_tier_1(self):
        guidance = analyze_security_alert(sqli("' OR '1'='1"))["proposed_action"].lower()
        self.assertIn("escalate", guidance)
        self.assertIn("approval", guidance)
        self.assertNotIn("immediately", guidance)

    def test_non_string_payloads_do_not_crash(self):
        for payload in (12345, None, ["a", "b"], {"x": 1}):
            with self.subTest(payload=payload):
                r = analyze_security_alert(sqli(payload))
                self.assertIn(r["uncertainty"], LEVELS)

    def test_very_long_payload_is_truncated(self):
        r = analyze_security_alert(sqli("A" * 10000 + " OR 1=1"))
        self.assertLessEqual(len(r["signals"]["payload_signal"]), 300)


class TestFailedLogins(unittest.TestCase):
    def test_trusted_internal_source_is_high_uncertainty(self):
        r = analyze_security_alert(logins("10.0.0.12"))
        self.assertEqual(r["uncertainty"], "High")
        self.assertIn("do not lock", r["proposed_action"].lower())

    def test_vpn_mention_is_high_even_with_external_ip(self):
        r = analyze_security_alert(logins("203.0.113.5", payload="5 failures via corporate VPN"))
        self.assertEqual(r["uncertainty"], "High")

    def test_external_source_is_medium(self):
        self.assertEqual(analyze_security_alert(logins("203.0.113.5"))["uncertainty"], "Medium")

    def test_singular_alert_type_is_still_recognised(self):
        r = analyze_security_alert(logins("203.0.113.5", alert_type="Failed Login Attempt"))
        self.assertNotIn("No rule covers", r["uncertainty_reason"])

    def test_explanation_names_the_target(self):
        r = analyze_security_alert(logins("203.0.113.5"))
        self.assertIn("HR-Portal-Server", r["explanation"])


class TestUnknownAndIncomplete(unittest.TestCase):
    def test_unknown_alert_type_is_high_and_not_interpreted(self):
        r = analyze_security_alert({"alert_type": "Port Scan Detected", "source_ip": "198.51.100.23"})
        self.assertEqual(r["uncertainty"], "High")
        self.assertIn("No rule covers", r["uncertainty_reason"])

    def test_missing_fields_raise_uncertainty_and_are_listed(self):
        alert = logins("203.0.113.5")
        del alert["severity"], alert["target_asset"]
        r = analyze_security_alert(alert)
        self.assertEqual(r["uncertainty"], "High")  # Medium raised one level
        self.assertIn("severity", r["uncertainty_reason"])
        self.assertIn("target_asset", r["uncertainty_reason"])

    def test_missing_severity_is_not_silently_treated_as_low(self):
        alert = sqli("' OR '1'='1")
        del alert["severity"]
        r = analyze_security_alert(alert)
        self.assertEqual(r["signals"]["impact_level"], "Unknown")
        self.assertNotEqual(r["uncertainty"], "Low")


class TestInvalidInput(unittest.TestCase):
    def test_invalid_inputs_are_flagged_not_explained(self):
        bad_inputs = [
            None,
            "ERROR_MALFORMED_PACKET",
            123,
            [],
            {},
            {"corrupted_log": "x"},
            {"alert_type": None},
            {"alert_type": 123},
            {"alert_type": "   "},
        ]
        for bad in bad_inputs:
            with self.subTest(bad=bad):
                r = analyze_security_alert(bad)
                self.assertEqual(r["uncertainty"], "High")
                self.assertEqual(r["signals"], {"status": "MALFORMED_OR_INVALID_LOG"})
                self.assertIn("no reliable explanation", r["explanation"].lower())
                self.assertTrue(REQUIRED_KEYS <= set(r))


class TestIpClassification(unittest.TestCase):
    def test_internal_ranges(self):
        for ip in ("10.0.0.12", "172.16.5.4", "192.168.1.55", "127.0.0.1", "169.254.1.1",
                   "::1", "fd00::1", "fe80::1"):
            with self.subTest(ip=ip):
                self.assertIs(_is_internal(ip), True)

    def test_external_ranges(self):
        for ip in ("203.0.113.45", "8.8.8.8", "172.32.0.1", "2001:db8::1"):
            with self.subTest(ip=ip):
                self.assertIs(_is_internal(ip), False)

    def test_unparseable_addresses_are_unknown_not_guessed(self):
        for ip in ("not-an-ip", "", None, "999.1.1.1"):
            with self.subTest(ip=ip):
                self.assertIsNone(_is_internal(ip))


class TestEngineContract(unittest.TestCase):
    def test_output_always_has_the_full_schema(self):
        samples = [sqli("' OR '1'='1"), logins("10.0.0.12"), {"alert_type": "X"}, None, "junk"]
        for sample in samples:
            with self.subTest(sample=sample):
                r = analyze_security_alert(sample)
                self.assertTrue(REQUIRED_KEYS <= set(r))
                self.assertIn(r["uncertainty"], LEVELS)
                self.assertTrue(r["uncertainty_reason"].strip())
                self.assertTrue(r["proposed_action"].strip())

    def test_engine_is_deterministic(self):
        alert = sqli("' OR '1'='1")
        self.assertEqual(analyze_security_alert(alert), analyze_security_alert(alert))

    def test_engine_does_not_modify_its_input(self):
        alert = logins("10.0.0.12")
        before = copy.deepcopy(alert)
        analyze_security_alert(alert)
        self.assertEqual(alert, before)


class TestSampleData(unittest.TestCase):
    """Regression check on the profiles shipped in alerts_data.json."""

    EXPECTED = {
        "test_case_1_normal": "Low",
        "test_case_2_edge": "High",
        "test_case_3_invalid": "High",
        "test_case_4_weak_signal": "Medium",
        "test_case_5_unknown_type": "High",
        "test_case_6_missing_fields": "High",
    }

    def test_shipped_profiles_give_expected_uncertainty(self):
        data = json.loads((ROOT / "alerts_data.json").read_text(encoding="utf-8"))
        for name, expected in self.EXPECTED.items():
            with self.subTest(profile=name):
                self.assertIn(name, data)
                self.assertEqual(analyze_security_alert(data[name])["uncertainty"], expected)


if __name__ == "__main__":
    unittest.main()
