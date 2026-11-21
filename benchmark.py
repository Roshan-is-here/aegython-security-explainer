"""
Measures how long the explainer engine takes per alert.
Run:  python benchmark.py
This times the engine only (not Streamlit rendering or browser time).
"""
import json
import statistics
import time
from pathlib import Path

from explainer_engine import analyze_security_alert


def main():
    data = json.loads((Path(__file__).parent / "alerts_data.json").read_text(encoding="utf-8"))
    alerts = list(data.values())
    loops, rounds = 2000, 5
    per_alert_us = []
    for _ in range(rounds):
        start = time.perf_counter()
        for _ in range(loops):
            for alert in alerts:
                analyze_security_alert(alert)
        elapsed = time.perf_counter() - start
        per_alert_us.append(elapsed / (loops * len(alerts)) * 1_000_000)

    median = statistics.median(per_alert_us)
    print(f"Alerts per round : {loops * len(alerts)} ({len(alerts)} profiles x {loops} loops)")
    print(f"Median time      : {median:.1f} microseconds per alert")
    print(f"Throughput       : about {1_000_000 / median:,.0f} alerts per second")


if __name__ == "__main__":
    main()