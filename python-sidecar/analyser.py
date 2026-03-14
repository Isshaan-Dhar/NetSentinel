import os
import math
import logging
import schedule
import time
from collections import defaultdict
from datetime import datetime, timezone
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from models.anomaly import AnomalyAlert

load_dotenv("../.env")
load_dotenv(".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("netsentinel-analyser")

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "timescaledb"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
}

PROXY_URL = "http://proxy:8080/internal/anomaly"
ANALYSIS_WINDOW = 300
MIN_REQUESTS = 5


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def fetch_window(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT client_ip, method, path, user_agent, status_code, duration_ms, blocked, occurred_at
            FROM request_stats
            WHERE occurred_at >= NOW() - INTERVAL '%s seconds'
            ORDER BY occurred_at ASC
            """,
            (ANALYSIS_WINDOW,)
        )
        return [dict(r) for r in cur.fetchall()]


def fetch_attacks(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT client_ip, category, severity
            FROM attack_log
            WHERE occurred_at >= NOW() - INTERVAL '%s seconds'
            """,
            (ANALYSIS_WINDOW,)
        )
        return [dict(r) for r in cur.fetchall()]


def ua_entropy(agents: list[str]) -> float:
    if not agents:
        return 0.0
    unique = set(agents)
    total = len(agents)
    return -sum((agents.count(u) / total) * math.log2(agents.count(u) / total) for u in unique)


def build_features(requests: list[dict], attacks: list[dict]) -> dict[str, list]:
    ip_requests = defaultdict(list)
    for r in requests:
        ip_requests[r["client_ip"]].append(r)

    ip_attacks = defaultdict(list)
    for a in attacks:
        ip_attacks[a["client_ip"]].append(a)

    features = {}
    for ip, reqs in ip_requests.items():
        if len(reqs) < MIN_REQUESTS:
            continue
        total = len(reqs)
        blocked = sum(1 for r in reqs if r["blocked"])
        atks = len(ip_attacks.get(ip, []))
        paths = {r["path"] for r in reqs}
        agents = [r["user_agent"] or "" for r in reqs]
        hour = reqs[-1]["occurred_at"].hour if isinstance(reqs[-1]["occurred_at"], datetime) else datetime.fromisoformat(str(reqs[-1]["occurred_at"])).hour

        features[ip] = [
            total / ANALYSIS_WINDOW,
            atks / total,
            len(paths) / total,
            ua_entropy(agents),
            blocked / total,
            hour,
        ]
    return features


def notify_proxy(alert: AnomalyAlert):
    try:
        requests_mod = requests
        requests_mod.post(
            PROXY_URL,
            json={"anomaly_type": alert.anomaly_type, "severity": alert.severity},
            timeout=2,
        )
    except Exception:
        pass


def write_alert(conn, alert: AnomalyAlert):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO attack_log (client_ip, method, host, path, user_agent, rule_id, category, severity, action, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (alert.client_ip, "SIDECAR", "sidecar", "/", "sidecar",
             alert.anomaly_type, "BehavioralAnomaly", alert.severity, "monitor", alert.detail)
        )
        conn.commit()


def run_analysis():
    log.info("Running behavioural analysis cycle")
    try:
        conn = get_connection()
        reqs = fetch_window(conn)
        atks = fetch_attacks(conn)

        if not reqs:
            log.info("No request_stats in analysis window")
            conn.close()
            return

        log.info(f"Analysing {len(reqs)} requests, {len(atks)} attacks across {ANALYSIS_WINDOW}s window")

        feature_map = build_features(reqs, atks)
        if len(feature_map) < 2:
            log.info("Insufficient IPs for anomaly detection")
            conn.close()
            return

        ips = list(feature_map.keys())
        X = np.array([feature_map[ip] for ip in ips])

        clf = IsolationForest(contamination=0.1, random_state=42)
        preds = clf.fit_predict(X)

        alerts = []
        for i, ip in enumerate(ips):
            if preds[i] == -1:
                feats = feature_map[ip]
                attack_rate = feats[1]
                severity = "CRITICAL" if attack_rate > 0.3 else "HIGH"
                anomaly_type = "IP_CAMPAIGN" if attack_rate > 0.3 else "BEHAVIORAL_ANOMALY"
                alert = AnomalyAlert(
                    anomaly_type=anomaly_type,
                    severity=severity,
                    client_ip=ip,
                    detail=f"Isolation Forest anomaly: req_rate={feats[0]:.3f} attack_rate={feats[1]:.3f} path_diversity={feats[2]:.3f}",
                    evidence={
                        "request_rate": feats[0],
                        "attack_rate": feats[1],
                        "path_diversity": feats[2],
                        "ua_entropy": feats[3],
                        "blocked_ratio": feats[4],
                        "hour": feats[5],
                    }
                )
                alerts.append(alert)

        if not alerts:
            log.info("No anomalies detected")
        else:
            for alert in alerts:
                log.warning(f"ANOMALY [{alert.severity}] {alert.anomaly_type} — ip: {alert.client_ip}")
                write_alert(conn, alert)
                notify_proxy(alert)

        conn.close()

    except Exception as e:
        log.error(f"Analysis cycle failed: {e}")


def main():
    log.info("NetSentinel behavioural analyser starting")
    log.info(f"Window: {ANALYSIS_WINDOW}s | Interval: 60s | Min requests: {MIN_REQUESTS}")
    run_analysis()
    schedule.every(60).seconds.do(run_analysis)
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()