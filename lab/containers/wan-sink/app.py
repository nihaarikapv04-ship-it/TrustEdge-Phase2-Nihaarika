"""
cloudapi/app.py — TrustEdge Cloud Telemetry API

Stores per-device telemetry windows and quarantine alerts in SQLite.
Runs at 172.21.0.11:80 on the WAN network.

Endpoints
─────────
POST /telemetry         Ingest a telemetry snapshot from the firewall
POST /alert             Ingest a quarantine alert
GET  /history           Last N telemetry rows (?device=ip&n=500)
GET  /summary           Per-device aggregated stats (last 24 h)
GET  /alerts            Last N alerts (?device=ip&n=100)
GET  /ping              Health check
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

DB_PATH  = "/data/telemetry.db"
_db_lock = threading.Lock()

os.makedirs("/data", exist_ok=True)


# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────

def _get_db():
    """Return a thread-local SQLite connection (WAL mode for concurrency)."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    with _db_lock, _get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                device    TEXT    NOT NULL,
                trust     REAL,
                anomaly   REAL,
                tier      TEXT,
                ae_suppressed INTEGER,
                packets   INTEGER,
                raw       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tel_device ON telemetry(device);
            CREATE INDEX IF NOT EXISTS idx_tel_ts     ON telemetry(ts);

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT    NOT NULL,
                device       TEXT    NOT NULL,
                name         TEXT,
                old_tier     TEXT,
                new_tier     TEXT,
                trust_score  REAL,
                anomaly_score REAL,
                raw          TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alert_device ON alerts(device);
        """)


_init_db()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _ok(data=None, msg="ok", code=200):
    body = {"status": "ok", "message": msg}
    if data is not None:
        body["data"] = data
    return jsonify(body), code


def _err(msg, code=400):
    return jsonify({"status": "error", "message": msg}), code


# ─────────────────────────────────────────────
# INGEST ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/telemetry", methods=["POST"])
def ingest_telemetry():
    data = request.get_json(silent=True) or {}
    device = data.get("device", "").strip()
    if not device:
        return _err("'device' field required")

    ts = data.get("ts") or datetime.now(timezone.utc).isoformat()
    with _db_lock, _get_db() as conn:
        conn.execute(
            """INSERT INTO telemetry
               (ts, device, trust, anomaly, tier, ae_suppressed, packets, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts,
                device,
                data.get("trust"),
                data.get("anomaly"),
                data.get("tier"),
                int(bool(data.get("ae_suppressed", False))),
                data.get("packets"),
                json.dumps(data),
            ),
        )
        # Rolling retention: keep last 50 000 rows per device
        conn.execute(
            """DELETE FROM telemetry WHERE device = ? AND id NOT IN (
                SELECT id FROM telemetry WHERE device = ?
                ORDER BY id DESC LIMIT 50000)""",
            (device, device),
        )
    return _ok(msg="telemetry stored")


@app.route("/alert", methods=["POST"])
def ingest_alert():
    data = request.get_json(silent=True) or {}
    device = data.get("device", "").strip()
    if not device:
        return _err("'device' field required")

    ts = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with _db_lock, _get_db() as conn:
        conn.execute(
            """INSERT INTO alerts
               (ts, device, name, old_tier, new_tier, trust_score, anomaly_score, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts,
                device,
                data.get("name"),
                data.get("old_tier"),
                data.get("new_tier"),
                data.get("trust_score"),
                data.get("anomaly_score"),
                json.dumps(data),
            ),
        )
    return _ok(msg="alert stored")


# ─────────────────────────────────────────────
# QUERY ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/history", methods=["GET"])
def history():
    device = request.args.get("device")
    n = min(int(request.args.get("n", 500)), 5000)
    with _db_lock, _get_db() as conn:
        if device:
            rows = conn.execute(
                "SELECT * FROM telemetry WHERE device=? ORDER BY id DESC LIMIT ?",
                (device, n),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM telemetry ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
    return _ok([dict(r) for r in rows])


@app.route("/summary", methods=["GET"])
def summary():
    """Per-device aggregated stats over the last 24 hours."""
    cutoff = datetime.now(timezone.utc).replace(microsecond=0).isoformat()[:10]  # YYYY-MM-DD
    with _db_lock, _get_db() as conn:
        rows = conn.execute(
            """SELECT
                device,
                COUNT(*)            AS windows,
                ROUND(AVG(trust),4) AS avg_trust,
                ROUND(MIN(trust),4) AS min_trust,
                ROUND(AVG(anomaly),4) AS avg_anomaly,
                ROUND(MAX(anomaly),4) AS max_anomaly,
                SUM(ae_suppressed)  AS ae_suppressed,
                SUM(packets)        AS total_packets
               FROM telemetry
               WHERE ts >= ?
               GROUP BY device""",
            (cutoff + "T00:00:00",),
        ).fetchall()
    return _ok([dict(r) for r in rows])


@app.route("/alerts", methods=["GET"])
def get_alerts():
    device = request.args.get("device")
    n = min(int(request.args.get("n", 100)), 1000)
    with _db_lock, _get_db() as conn:
        if device:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE device=? ORDER BY id DESC LIMIT ?",
                (device, n),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
    return _ok([dict(r) for r in rows])


# ─────────────────────────────────────────────
# LEGACY / HEALTH
# ─────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload():
    size = len(request.data)
    return _ok({"bytes_received": size})


@app.route("/ping", methods=["GET"])
def ping():
    return _ok(msg="cloudapi alive")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
