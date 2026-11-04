#!/usr/bin/env python3
"""Live Docker three-window ordinary ML downgrade validation.

Uses the real capture pipeline (phone → firewall → IF/AE → EWMA → nft).
Scores and trust are read from the Gateway API after each window — not fabricated.

Run from the host with lab containers up:
  python3 -u lab/scripts/live_three_window_validate.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any

# Guest phone IF scores ≥0.89 on ordinary HTTP (synthetic pa200) without hard rules.
DEVICE = 'trustedge-lab-phone'
FIREWALL = 'trustedge-lab-firewall'
IP = '172.20.0.13'
SINK = '172.21.0.11'
WEB = '172.21.0.10'
ANOMALY_THRESHOLD = 0.70


def sh(*args: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def fw_py(code: str, timeout: float = 60) -> str:
    result = sh('docker', 'exec', FIREWALL, 'python3', '-c', code, timeout=timeout)
    return result.stdout.strip()


def device_py(code: str, timeout: float = 120) -> str:
    result = sh('docker', 'exec', DEVICE, 'python3', '-c', code, timeout=timeout)
    return result.stdout.strip()


def stop_background_traffic() -> None:
    sh('docker', 'exec', DEVICE, 'sh', '-c',
       'touch /tmp/trustedge_pause; '
       'for p in /proc/[0-9]*; do '
       '  cmd=$(tr "\\0" " " < "$p/cmdline" 2>/dev/null || true); '
       '  case "$cmd" in *curl*|*payload*) kill "${p#/proc/}" 2>/dev/null || true;; esac; '
       'done',
       check=False, timeout=20)


def resume_background_traffic() -> None:
    sh('docker', 'exec', DEVICE, 'rm', '-f', '/tmp/trustedge_pause', check=False, timeout=20)


def device_snapshot() -> dict[str, Any]:
    out = fw_py(
        'import json,os,urllib.request\n'
        't=os.environ["TRUSTEDGE_API_TOKEN"]\n'
        'd=json.load(urllib.request.urlopen(urllib.request.Request('
        '"http://127.0.0.1:8080/status",'
        'headers={"Authorization":"Bearer "+t}),timeout=5))\n'
        f'dev=[x for x in d["devices"] if x["ip"]=="{IP}"][0]\n'
        'keep=("ip","name","trust","desired_tier","applied_tier","learning",'
        '"anomaly_streak","normal_streak","model_info")\n'
        'print(json.dumps({k:dev.get(k) for k in keep}))\n'
    )
    return json.loads(out)


def history(limit: int = 8) -> list[dict[str, Any]]:
    """Fetch windows via Gateway HTTP API (avoids contending on SQLite)."""
    out = fw_py(
        'import json,os,urllib.request\n'
        't=os.environ["TRUSTEDGE_API_TOKEN"]\n'
        f'url="http://127.0.0.1:8080/devices/{IP}/history?limit={limit}"\n'
        'rows=json.load(urllib.request.urlopen(urllib.request.Request('
        'url,headers={"Authorization":"Bearer "+t}),timeout=10))\n'
        'print(json.dumps(list(reversed(rows))))\n',
        timeout=30,
    )
    return json.loads(out)


def enrich_scores(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute IF score + AE recon error from persisted features + model blob."""
    payload = json.dumps([{
        'id': w.get('id'),
        'features': w.get('features'),
        'hard': w.get('hard'),
    } for w in windows])
    out = fw_py(
        'import json,pickle,sqlite3,numpy as np\n'
        'from trustedge.detection import isolation_score\n'
        f'items=json.loads({payload!r})\n'
        'db=sqlite3.connect("file:/var/lib/trustedge/lab.sqlite?mode=ro", uri=True, timeout=5)\n'
        'db.execute("PRAGMA busy_timeout=5000")\n'
        f'row=db.execute("SELECT payload FROM models WHERE ip=?", ("{IP}",)).fetchone()\n'
        'bundle=pickle.loads(row[0]) if row else None\n'
        'out={}\n'
        'for it in items:\n'
        '  iso=None; err=None; thr=None\n'
        '  feats=it.get("features")\n'
        '  if bundle is not None and feats is not None and not it.get("hard"):\n'
        '    iso=float(isolation_score(bundle, feats))\n'
        '    if "ae_model" in bundle:\n'
        '      X=np.asarray(feats, dtype=float).reshape(1,-1)\n'
        '      scaled=bundle["ae_scaler"].transform(X)\n'
        '      err=float(np.mean((scaled-bundle["ae_model"].predict(scaled))**2))\n'
        '      thr=float(bundle["calibration"]["ae_threshold"])\n'
        '  out[str(it["id"])]=dict(if_score=iso, ae_recon_error=err, ae_threshold=thr)\n'
        'print(json.dumps(out))\n'
        'db.close()\n',
        timeout=30,
    )
    scores = json.loads(out)
    for w in windows:
        extra = scores.get(str(w.get('id')), {})
        w.update(extra)
    return windows


def nft_enforcement(ip: str) -> str:
    out = fw_py(
        'import subprocess\n'
        'text=subprocess.check_output(["nft","list","table","inet","trustedge"],text=True)\n'
        f'lines=[ln.strip() for ln in text.splitlines() if "{ip}" in ln]\n'
        'print(" | ".join(lines[:6]) if lines else "no-ip-rules")\n'
    )
    return out


def start_continuous_anomaly(seconds: int = 22) -> None:
    """Keep every capture window ordinary-anomalous so the streak does not reset.

    High-rate HTTP GETs/POSTs to enrolled sinks (complete handshakes, not hard rules).
    """
    code = (
        'import http.client,time\n'
        f'web="{WEB}"\n'
        f'deadline=time.time()+{seconds}\n'
        'n=0\n'
        '# One persistent connection, moderate request rate (≪5000 pkts/window).\n'
        'c=http.client.HTTPConnection(web,timeout=2)\n'
        'while time.time() < deadline:\n'
        '  for _ in range(35):\n'
        '    try:\n'
        '      c.request("GET", "/")\n'
        '      c.getresponse().read()\n'
        '      n+=1\n'
        '    except Exception:\n'
        '      try: c.close()\n'
        '      except Exception: pass\n'
        '      c=http.client.HTTPConnection(web,timeout=2)\n'
        '  time.sleep(0.55)\n'
        'try: c.close()\n'
        'except Exception: pass\n'
        'print("continuous_done", n)\n'
    )
    print(f'  starting continuous ordinary anomaly for {seconds}s...', flush=True)
    sh('docker', 'exec', '-d', DEVICE, 'python3', '-c', code, check=True, timeout=20)


def hard_rule_burst() -> None:
    # PORT_SCAN: entropy>3.5 with <5000 packets (avoid VOLUME_ANOMALY stealing the label).
    code = (
        'import socket,time\n'
        f'sink="{SINK}"\n'
        's=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n'
        'n=0\n'
        'for port in range(20000, 20064):\n'  # 64 ports → entropy=6
        '  for _ in range(8):\n'
        '    try: s.sendto(b"p", (sink, port)); n+=1\n'
        '    except Exception: pass\n'
        '  time.sleep(0.01)\n'
        's.close()\n'
        'print("hard_burst_done", n)\n'
    )
    print('  hard-rule PORT_SCAN burst (64 ports)...', flush=True)
    print(' ', device_py(code, timeout=30), flush=True)


def wait_new_windows(after_id: int, timeout: float = 20.0) -> list[dict[str, Any]]:
    """Return every new window after after_id (oldest first). Do not skip intermediates."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = history(12)
        newer = [w for w in rows if int(w['id']) > after_id]
        if newer:
            return enrich_scores(newer)
        time.sleep(0.25)
    raise TimeoutError(f'no window after id={after_id}')


def wait_new_window(after_id: int, timeout: float = 20.0) -> dict[str, Any]:
    return wait_new_windows(after_id, timeout)[0]


def release_quarantine() -> None:
    fw_py(
        'import json,os,urllib.request\n'
        't=os.environ["TRUSTEDGE_API_TOKEN"]\n'
        'body=json.dumps({"reason":"live three-window validation reset"}).encode()\n'
        'req=urllib.request.Request("http://127.0.0.1:8080/devices/'
        + IP + '/release",data=body,method="POST",'
        'headers={"Authorization":"Bearer "+t,"Content-Type":"application/json"})\n'
        'print(urllib.request.urlopen(req,timeout=10).read().decode())\n'
    )


def main() -> int:
    print('=== Live Docker three-window validation ===', flush=True)
    snap = device_snapshot()
    print('before:', snap['ip'], snap['desired_tier'], round(float(snap['trust']), 4),
          'learning', snap['learning'], flush=True)
    if snap['learning'] or not (snap.get('model_info') or {}).get('autoencoder'):
        print('FAIL: phone must be trained (IF+AE)', file=sys.stderr)
        return 2

    if snap['desired_tier'] == 'QUARANTINE':
        print('releasing quarantine...', flush=True)
        release_quarantine()
        resume_background_traffic()
        time.sleep(2)
        snap = device_snapshot()

    # Need TRUSTED. Trust ≥0.75 keeps the first ordinary anomalies from jumping
    # tiers before the three-window streak completes (EWMA still drops trust).
    resume_background_traffic()
    for _ in range(80):
        snap = device_snapshot()
        if snap['desired_tier'] == 'TRUSTED' and float(snap['trust']) >= 0.75:
            break
        print(f'  recovering TRUSTED: {snap["desired_tier"]} '
              f'trust={snap["trust"]} nstreak={snap.get("normal_streak")}', flush=True)
        time.sleep(5)
    snap = device_snapshot()
    if snap['desired_tier'] != 'TRUSTED' or float(snap['trust']) < 0.75:
        print('FAIL: could not reach TRUSTED with trust>=0.75', snap, file=sys.stderr)
        return 2
    print('ready:', snap['desired_tier'], round(float(snap['trust']), 4), flush=True)

    print('stopping background phone traffic...', flush=True)
    stop_background_traffic()
    time.sleep(8)  # drain partial windows; empty windows are not persisted
    rows = history(1)
    anchor = int(rows[-1]['id']) if rows else 0
    print('anchor window id', anchor, flush=True)

    results: list[tuple] = []
    # Snapshot tier/trust BEFORE traffic so we can attach per-window device state
    # from history fields (desired_tier/trust recorded on the window itself).
    start_continuous_anomaly(22)
    last_id = anchor
    consecutive: list[tuple] = []
    deadline = time.time() + 40
    seen = 0
    while time.time() < deadline and len(consecutive) < 3:
        try:
            batch = wait_new_windows(last_id, timeout=10)
        except TimeoutError:
            continue
        for w in batch:
            last_id = int(w['id'])
            # Prefer tier/trust persisted on the window (state at close time).
            d = {
                'ip': IP,
                'trust': w.get('trust'),
                'desired_tier': w.get('desired_tier'),
                'applied_tier': w.get('applied_tier'),
                'anomaly_streak': None,
                'normal_streak': None,
            }
            # Refresh live streak counters from status (best-effort).
            live = device_snapshot()
            d['anomaly_streak'] = live.get('anomaly_streak')
            d['normal_streak'] = live.get('normal_streak')
            enf = nft_enforcement(IP)
            seen += 1
            label = f'win{seen}'
            results.append((label, w, d, enf))
            print(
                f'  {label}: score={w.get("score")} hard={w.get("hard")} '
                f'if={w.get("if_score")} ae_err={w.get("ae_recon_error")} '
                f'trust={d["trust"]} tier={d["desired_tier"]} '
                f'live_streak={d.get("anomaly_streak")} pkts={w.get("packets")}',
                flush=True,
            )
            if w.get('hard'):
                print('FAIL: hard rule during ordinary three-window phase', file=sys.stderr)
                resume_background_traffic()
                _emit_table(results)
                return 3
            if (w.get('score') or 0) >= ANOMALY_THRESHOLD and not w.get('ae_suppressed'):
                consecutive.append(results[-1])
            else:
                consecutive = []
            if len(consecutive) >= 3:
                break

    time.sleep(1)
    d_after = device_snapshot()
    high = consecutive[:3]
    print('after ordinary phase:', d_after['desired_tier'], d_after['trust'],
          'consecutive_highs', len(high),
          'tiers', [h[2]['desired_tier'] for h in high], flush=True)

    hard_anchor = int(history(1)[-1]['id'])
    hard_rule_burst()
    hard_w = wait_new_window(hard_anchor, timeout=20)
    d_hard = device_snapshot()
    results.append(('hard', hard_w, d_hard, nft_enforcement(IP)))
    print('hard-rule:', hard_w.get('hard'), hard_w.get('reason'),
          'trust', d_hard['trust'], 'tier', d_hard['desired_tier'], flush=True)

    print('clean traffic while quarantined (must not auto-release)...', flush=True)
    resume_background_traffic()
    time.sleep(15)
    d_clean = device_snapshot()
    results.append(('post_clean', enrich_scores(history(1))[-1], d_clean, nft_enforcement(IP)))

    _emit_table(results)

    ok_three = len(high) >= 3 and all(
        (r[1].get('score') or 0) >= ANOMALY_THRESHOLD and not r[1].get('hard') for r in high
    )
    early_ok = len(high) >= 2 and all(
        r[2]['desired_tier'] != 'QUARANTINE' for r in high[:2]
    )
    # Phase 2 one-tier correction: windows 1–2 remain TRUSTED; window 3 → CAUTIOUS.
    if len(high) >= 3:
        t0, t1, t2 = (high[0][2]['desired_tier'], high[1][2]['desired_tier'],
                      high[2][2]['desired_tier'])
        downgrade_ok = t0 == 'TRUSTED' and t1 == 'TRUSTED' and t2 == 'CAUTIOUS'
    else:
        downgrade_ok = False

    hard_ok = (
        bool(hard_w.get('hard'))
        and d_hard['desired_tier'] == 'QUARANTINE'
        and abs(float(d_hard['trust']) - 0.1) < 1e-9
    )
    no_auto = d_clean['desired_tier'] == 'QUARANTINE'

    print('\nASSERTIONS:', flush=True)
    print('  >=3 ordinary anomalous windows:', ok_three, f'({len(high)})', flush=True)
    print('  first two highs not QUARANTINE:', early_ok, flush=True)
    print('  three-window → CAUTIOUS (not early):', downgrade_ok,
          [r[2]['desired_tier'] for r in high[:3]], flush=True)
    print('  hard-rule → QUARANTINE trust 0.1:', hard_ok, flush=True)
    print('  clean windows do not auto-release:', no_auto, flush=True)

    if ok_three and early_ok and downgrade_ok and hard_ok and no_auto:
        print('PASS', flush=True)
        return 0
    print('FAIL', flush=True)
    return 1


def _emit_table(results: list) -> None:
    print('\nLIVE_THREE_WINDOW_TABLE', flush=True)
    print('| Window | Packets | Features | IF score | AE recon err | Combined | Trust | Tier | Enforcement |',
          flush=True)
    print('|---|---|---|---|---|---|---|---|---|', flush=True)
    for label, w, d, enf in results:
        feats = w.get('features') or []
        feat_s = ''
        if feats:
            feat_s = f'pkts={feats[0]:.0f},syn={feats[6]:.0f},tcp={feats[9]:.2f},ent={feats[13]:.2f}'
        combined = ('HARD ' + str(w.get('reason'))) if w.get('hard') else (
            f"score={w.get('score')} ae_sup={w.get('ae_suppressed')}"
        )
        print(
            f"| {label}#{w.get('id')} | {w.get('packets')} | {feat_s} | "
            f"{w.get('if_score')} | {w.get('ae_recon_error')} | {combined} | "
            f"{d.get('trust')} | {d.get('desired_tier')}/{d.get('applied_tier')} | {enf[:90]} |",
            flush=True,
        )
    out_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), '..', 'results', 'live_three_window_latest.json'))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    serializable = []
    for label, w, d, enf in results:
        serializable.append({
            'label': label,
            'window': {k: w.get(k) for k in (
                'id', 'timestamp', 'packets', 'bytes', 'features', 'score', 'hard',
                'reason', 'ae_suppressed', 'trust', 'desired_tier', 'applied_tier',
                'if_score', 'ae_recon_error', 'ae_threshold')},
            'device': {k: d.get(k) for k in (
                'ip', 'trust', 'desired_tier', 'applied_tier', 'anomaly_streak',
                'normal_streak')},
            'enforcement': enf,
        })
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(serializable, fh, indent=2)
    print('wrote', out_path, flush=True)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(exc.stdout or '', flush=True)
        print(exc.stderr or '', file=sys.stderr, flush=True)
        raise
    except subprocess.TimeoutExpired as exc:
        print('TIMEOUT', exc, file=sys.stderr, flush=True)
        resume_background_traffic()
        raise SystemExit(4)
