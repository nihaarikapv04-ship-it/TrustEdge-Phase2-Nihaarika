#!/usr/bin/env python3
"""Wait until a lab device has finished baseline+AE and is TRUSTED with high trust."""
import json
import subprocess
import sys
import time

IP = sys.argv[1] if len(sys.argv) > 1 else '172.20.0.12'


def snap():
    code = f'''
import json,os,urllib.request
t=os.environ["TRUSTEDGE_API_TOKEN"]
d=json.load(urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8080/status",
    headers={{"Authorization":"Bearer "+t}}),timeout=5))
dev=[x for x in d["devices"] if x["ip"]=="{IP}"][0]
print(json.dumps({{
  "desired_tier": dev.get("desired_tier"),
  "trust": dev.get("trust"),
  "learning": dev.get("learning"),
  "anomaly_streak": dev.get("anomaly_streak"),
  "normal_streak": dev.get("normal_streak"),
  "model_info": dev.get("model_info"),
  "baseline": len(dev.get("baseline") or []),
}}))
'''
    out = subprocess.check_output(
        ['docker', 'exec', 'trustedge-lab-firewall', 'python3', '-c', code],
        text=True,
    )
    return json.loads(out)


def main() -> int:
    for i in range(150):
        s = snap()
        mi = s.get('model_info') or {}
        print(
            f'{i}: learn={s["learning"]} base={s["baseline"]} tier={s["desired_tier"]} '
            f'trust={round(float(s["trust"]),4)} ae={mi.get("autoencoder")} '
            f'nstreak={s.get("normal_streak")}',
            flush=True,
        )
        if (
            not s['learning']
            and mi.get('autoencoder')
            and s['desired_tier'] == 'TRUSTED'
            and float(s['trust']) >= 0.95
        ):
            print('READY', flush=True)
            return 0
        time.sleep(5)
    print('TIMEOUT', flush=True)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
