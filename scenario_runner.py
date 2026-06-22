#!/usr/bin/env python3
"""
scenario_runner.py — ejecuta un escenario YAML y emite logs sintéticos
contra los ficheros monitorizados por Wazuh.

Genera ground truth en lab_state/ground_truth.jsonl:
  {incident_id, scenario, t_emit, source, type, vars}

Uso:
  python3 scenario_runner.py scenarios/s01_*.yaml
  python3 scenario_runner.py scenarios/s02_*.yaml --time-scale 0.1
  python3 scenario_runner.py scenarios/s03_*.yaml --dry-run
"""
from __future__ import annotations
import argparse
import json
import random
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

# repo root in path
sys.path.insert(0, str(Path(__file__).resolve().parent))


def _now_local_aware() -> datetime:
    """datetime con tz local (la del sistema). El resto del pipeline
    trabaja siempre con datetimes aware: comparaciones entre naive y
    aware no son seguras."""
    return datetime.now().astimezone()

from generators import sink
from generators import palo_alto as pa
from generators import vcenter as vc
from generators import office365 as o365
from generators import sentinelone as s1


GT_PATH = Path("lab_state/ground_truth.jsonl")
GT_PATH.parent.mkdir(parents=True, exist_ok=True)


# Mapeo (source, type) → función generador. Se llama con (ts, **vars).
DISPATCH = {
    ("paloalto", "traffic_drop"):
        lambda ts, **v: pa.TrafficEvent(
            src_ip=v["src_ip"], dst_ip=v["dst_ip"],
            src_port=v.get("src_port", random.randint(30000, 60000)),
            dst_port=v.get("dst_port", 53),
            action=v.get("action", "drop"),
            protocol=v.get("protocol", "udp"),
            rule_name=v.get("rule_name", "Drop default"),
        ).render(ts),
    ("paloalto", "traffic_allow"):
        lambda ts, **v: pa.TrafficEvent(
            src_ip=v["src_ip"], dst_ip=v["dst_ip"],
            src_port=v.get("src_port", random.randint(30000, 60000)),
            dst_port=v.get("dst_port", 443),
            action="allow",
            protocol=v.get("protocol", "tcp"),
            rule_name=v.get("rule_name", "allow-outbound-web"),
            application=v.get("application", "ssl"),
        ).render(ts),
    ("paloalto", "threat_event"):
        lambda ts, **v: pa.ThreatEvent(
            src_ip=v["src_ip"], dst_ip=v["dst_ip"],
            threat_subtype=v.get("threat_subtype", "url"),
            category=v.get("category", "computer-and-internet-info"),
            severity=v.get("severity", "informational"),
            url=v.get("url", "example.com/"),
            action=v.get("action", "alert"),
        ).render(ts),

    ("vcenter", "login"):
        lambda ts, **v: vc.LoginEvent(
            user=v.get("user", "VSPHERE.LOCAL\\administrator"),
            src_ip=v.get("src_ip", "10.252.11.47"),
        ).render(ts),
    ("vcenter", "logout"):
        lambda ts, **v: vc.LogoutEvent(
            user=v.get("user", "VSPHERE.LOCAL\\administrator"),
            src_ip=v.get("src_ip", "10.252.11.47"),
        ).render(ts),
    ("vcenter", "task"):
        lambda ts, **v: vc.TaskEvent(
            user=v.get("user", "VSPHERE.LOCAL\\svc-vsc"),
            task_name=v.get("task_name", "Recompute virtual disk digest"),
        ).render(ts),
    ("vcenter", "alarm"):
        lambda ts, **v: vc.AlarmEvent(
            alarm_name=v.get("alarm_name", "Virtual machine CPU usage"),
            host=v.get("host", "SRVGSA03"),
            from_state=v.get("from_state", "Green"),
            to_state=v.get("to_state", "Yellow"),
        ).render(ts),
    ("vcenter", "vmotion"):
        lambda ts, **v: vc.VmotionEvent(
            vm=v.get("vm", "LABCORP Workload"),
        ).render(ts),

    ("office365", "user_logged_in"):
        lambda ts, **v: o365.UserLoggedIn(
            user_id=v["user_id"],
            client_ip=v.get("client_ip", "212.64.161.47"),
            country=v.get("country", "ES"),
            risk_state=v.get("risk_state", "none"),
        ).render(ts),
    ("office365", "mail_items_accessed"):
        lambda ts, **v: o365.MailItemsAccessed(
            user_id=v["user_id"],
            client_ip=v.get("client_ip", "212.64.161.47"),
            access_type=v.get("access_type", "Sync"),
        ).render(ts),
    ("office365", "new_inbox_rule"):
        lambda ts, **v: o365.NewInboxRule(
            user_id=v["user_id"],
            client_ip=v.get("client_ip", "212.64.161.47"),
            rule_name=v.get("rule_name", "forward-external"),
            forward_to=v.get("forward_to", "attacker@evil.tld"),
        ).render(ts),
    ("office365", "add_mailbox_full_access"):
        lambda ts, **v: o365.AddMailboxPermission(
            user_id=v["user_id"],
            target_mailbox=v.get("target_mailbox", "ceo@labcorp.local"),
            permission="FullAccess",
        ).render(ts),
    ("office365", "phishing_detected"):
        lambda ts, **v: o365.PhishingDetected(
            recipient=v["recipient"],
            sender=v.get("sender", "spoofed@evil.tld"),
            subject=v.get("subject", "URGENT review needed"),
        ).render(ts),

    ("sentinelone_threats", "active_threat"):
        lambda ts, **v: s1.ActiveThreat(
            computer_name=v["computer_name"],
            threat_name=v.get("threat_name", "mimikatz.exe"),
            file_path=v.get("file_path", "C:\\Users\\Public\\mal.exe"),
            mitigation_mode=v.get("mitigation_mode", "detect"),
            classification=v.get("classification", "Malware"),
        ).render(ts),
    ("sentinelone_threats", "mitigated_threat"):
        lambda ts, **v: s1.MitigatedThreat(
            computer_name=v["computer_name"],
            threat_name=v.get("threat_name", "trojan.gen"),
        ).render(ts),
    ("sentinelone_device", "usb_inserted"):
        lambda ts, **v: s1.UsbActivity(
            computer_name=v["computer_name"],
            device_name=v.get("device_name", "Generic USB"),
            event_type=v.get("event_type", "Inserted"),
        ).render(ts),
    ("sentinelone_activity", "console_login"):
        lambda ts, **v: s1.ConsoleLogin(
            user_email=v.get("user_email", "analyst@labcorp.local"),
            primary_description=v.get(
                "primary_description",
                f"The management user logged in to console."
            ),
        ).render(ts),
}


def _resolve_vars(vars_dict: dict, entities: dict) -> dict:
    """Resuelve {{ entity }} y {{ randint(a,b) }} dentro de los vars."""
    out = {}
    pat_entity = re.compile(r"\{\{\s*(\w+)\s*\}\}")
    pat_randint = re.compile(r"\{\{\s*randint\((\d+)\s*,\s*(\d+)\)\s*\}\}")
    for k, v in vars_dict.items():
        if isinstance(v, str):
            # randint
            def _ri(m):
                return str(random.randint(int(m.group(1)), int(m.group(2))))
            v = pat_randint.sub(_ri, v)
            # entidades
            v = pat_entity.sub(lambda m: str(entities.get(m.group(1), m.group(0))), v)
        out[k] = v
    return out


def run(path: Path, time_scale: float, dry_run: bool, jitter: float = 0.2) -> None:
    sc = yaml.safe_load(path.read_text())
    run_id = uuid.uuid4().hex[:8]
    incident_id = f"{sc['incident_id']}-{run_id}"
    is_benign = bool(sc.get("is_benign", False))
    entities = sc.get("entities", {})

    print(f"[runner] incident={incident_id}  scenario='{sc['name']}'  benign={is_benign}")
    t0 = time.time()

    for ev in sc["events"]:
        repeat = ev.get("repeat", 1)
        interval = ev.get("repeat_interval", 1) * time_scale
        for i in range(repeat):
            target_t = t0 + (ev["t_offset"] + i * ev.get("repeat_interval", 1)) * time_scale
            target_t += random.uniform(-jitter, jitter) * time_scale
            sleep_s = max(0, target_t - time.time())
            if sleep_s > 0:
                time.sleep(sleep_s)

            now = _now_local_aware()
            resolved = _resolve_vars(ev.get("vars", {}), entities)

            key = (ev["source"], ev["type"])
            if key not in DISPATCH:
                # no abortamos: el resto de eventos del escenario debe
                # seguir emitiendose para no truncar el GT a medias.
                print(f"[runner][ERR] sin generador para {key} "
                      f"(yaml={path.name}, evento idx={sc['events'].index(ev)}); "
                      "saltando")
                continue
            try:
                line = DISPATCH[key](now, **resolved)
            except Exception as e:
                tb = traceback.format_exc(limit=2).strip().splitlines()[-1]
                print(f"[runner][ERR] {key} {type(e).__name__}: {e}\n"
                      f"             vars={resolved}\n"
                      f"             {tb}")
                continue

            if dry_run:
                print(f"  {ev['source']:<22} {line[:140]}{'...' if len(line) > 140 else ''}")
            else:
                sink.write(ev["source"], line)

            # ground truth — guardamos t_emit en UTC ISO con TZ explícito
            t_emit_utc = now.astimezone(timezone.utc).isoformat()
            with open(GT_PATH, "a") as gt:
                gt.write(json.dumps({
                    "incident_id": incident_id,
                    "scenario": sc["name"],
                    "is_benign": is_benign,
                    "t_emit": t_emit_utc,
                    "source": ev["source"],
                    "type": ev["type"],
                    "entities": entities,
                    "vars": resolved,
                }, default=str) + "\n")

    print(f"[runner] done. ground_truth → {GT_PATH}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", type=Path)
    ap.add_argument("--time-scale", type=float, default=1.0,
                    help="0.1 = 10x más rápido; 1.0 = tiempo real")
    ap.add_argument("--dry-run", action="store_true",
                    help="muestra logs por stdout sin escribir a disco")
    args = ap.parse_args()
    run(args.scenario, args.time_scale, args.dry_run)
