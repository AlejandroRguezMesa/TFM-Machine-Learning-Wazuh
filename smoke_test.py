#!/usr/bin/env python3
"""
smoke_test.py — Emite UN evento por cada fuente para validar que la
cadena log → predecoder → decoder → regla genera alerta.

Pasos:
  1. Ejecutar: sudo python3 smoke_test.py
  2. En otra terminal: sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .
  3. Verificar que llegan 4-5 alertas (una por fuente)

Si no llega alguna, depurar con:
  sudo /var/ossec/bin/wazuh-logtest
"""
from __future__ import annotations
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generators import sink, palo_alto as pa, vcenter as vc, office365 as o365, sentinelone as s1


def main():
    now = datetime.now()
    cases = [
        # (source, descripción, función render)
        ("paloalto", "PA TRAFFIC drop  → regla 64508 (level 6)",
         pa.TrafficEvent(src_ip="172.24.0.15", dst_ip="192.168.12.100",
                         action="drop").render(now)),

        ("paloalto", "PA THREAT URL    → regla 64500+",
         pa.ThreatEvent(src_ip="10.253.13.43", dst_ip="18.197.147.66",
                        threat_subtype="url",
                        category="computer-and-internet-info").render(now)),

        ("vcenter", "vCenter login   → regla 140007",
         vc.LoginEvent(user="VSPHERE.LOCAL\\administrator",
                       src_ip="10.252.11.99").render(now)),

        ("vcenter", "vCenter task    → regla 140006",
         vc.TaskEvent(user="VSPHERE.LOCAL\\svc-vsc",
                      task_name="Recompute virtual disk digest").render(now)),

        ("office365", "O365 STS logon → regla 91545",
         o365.UserLoggedIn(user_id="smoketest@labcorp.com",
                           client_ip="212.64.161.47").render(now)),

        ("office365", "O365 MailAccess → regla 91578",
         o365.MailItemsAccessed(user_id="smoketest@labcorp.com").render(now)),

        ("office365", "O365 Phishing  → regla custom 91556",
         o365.PhishingDetected(recipient="smoketest@labcorp.com").render(now)),

        ("sentinelone_threats", "S1 active threat → regla 300601",
         s1.ActiveThreat(computer_name="SMOKE-TEST-01",
                         threat_name="mimikatz.exe",
                         mitigation_mode="detect").render(now)),

        ("sentinelone_device", "S1 USB inserted → regla 300651",
         s1.UsbActivity(computer_name="SMOKE-TEST-01",
                        event_type="Inserted").render(now)),

        ("sentinelone_activity", "S1 console login → regla 300612",
         s1.ConsoleLogin(user_email="smoke@labcorp.com").render(now)),
    ]
    for src, desc, line in cases:
        print(f"\n>>> {desc}")
        print(f"    → {sink.SOURCE_PATHS[src]}")
        print(f"    {line[:200]}{'...' if len(line) > 200 else ''}")
        sink.write(src, line)
        time.sleep(1)

    print("\nDone. Ahora revisa: sudo tail -n 100 /var/ossec/logs/alerts/alerts.json")


if __name__ == "__main__":
    main()
