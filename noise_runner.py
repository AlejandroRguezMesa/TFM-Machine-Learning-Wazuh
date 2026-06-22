#!/usr/bin/env python3
"""
noise_runner.py — Genera ruido benigno continuo en todas las fuentes,
en paralelo a los escenarios de ataque. Replica la realidad: muchos
eventos rutinarios y pocos relevantes.

Cada fuente tiene una tasa Poisson (eventos/segundo) configurable.
Ajusta DEFAULT_RATES para acercarte al ratio señal/ruido del entorno real.

Uso:
  python3 noise_runner.py --duration 600     # 10 min de ruido
  python3 noise_runner.py --duration 0       # corre indefinidamente (Ctrl-C para parar)
"""
from __future__ import annotations
import argparse
import random
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generators import sink
from generators import palo_alto as pa
from generators import vcenter as vc
from generators import office365 as o365
from generators import sentinelone as s1


# eventos/segundo aproximados (rate Poisson — usar valores realistas)
DEFAULT_RATES = {
    "paloalto":              2.0,   # 2 eventos/s = ~7k/h, similar a perimeter
    "vcenter":               0.5,   # 0.5/s = ~1800/h
    "office365":             1.2,
    "sentinelone_activity":  0.1,   # solo logins consola de vez en cuando
    "sentinelone_device":    0.02,  # USB events son raros
}

# Plantillas de ruido por fuente. Cada una devuelve una línea de log
# benigna que no debe alertar (o que alerta a nivel bajo).
def _noise_dispatch():
    return {
        "paloalto": [pa.noise_traffic_allow],
        "vcenter":  [vc.noise_login, vc.noise_logout, vc.noise_task, vc.noise_alarm],
        "office365": [o365.noise_login_ok, o365.noise_mail_access],
        "sentinelone_activity": [s1.noise_console_login],
        "sentinelone_device":   [s1.noise_usb_eject],
    }


def _worker(source: str, rate: float, stop_event: threading.Event):
    fns = _noise_dispatch()[source]
    while not stop_event.is_set():
        # Poisson: inter-arrival ~ Exp(rate)
        wait = random.expovariate(rate) if rate > 0 else 60
        if stop_event.wait(timeout=wait):
            return
        fn = random.choice(fns)
        line = fn(datetime.now().astimezone())
        try:
            sink.write(source, line)
        except Exception as e:
            print(f"[noise:{source}][ERR] {e}", file=sys.stderr)


def run(duration: float, rates: dict[str, float]):
    stop = threading.Event()
    threads = []
    for src, r in rates.items():
        if r <= 0:
            continue
        t = threading.Thread(target=_worker, args=(src, r, stop), daemon=True)
        t.start()
        threads.append(t)
        print(f"[noise] {src}: {r} ev/s")

    try:
        if duration > 0:
            stop.wait(timeout=duration)
        else:
            while True:
                stop.wait(timeout=60)
                print(f"[noise] alive ({time.strftime('%H:%M:%S')})")
    except KeyboardInterrupt:
        print("\n[noise] stopping...")
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2)
    print("[noise] done")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=300,
                    help="segundos (0=infinito hasta Ctrl-C)")
    ap.add_argument("--pa-rate", type=float, default=DEFAULT_RATES["paloalto"])
    ap.add_argument("--vc-rate", type=float, default=DEFAULT_RATES["vcenter"])
    ap.add_argument("--o365-rate", type=float, default=DEFAULT_RATES["office365"])
    ap.add_argument("--s1act-rate", type=float, default=DEFAULT_RATES["sentinelone_activity"])
    ap.add_argument("--s1dev-rate", type=float, default=DEFAULT_RATES["sentinelone_device"])
    args = ap.parse_args()

    rates = {
        "paloalto":             args.pa_rate,
        "vcenter":              args.vc_rate,
        "office365":            args.o365_rate,
        "sentinelone_activity": args.s1act_rate,
        "sentinelone_device":   args.s1dev_rate,
    }
    run(args.duration, rates)
