#!/usr/bin/env python3
"""
inject_real_alerts.py — Inyecta alertas reales del fichero al Indexer del lab.

Usa el fichero alerts_filtrado.json (formato Wazuh) como fondo realista y
mete una muestra de N alertas, **reasignando timestamps** a una ventana
reciente para que aparezcan junto a los escenarios sintéticos en el
mismo timeline.

Estrategia de muestreo:
  - Mantiene representatividad por (decoder, rule.id):
    si la regla 64508 era el 80% del dataset original, será el 80% de
    la muestra.
  - Filtro opcional para descartar reglas específicas (las del ruido
    masivo que silenciaste).
  - Reasigna timestamps lineal o aleatoriamente dentro de la ventana.

Uso típico:
  # muestreo 20k alertas, distribuirlas en últimos 60 min, excluir 64508
  python3 inject_real_alerts.py /ruta/alerts_filtrado.json \\
      --n 20000 --duration-min 60 --exclude-rule 64508

  # primero hacer dry-run para ver qué entraría
  python3 inject_real_alerts.py /ruta/alerts_filtrado.json --n 1000 --dry-run

Requisitos: el usuario tfm_analyst necesita permiso de escritura en
wazuh-alerts-* del lab. Si no lo tiene, configura tfm_correlation_role
con write en wazuh-alerts-* (solo en lab, NUNCA en producción).
"""
from __future__ import annotations
import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from indexer_client import get_client


def _parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="ruta al alerts_filtrado.json o similar")
    ap.add_argument("--n", type=int, default=20000,
                    help="número de alertas a inyectar (default 20000)")
    ap.add_argument("--duration-min", type=int, default=60,
                    help="ventana temporal donde distribuir las alertas (default 60 min)")
    ap.add_argument("--start-offset-min", type=int, default=-60,
                    help="cuándo empieza la ventana respecto a 'ahora' "
                         "(default -60 = empieza hace 60 min)")
    ap.add_argument("--exclude-rule", action="append", default=[],
                    help="rule.id a excluir (puede repetirse)")
    ap.add_argument("--exclude-decoder", action="append", default=[],
                    help="decoder.name a excluir (puede repetirse)")
    ap.add_argument("--min-level", type=int, default=0,
                    help="descartar alertas con rule.level < N")
    ap.add_argument("--target-index", default=None,
                    help="índice destino (default: wazuh-alerts-4.x-<HOY>)")
    ap.add_argument("--agent-name", default="lab-replay",
                    help="agent.name para las alertas inyectadas (default lab-replay)")
    ap.add_argument("--agent-id", default="900",
                    help="agent.id para las alertas inyectadas (default 900)")
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--dry-run", action="store_true",
                    help="no escribe al Indexer, solo muestra distribución")
    return ap.parse_args()


def sample_stratified(path: Path, n: int, excl_rules: set, excl_decoders: set,
                      min_level: int):
    """Hace 2 pasadas:
      1. Cuenta alertas por (decoder, rule.id) → distribución original
      2. Recorre de nuevo seleccionando con probabilidad p_i para mantener
         la distribución pero topando al n total.
    """
    print("Pasada 1/2: contando distribución original...")
    counts: Counter = Counter()
    n_total = 0
    n_kept = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            n_total += 1
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = str(a.get("rule", {}).get("id", "?"))
            dec = (a.get("decoder", {}) or {}).get("name", "?")
            lvl = a.get("rule", {}).get("level", 0)
            if rid in excl_rules: continue
            if dec in excl_decoders: continue
            if lvl < min_level: continue
            counts[(dec, rid)] += 1
            n_kept += 1
    print(f"  Total leídas:    {n_total:,}")
    print(f"  Tras filtros:    {n_kept:,}")
    print(f"  Combinaciones (decoder, rule.id): {len(counts)}")
    if n_kept == 0:
        raise SystemExit("Filtros demasiado estrictos, nada que samplear.")

    # Probabilidad de muestreo: si quiero n de n_kept → p = n / n_kept
    p = min(1.0, n / n_kept)
    print(f"  Probabilidad de muestreo: {p:.4f}")

    # Reservoir alternativo: muestreo estratificado por (decoder, rule.id)
    # tal que la distribución se preserve.
    print("\nPasada 2/2: muestreando...")
    random.seed(42)
    sample = []
    seen = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = str(a.get("rule", {}).get("id", "?"))
            dec = (a.get("decoder", {}) or {}).get("name", "?")
            lvl = a.get("rule", {}).get("level", 0)
            if rid in excl_rules: continue
            if dec in excl_decoders: continue
            if lvl < min_level: continue
            seen += 1
            if random.random() < p:
                sample.append(a)
            if len(sample) >= n * 1.1:  # margen del 10% por si quedamos cortos
                break
    sample = sample[:n]
    print(f"  Muestreadas: {len(sample):,}")

    # Reportar distribución muestreada
    sample_counts = Counter()
    for a in sample:
        rid = str(a.get("rule", {}).get("id", "?"))
        dec = (a.get("decoder", {}) or {}).get("name", "?")
        sample_counts[(dec, rid)] += 1
    print("\n  Top 10 (decoder, rule.id) en la muestra:")
    for (dec, rid), c in sample_counts.most_common(10):
        orig = counts[(dec, rid)]
        orig_pct = orig / n_kept * 100
        sample_pct = c / len(sample) * 100
        print(f"    {dec:<14} {rid:<6}  muestra={c:>5} ({sample_pct:.1f}%)  "
              f"orig={orig:>9,} ({orig_pct:.1f}%)")

    return sample


def reassign_timestamps(sample: list, window_start: datetime, duration_s: int):
    """Reasigna timestamps preservando el ORDEN relativo original.
    Cada alerta queda en una posición proporcional a su orden de aparición."""
    n = len(sample)
    if n == 0:
        return sample
    # Ordenar por timestamp original
    for a in sample:
        try:
            a["_orig_ts"] = a.get("timestamp", "")
        except Exception:
            a["_orig_ts"] = ""
    sample.sort(key=lambda x: x["_orig_ts"])
    for i, a in enumerate(sample):
        offset = duration_s * i / max(1, n - 1)
        new_ts = window_start + timedelta(seconds=offset)
        ts_str = new_ts.strftime("%Y-%m-%dT%H:%M:%S.") + \
                 f"{new_ts.microsecond // 1000:03d}+0000"
        a["timestamp"] = ts_str
        a["@timestamp"] = ts_str
        a.pop("_orig_ts", None)
    return sample


def adapt_for_lab(sample: list, agent_id: str, agent_name: str):
    """Reescribe agent.id / agent.name y añade marca 'tfm_replay': true."""
    for a in sample:
        a["agent"] = {"id": agent_id, "name": agent_name}
        a["tfm_replay"] = True
        # nuevo ID interno único para que no choque con el original
        a["id"] = f"replay-{random.randint(10**12, 10**13)}"
    return sample


def push_to_indexer(client, sample: list, index: str, batch_size: int):
    """Bulk index al Indexer del lab usando la API _bulk."""
    n = len(sample)
    print(f"\nIndexando {n:,} documentos a {index} (batch {batch_size})...")
    n_ok = 0
    n_fail = 0
    for i in range(0, n, batch_size):
        batch = sample[i:i + batch_size]
        body = []
        for doc in batch:
            body.append({"index": {"_index": index}})
            body.append(doc)
        try:
            res = client.bulk(body=body, refresh=False)
            for item in res.get("items", []):
                if item.get("index", {}).get("status", 0) < 300:
                    n_ok += 1
                else:
                    n_fail += 1
                    if n_fail <= 3:
                        print(f"  [!] fail: {item['index'].get('error', '?')}",
                              file=sys.stderr)
        except Exception as e:
            n_fail += len(batch)
            print(f"  [!] bulk error: {e}", file=sys.stderr)
        if (i // batch_size) % 10 == 0:
            print(f"  procesados {i + len(batch):,}/{n:,}  ok={n_ok:,} fail={n_fail:,}")
    print(f"\n  Resultado: ok={n_ok:,}  fail={n_fail:,}")
    return n_ok, n_fail


def main():
    args = _parse_args()

    path = Path(args.source)
    if not path.exists():
        raise SystemExit(f"No existe {path}")

    excl_rules = set(args.exclude_rule)
    excl_decoders = set(args.exclude_decoder)

    print(f"Fuente: {path} ({path.stat().st_size / 1e9:.2f} GB)")
    if excl_rules: print(f"  Excluyendo rule.id: {excl_rules}")
    if excl_decoders: print(f"  Excluyendo decoders: {excl_decoders}")
    if args.min_level: print(f"  Min level: {args.min_level}")

    # Muestreo estratificado
    sample = sample_stratified(path, args.n, excl_rules, excl_decoders, args.min_level)

    # Reasignación temporal
    now = datetime.now(timezone.utc)
    window_start = now + timedelta(minutes=args.start_offset_min)
    duration_s = args.duration_min * 60
    sample = reassign_timestamps(sample, window_start, duration_s)
    print(f"\nVentana asignada: {window_start.isoformat()} → "
          f"{(window_start + timedelta(seconds=duration_s)).isoformat()}")

    # Adaptación lab
    sample = adapt_for_lab(sample, args.agent_id, args.agent_name)

    if args.dry_run:
        print("\n[DRY-RUN] No se indexa. Primera alerta como muestra:")
        print(json.dumps(sample[0], indent=2, default=str)[:1500])
        return

    # Índice destino
    target_index = args.target_index or f"wazuh-alerts-4.x-{now.strftime('%Y.%m.%d')}"
    print(f"\nÍndice destino: {target_index}")

    client = get_client()
    push_to_indexer(client, sample, target_index, args.batch_size)


if __name__ == "__main__":
    main()
