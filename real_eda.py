#!/usr/bin/env python3
"""
real_eda.py — Análisis exploratorio en streaming de alerts.json grande.

Lee el fichero línea a línea SIN cargarlo en memoria. Genera un informe
estadístico que sirve para decidir parámetros de:
  - deduplicación (qué reglas se repiten mucho)
  - normalización (qué campos están poblados por decoder)
  - clustering (cardinalidad de entidades, distribución temporal)

Uso:
  python3 real_eda.py /ruta/al/alerts.json
  python3 real_eda.py /ruta/al/alerts.json --max-lines 500000   # samplear
  python3 real_eda.py /ruta/al/alerts.json --out lab_state/eda_report.txt
"""
from __future__ import annotations
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

# Para mostrar progreso sin saturar el log
def _progress(n, every=100000):
    if n % every == 0:
        print(f"  procesadas {n:,} líneas")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="ruta al alerts.json")
    ap.add_argument("--max-lines", type=int, default=None,
                    help="limitar nº de líneas (debug rápido)")
    ap.add_argument("--out", default="lab_state/eda_report.txt")
    args = ap.parse_args()

    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"No existe {path}")

    print(f"Analizando {path} ({path.stat().st_size / 1e9:.2f} GB)")

    # Contadores
    n_total = 0
    n_parse_errors = 0
    n_encoding_errors = 0
    decoders = Counter()
    rule_ids = Counter()
    rule_levels = Counter()
    rule_groups = Counter()
    locations = Counter()
    timestamps = []
    mitre_tactics = Counter()
    # campos data.* por decoder: cuántas alertas tienen cada campo
    fields_by_decoder: dict[str, Counter] = defaultdict(Counter)
    # cardinalidad de entidades clave por decoder
    entities_by_decoder: dict[str, dict[str, Counter]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    # tuplas (decoder, rule.id, key_fields) para estimar repetición
    repetition_keys = Counter()

    CAND_ENTITIES = {
        "src_ip":  ["data.srcip", "data.source_address", "data.office365.ClientIP"],
        "dst_ip":  ["data.dstip", "data.destination_address"],
        "user":    ["data.office365.UserId", "data.vc_user",
                    "data.srcuser", "data.dstuser",
                    "data.userEmail"],
        "host":    ["data.agentRealtimeInfo.agentComputerName",
                    "data.computerName",
                    "predecoder.hostname"],
    }

    def _get(d, path):
        cur = d
        for p in path.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
            if cur is None:
                return None
        return cur

    # Antes: errors="replace" silenciaba corrupcion de bytes. Ahora
    # leemos como binario, decodificamos linea a linea con encoding
    # estricto y descartamos la linea ofensiva con contador para reporte.
    with open(path, "rb") as f_bin:
        for raw_line in f_bin:
            try:
                line = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                n_encoding_errors += 1
                continue
            if not line:
                continue
            n_total += 1
            _progress(n_total)
            if args.max_lines and n_total > args.max_lines:
                break
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                n_parse_errors += 1
                continue

            # campos básicos
            dec  = _get(a, "decoder.name") or "?"
            rid  = str(_get(a, "rule.id") or "?")
            lvl  = _get(a, "rule.level")
            loc  = _get(a, "location") or "?"
            tsv  = _get(a, "timestamp")
            grps = _get(a, "rule.groups") or []
            tact = _get(a, "rule.mitre.tactic") or []

            decoders[dec] += 1
            rule_ids[(rid, (_get(a, "rule.description") or "")[:80])] += 1
            if lvl is not None:
                rule_levels[lvl] += 1
            locations[loc] += 1
            if tsv:
                timestamps.append(tsv)
            if isinstance(grps, list):
                for g in grps:
                    rule_groups[g] += 1
            if isinstance(tact, list):
                for t in tact:
                    mitre_tactics[t] += 1

            # campos poblados (solo data.* primer nivel para no inflar)
            data = a.get("data", {})
            if isinstance(data, dict):
                for k in data.keys():
                    fields_by_decoder[dec][f"data.{k}"] += 1
            # entidades
            for ent_kind, cols in CAND_ENTITIES.items():
                for col in cols:
                    v = _get(a, col)
                    if isinstance(v, str) and v:
                        entities_by_decoder[dec][ent_kind][v] += 1
                        break  # solo el primero

            # clave de repetición para estimar dedup potencial
            src = _get(a, "data.source_address") or _get(a, "data.srcip") or ""
            dst = _get(a, "data.destination_address") or _get(a, "data.dstip") or ""
            user = _get(a, "data.office365.UserId") or _get(a, "data.vc_user") or ""
            repetition_keys[(dec, rid, src, dst, user)] += 1

    # ====== Imprimir informe ======
    out = []
    def p(s=""):
        print(s)
        out.append(s)

    p(f"\n{'='*72}")
    p(f"  INFORME EDA: {path.name}")
    p(f"{'='*72}")
    p(f"Total líneas leídas: {n_total:,}")
    p(f"Errores de parseo:   {n_parse_errors:,}")
    if n_encoding_errors:
        p(f"Errores de encoding (lineas descartadas): "
          f"{n_encoding_errors:,}  ⚠ revisa la fuente")

    if timestamps:
        timestamps.sort()
        p(f"Timespan: {timestamps[0]} → {timestamps[-1]}")

    p(f"\n--- Top 20 decoders ---")
    for d, c in decoders.most_common(20):
        p(f"  {c:>10,}  {d}")

    p(f"\n--- Distribución de niveles de regla ---")
    for lvl in sorted(rule_levels):
        p(f"  level {lvl}:  {rule_levels[lvl]:>10,}")

    p(f"\n--- Top 30 reglas (rule.id, descripción) ---")
    for (rid, desc), c in rule_ids.most_common(30):
        p(f"  {c:>10,}  rule={rid:<6}  {desc}")

    p(f"\n--- Top 25 grupos de regla ---")
    for g, c in rule_groups.most_common(25):
        p(f"  {c:>10,}  {g}")

    p(f"\n--- MITRE tactics ---")
    for t, c in mitre_tactics.most_common(15):
        p(f"  {c:>10,}  {t}")

    p(f"\n--- Top 15 locations ---")
    for l, c in locations.most_common(15):
        p(f"  {c:>10,}  {l}")

    # Análisis de repetición
    p(f"\n--- ANÁLISIS DE REPETICIÓN (deduplicación potencial) ---")
    p(f"Claves únicas (decoder, rule.id, src, dst, user): {len(repetition_keys):,}")
    n_unique = sum(1 for c in repetition_keys.values() if c == 1)
    n_repeated = len(repetition_keys) - n_unique
    redundant_alerts = n_total - len(repetition_keys)
    p(f"  claves con 1 sola alerta:     {n_unique:,}")
    p(f"  claves repetidas:             {n_repeated:,}")
    p(f"  alertas redundantes:          {redundant_alerts:,} "
      f"({redundant_alerts/n_total:.1%})")
    p(f"  Reducción esperada con dedup: ~{redundant_alerts/n_total:.0%}")

    p(f"\nTop 15 claves más repetidas:")
    for key, c in repetition_keys.most_common(15):
        dec, rid, src, dst, user = key
        ent = f"src={src} dst={dst} user={user}"
        p(f"  {c:>10,}  dec={dec:<12} rule={rid:<6}  {ent[:80]}")

    # Campos por decoder (para validar normalización)
    p(f"\n--- CAMPOS data.* POBLADOS POR DECODER (top 12 por dec) ---")
    for dec, total in decoders.most_common(10):
        p(f"\n  decoder={dec}  (total={total:,})")
        for f, c in fields_by_decoder[dec].most_common(12):
            p(f"     {c:>10,}  {f}")

    # Cardinalidad de entidades
    p(f"\n--- CARDINALIDAD DE ENTIDADES POR DECODER ---")
    for dec, total in decoders.most_common(10):
        p(f"\n  decoder={dec}")
        for ent_kind, counter in entities_by_decoder[dec].items():
            if not counter:
                continue
            top3 = ", ".join(f"{v}({n})" for v, n in counter.most_common(3))
            p(f"     {ent_kind:<10} valores únicos: {len(counter):>6,}  top3: {top3}")

    p(f"\n{'='*72}")
    p(f"  RECOMENDACIONES")
    p(f"{'='*72}")
    biggest_rule = rule_ids.most_common(1)[0]
    p(f"  - La regla dominante es {biggest_rule[0][0]} con {biggest_rule[1]:,} alertas.")
    if redundant_alerts / n_total > 0.5:
        p(f"  - >50% de las alertas son redundantes. Aplica dedup antes de clusterizar.")
    if n_total > 100_000:
        p(f"  - Volumen alto ({n_total:,}). Tras dedup, "
          f"clustering en {len(repetition_keys):,} alertas.")

    # Guardar a fichero
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(out))
    p(f"\nInforme guardado en {out_path}")


if __name__ == "__main__":
    main()
