#!/usr/bin/env python3
"""
inspect_community.py — Inspecciona una comunidad concreta del pipeline.

Para una community_id dada, lista las entidades compartidas entre los
micro-clusters que la forman, identificando cuáles actúan como puentes.

Útil para diagnosticar por qué dos clusters se unieron y si la entidad
puente es legítima o espuria.

Uso:
  python3 inspect_community.py 22
  python3 inspect_community.py 22 --max-clusters 10
"""
from __future__ import annotations
import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

IN = Path("lab_state/real_alerts_incidents.parquet")

BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
CYAN = "\033[36m"; RESET = "\033[0m"


def _iter_entities(v):
    if v is None: return
    if isinstance(v, np.ndarray):
        for x in v.tolist():
            if x: yield x
        return
    if isinstance(v, (list, tuple)):
        for x in v:
            if x: yield x
        return
    if isinstance(v, str) and v:
        yield v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("community_id", type=int)
    ap.add_argument("--max-clusters", type=int, default=8)
    args = ap.parse_args()

    if not IN.exists():
        raise SystemExit(f"Falta {IN}")
    df = pd.read_parquet(IN)
    sub = df[df["community_id"] == args.community_id]
    if sub.empty:
        raise SystemExit(f"No hay comunidad {args.community_id}")

    print(f"\n{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}  Comunidad #{args.community_id}{RESET}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}\n")

    decoders = sorted(set(sub["decoder.name"].dropna().astype(str)))
    rules = sorted(set(sub["rule.id"].dropna().astype(str)))
    print(f"  decoders:   [{', '.join(decoders)}]")
    print(f"  reglas:     [{', '.join(rules[:10])}]" +
          (f" + {len(rules)-10} más" if len(rules) > 10 else ""))
    print(f"  filas:      {len(sub)}")
    print(f"  alertas:    {int(sub['count'].sum()):,}")
    print(f"  clusters:   {sub['cluster_id'].nunique()}")

    # Entidades agregadas con conteo de en cuántos clusters aparecen
    ent_in_clusters: dict[str, set] = defaultdict(set)
    ent_total_count: Counter = Counter()
    for _, r in sub.iterrows():
        cid = int(r["cluster_id"])
        for col in ("entity_users", "entity_ips", "entity_hosts"):
            for x in _iter_entities(r[col]):
                ent_in_clusters[str(x)].add(cid)
                ent_total_count[str(x)] += 1

    n_clusters_comm = sub["cluster_id"].nunique()
    bridges = []  # entidades presentes en ≥2 clusters → son las "uniones"
    singles = []
    for e, clusters_set in ent_in_clusters.items():
        if len(clusters_set) >= 2:
            bridges.append((e, len(clusters_set), ent_total_count[e]))
        else:
            singles.append((e, ent_total_count[e]))
    bridges.sort(key=lambda x: -x[1])

    print(f"\n  {BOLD}{YELLOW}ENTIDADES PUENTE{RESET} "
          f"(presentes en ≥2 clusters de los {n_clusters_comm} de la comunidad):")
    if not bridges:
        print(f"    {DIM}ninguna — la comunidad se forma por otras señales{RESET}")
    for e, n_cl, n_total in bridges[:15]:
        pct = n_cl / n_clusters_comm
        # marcamos las muy genéricas
        marker = ""
        if pct > 0.5: marker = f" {RED}[muy genérica]{RESET}"
        elif pct > 0.3: marker = f" {YELLOW}[genérica]{RESET}"
        else: marker = f" {GREEN}[discriminante]{RESET}"
        print(f"    {n_cl:>3} clusters ({pct:>4.0%})  "
              f"{n_total:>4} filas  {e}{marker}")

    print(f"\n  {DIM}Entidades únicas (solo en 1 cluster): {len(singles)}{RESET}")

    # Por cluster, qué entidades trae
    print(f"\n  {BOLD}{CYAN}DESGLOSE POR CLUSTER (top {args.max_clusters}){RESET}")
    cluster_summary = sub.groupby("cluster_id").agg(
        n_filas=("cluster_id", "size"),
        n_alerts=("count", "sum"),
        decoders=("decoder.name", lambda s: ",".join(sorted(set(s)))),
        rules=("rule.id", lambda s: ",".join(sorted(set(s.astype(str)))[:3])),
    ).sort_values("n_alerts", ascending=False)

    for cid, row in cluster_summary.head(args.max_clusters).iterrows():
        cluster_sub = sub[sub["cluster_id"] == cid]
        ents_here = set()
        for _, r in cluster_sub.iterrows():
            for col in ("entity_users", "entity_ips", "entity_hosts"):
                for x in _iter_entities(r[col]):
                    ents_here.add(str(x))
        # cuáles de las ents_here son bridges de la comunidad
        bridge_set = {b[0] for b in bridges}
        bridges_in_this = ents_here & bridge_set
        unique_in_this = ents_here - bridge_set

        print(f"\n    cluster {cid}  ({row['n_filas']} filas, "
              f"{int(row['n_alerts'])} alertas, {row['decoders']}, "
              f"reglas {row['rules']})")
        if bridges_in_this:
            print(f"      {DIM}puentes:{RESET}  " +
                  ", ".join(sorted(bridges_in_this))[:120])
        if unique_in_this:
            uniqs = sorted(unique_in_this)
            print(f"      {DIM}únicas:{RESET}   " +
                  ", ".join(uniqs[:5]) +
                  (f"  ({len(uniqs)} en total)" if len(uniqs) > 5 else ""))
    print()


if __name__ == "__main__":
    main()
