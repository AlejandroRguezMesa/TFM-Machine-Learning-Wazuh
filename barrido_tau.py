#!/usr/bin/env python3
"""
barrido_tau.py - Barrido de tau sobre el dataset principal.

Para cada tau del barrido, reconstruye el grafo de la Capa 3 con el
mismo procedimiento que el pipeline (build_row_entities -> filtro de
entidades promiscuas -> build_row_graph -> Louvain -> consolidate_small)
y mide:

  - numero de aristas y de comunidades
  - factor de reduccion (alertas originales / comunidades >= 0)
  - recall y pureza de cada escenario sintetico (S06-S09), usando el
    mismo matching de entidades que verify_scenarios.py
  - veredicto 4/4 con los mismos umbrales (recall >= 0.30, pureza >= 0.50,
    separacion entre escenarios)

Salidas:
  - CSV con todas las metricas por tau (capturas_temporal/barrido_tau.csv)
  - figura con recall / pureza / comunidades / veredicto por tau
    (capturas_temporal/fig_barrido_tau.png)

Uso:
  .venv/bin/python barrido_tau.py
  .venv/bin/python barrido_tau.py --taus 10 60 300 900 1800 3600 7200
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from asset_map import AssetMap
from anonymization import maybe_load, DEFAULT_MAP_PATH
from graph_layer_real import (
    build_row_entities,
    build_row_graph,
    consolidate_small,
    detect_communities,
    filter_promiscuous_entities,
)


CLUSTERED = Path("lab_state/real_alerts_clustered.parquet")
ASSET_MAP = Path("lab_state/asset_map.json")
GT = Path("lab_state/ground_truth.jsonl")
OUT_DIR = Path("capturas_temporal")
DEFAULT_TAUS = [10.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0]


# Mismos umbrales que verify_scenarios.py
MIN_RECALL = 0.30
MIN_PURITY = 0.50


# ---------------------------------------------------------------------------
# Matching de entidades de los escenarios (replica fiel de
# verify_scenarios.py para que el veredicto sea homogeneo)
# ---------------------------------------------------------------------------

GENERIC_ENTITIES = {
    "pa-vm300-01", "pa-vm300-02", "host:pa-vm300-01", "host:pa-vm300-02",
    "wazuh-server", "wazuh-manager", "localhost",
    "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255",
    "labcorp.com", "labcorp.local", "vsphere.local",
    "10.252.11.21", "10.252.11.47",
    "", "none", "null", "unknown", "-", "--", "n/a",
    "8.8.8.8", "1.1.1.1",
}


def _is_discriminating(s):
    if not isinstance(s, str) or not s:
        return False
    s_low = s.lower().strip()
    if s_low in GENERIC_ENTITIES:
        return False
    if s_low.startswith("2026-") or s_low.startswith("2025-"):
        return False
    return True


def _iter_entities(v):
    if v is None:
        return
    if isinstance(v, np.ndarray):
        for x in v.tolist():
            if x:
                yield x
        return
    if isinstance(v, (list, tuple)):
        for x in v:
            if x:
                yield x
        return
    if isinstance(v, str) and v:
        yield v


def load_gt():
    if not GT.exists():
        raise SystemExit(f"No existe {GT}.")
    by_scenario = defaultdict(
        lambda: {"entities": set(), "sources": set(),
                 "n_events": 0, "name": ""})
    with open(GT) as f:
        for line in f:
            rec = json.loads(line)
            base = re.sub(r"-[0-9a-f]{6,}$", "", rec["incident_id"])
            inc = by_scenario[base]
            inc["name"] = rec.get("scenario", "")
            inc["n_events"] += 1
            inc["sources"].add(rec.get("source", ""))
            for v in (rec.get("vars") or {}).values():
                if (isinstance(v, str) and _is_discriminating(v)
                        and not v.isdigit()):
                    inc["entities"].add(v.lower())
            for v in (rec.get("entities") or {}).values():
                if isinstance(v, str) and _is_discriminating(v):
                    inc["entities"].add(v.lower())
    return by_scenario


def _normalize_for_match(s, anon=None):
    out = {s.lower()}
    s2 = s.lower()
    if "@" in s2:
        out.add(s2.split("@")[0])
    if "\\" in s2:
        out.add(s2.split("\\")[-1])
    if anon is not None:
        # mismo criterio que verify_scenarios.normalize_for_match:
        # IPs no se anonimizan, usuarios sustituidos por alias.
        from normalize import norm_ip
        extra = set()
        for v in list(out):
            if norm_ip(v):
                continue
            alias = anon.lookup_raw(v)
            if alias and alias != v:
                extra.add(alias)
                extra.add(f"user:{alias}")
        out |= extra
    return out


def _collect_alert_entities(row):
    out = set()
    for col in ("entity_users", "entity_ips", "entity_hosts"):
        for x in _iter_entities(row.get(col)):
            x = str(x).lower()
            matched = False
            for prefix in ("user:", "ip:", "host:", "asset:"):
                if x.startswith(prefix):
                    out.add(x[len(prefix):])
                    out.add(x)
                    matched = True
                    break
            if not matched:
                out.add(x)
    for col in ("data.source_address", "data.destination_address"):
        v = row.get(col)
        if isinstance(v, str) and v:
            out.add(v.lower())
    return out


def scenario_row_indices(df, by_scenario, anon=None):
    """{escenario_id: set(row_idx) cuyas entidades coinciden con el GT}."""
    if "_ents" not in df.columns:
        df = df.copy()
        df["_ents"] = df.apply(_collect_alert_entities, axis=1)
    result = {}
    for scenario_id, info in by_scenario.items():
        cands = set()
        for e in info["entities"]:
            cands.update(_normalize_for_match(e, anon=anon))
        mask = df["_ents"].apply(
            lambda r, c=cands: any(x in r for x in c))
        result[scenario_id] = set(df.index[mask])
    return result, df


# ---------------------------------------------------------------------------
# Carga compartida (asset_map, row_ents, decoders) - se hace UNA sola vez
# ---------------------------------------------------------------------------

def cargar_dataset_y_entidades():
    df = pd.read_parquet(CLUSTERED).reset_index(drop=True)
    amap = AssetMap.load(ASSET_MAP) if ASSET_MAP.exists() else None
    row_ents_full = build_row_entities(df, amap)
    decoders = df["decoder.name"].astype(str).tolist()
    row_ents, _ = filter_promiscuous_entities(
        row_ents_full, max_rows_frac=0.10, max_decoders=4,
        decoders=decoders, verbose=False)
    return df, row_ents


# ---------------------------------------------------------------------------
# Una configuracion (tau dado) -> metricas
# ---------------------------------------------------------------------------

def medir_tau(df, row_ents, by_scenario, scenario_rows,
              tau, decay_kind="exponential",
              min_shared=1, min_weight=1.0,
              min_comm_size=3):
    """Replica del flujo de graph_layer_real.main pero parametrizado por
    tau. Devuelve un dict con todas las metricas."""

    G = build_row_graph(
        row_ents, min_shared=min_shared, min_weight=min_weight,
        first_seen=df["first_seen"], last_seen=df["last_seen"],
        decay_kind=decay_kind, decay_tau=tau or 1.0,
        decay_hard_cutoff=None,
    )
    part = detect_communities(G, row_ents)
    part = consolidate_small(df, part, row_ents, min_size=min_comm_size)
    n_aristas = G.number_of_edges()
    n_comm = len({v for v in part.values() if v >= 0})

    comm_arr = np.array([part.get(i, -1) for i in range(len(df))])
    df_local = df.copy()
    df_local["community_id"] = comm_arr

    n_alertas = int(df_local["count"].sum())
    factor = n_alertas / n_comm if n_comm else float("nan")

    # recall / pureza por escenario, con el mismo criterio de
    # verify_scenarios
    sc_metrics = {}
    main_comm_by_scenario = {}
    for scenario_id, idx in scenario_rows.items():
        n_hits = len(idx)
        if n_hits == 0:
            sc_metrics[scenario_id] = {"recall": 0.0, "purity": 0.0,
                                       "main_comm": None,
                                       "n_in_main": 0, "comm_size": 0,
                                       "n_hits": 0}
            continue
        hits = df_local.loc[sorted(idx)]
        comm_dist = (hits[hits["community_id"] >= 0]["community_id"]
                     .value_counts())
        if comm_dist.empty:
            sc_metrics[scenario_id] = {"recall": 0.0, "purity": 0.0,
                                       "main_comm": None,
                                       "n_in_main": 0, "comm_size": 0,
                                       "n_hits": n_hits}
            continue
        main_comm = int(comm_dist.index[0])
        n_in_main = int(comm_dist.iloc[0])
        comm_size = int((comm_arr == main_comm).sum())
        recall = n_in_main / n_hits
        purity = n_in_main / comm_size if comm_size else 0.0
        sc_metrics[scenario_id] = {
            "recall": recall, "purity": purity, "main_comm": main_comm,
            "n_in_main": n_in_main, "comm_size": comm_size,
            "n_hits": n_hits,
        }
        main_comm_by_scenario[scenario_id] = main_comm

    comm_usage = Counter(main_comm_by_scenario.values())
    shared_comms = {c for c, n in comm_usage.items() if n > 1}

    n_ok = 0
    for scenario_id, m in sc_metrics.items():
        if m["main_comm"] is None:
            continue
        rec_ok = m["recall"] >= MIN_RECALL
        pur_ok = m["purity"] >= MIN_PURITY
        not_shared = m["main_comm"] not in shared_comms
        if rec_ok and pur_ok and not_shared:
            n_ok += 1

    return {
        "n_aristas": n_aristas,
        "n_comunidades": n_comm,
        "n_alertas": n_alertas,
        "factor_reduccion": factor,
        "n_ok": n_ok,
        "n_escenarios": len(sc_metrics),
        "shared_comms": sorted(shared_comms),
        "escenarios": sc_metrics,
    }


# ---------------------------------------------------------------------------
# Tabla CSV
# ---------------------------------------------------------------------------

def guardar_csv(resultados, scenarios_ord, path):
    cols = ["tau_s", "decay_kind", "n_aristas", "n_comunidades",
            "n_alertas", "factor_reduccion", "n_ok",
            "n_escenarios", "veredicto_4_4", "shared_comms"]
    for sc in scenarios_ord:
        cols += [f"{sc}_recall", f"{sc}_purity", f"{sc}_main_comm",
                 f"{sc}_n_filas"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in resultados:
            row = [
                r["tau_s"] if r["tau_s"] is not None else "",
                r["decay_kind"],
                r["n_aristas"], r["n_comunidades"], r["n_alertas"],
                f"{r['factor_reduccion']:.2f}",
                r["n_ok"], r["n_escenarios"],
                "SI" if r["n_ok"] == r["n_escenarios"] else "NO",
                ";".join(str(c) for c in r["shared_comms"]),
            ]
            for sc in scenarios_ord:
                m = r["escenarios"].get(sc, {})
                row += [
                    f"{m.get('recall', 0):.3f}",
                    f"{m.get('purity', 0):.3f}",
                    m.get("main_comm", ""),
                    m.get("n_hits", 0),
                ]
            w.writerow(row)


# ---------------------------------------------------------------------------
# Figura
# ---------------------------------------------------------------------------

COLORS_SCENARIO = {
    "INC-S06": "#0072B2",
    "INC-S07": "#D55E00",
    "INC-S08": "#009E73",
    "INC-S09": "#CC79A7",
}


def _xticks_etiquetas(taus):
    labels = []
    for t in taus:
        if t is None:
            labels.append("sin decay")
        elif t >= 3600:
            labels.append(f"{t/3600:g} h")
        elif t >= 60:
            labels.append(f"{t/60:g} min")
        else:
            labels.append(f"{t:g} s")
    return labels


def figura_barrido(resultados, scenarios_ord, out_path):
    taus = [r["tau_s"] for r in resultados]
    labels = _xticks_etiquetas(taus)
    n = len(taus)
    xs = np.arange(n)

    fig, axes = plt.subplots(2, 2, figsize=(13, 8.5))

    # --- recall por escenario ---
    ax = axes[0, 0]
    for sc in scenarios_ord:
        ys = [r["escenarios"].get(sc, {}).get("recall", 0)
              for r in resultados]
        ax.plot(xs, ys, marker="o", color=COLORS_SCENARIO.get(sc, "#444"),
                label=sc, linewidth=2.0)
    ax.axhline(MIN_RECALL, color="#aa0000", linestyle="--", linewidth=0.9,
               label=f"min recall = {MIN_RECALL:.0%}")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylim(-0.05, 1.05)
    ax.set_ylabel("Recall en la comunidad principal")
    ax.set_title("Recall por escenario en funcion de tau")
    ax.legend(loc="lower left", ncol=2, fontsize=8)
    ax.grid(True, color="#dddddd", linewidth=0.6)

    # --- pureza por escenario ---
    ax = axes[0, 1]
    for sc in scenarios_ord:
        ys = [r["escenarios"].get(sc, {}).get("purity", 0)
              for r in resultados]
        ax.plot(xs, ys, marker="s", color=COLORS_SCENARIO.get(sc, "#444"),
                label=sc, linewidth=2.0)
    ax.axhline(MIN_PURITY, color="#aa0000", linestyle="--", linewidth=0.9,
               label=f"min pureza = {MIN_PURITY:.0%}")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylim(-0.05, 1.05)
    ax.set_ylabel("Pureza de la comunidad principal")
    ax.set_title("Pureza por escenario en funcion de tau")
    ax.legend(loc="lower left", ncol=2, fontsize=8)
    ax.grid(True, color="#dddddd", linewidth=0.6)

    # --- num comunidades + factor de reduccion ---
    ax = axes[1, 0]
    comms = [r["n_comunidades"] for r in resultados]
    ax.plot(xs, comms, marker="o", color="#0072B2", linewidth=2.0,
            label="comunidades")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylabel("Num. comunidades", color="#0072B2")
    ax.tick_params(axis="y", labelcolor="#0072B2")
    ax2 = ax.twinx()
    factor = [r["factor_reduccion"] for r in resultados]
    ax2.plot(xs, factor, marker="s", color="#D55E00", linewidth=2.0,
             label="factor reduccion")
    ax2.set_ylabel("Factor de reduccion (alertas / comunidades)",
                   color="#D55E00")
    ax2.tick_params(axis="y", labelcolor="#D55E00")
    ax.set_title("Granularidad del grafo en funcion de tau")
    ax.grid(True, color="#dddddd", linewidth=0.6)
    ax2.grid(False)

    # --- veredicto 4/4 ---
    ax = axes[1, 1]
    n_ok = [r["n_ok"] for r in resultados]
    n_total = [r["n_escenarios"] for r in resultados]
    colors = ["#009E73" if a == b else ("#D55E00" if a > 0 else "#aa0000")
              for a, b in zip(n_ok, n_total)]
    bars = ax.bar(xs, n_ok, color=colors, edgecolor="#222", linewidth=0.6)
    ax.axhline(n_total[0], color="#444", linestyle=":", linewidth=0.8,
               label=f"objetivo {n_total[0]}/{n_total[0]}")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylim(0, max(n_total) + 0.5)
    ax.set_ylabel("Escenarios consolidados (OK)")
    ax.set_title("Veredicto 4/4 en funcion de tau")
    for b, val, tot in zip(bars, n_ok, n_total):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05,
                f"{val}/{tot}", ha="center", va="bottom",
                fontsize=10, fontweight="bold")
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(True, axis="y", color="#dddddd", linewidth=0.6)

    fig.suptitle(
        "Barrido de tau con Dt en SEGUNDOS REALES "
        "(graph_layer_real._row_intervals_seconds corregido)",
        fontsize=13, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=180, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--taus", type=float, nargs="*",
                    default=DEFAULT_TAUS,
                    help="lista de tau en segundos para el barrido")
    ap.add_argument("--csv", type=Path,
                    default=OUT_DIR / "barrido_tau.csv")
    ap.add_argument("--fig", type=Path,
                    default=OUT_DIR / "fig_barrido_tau.png")
    ap.add_argument("--decay-kind", default="exponential",
                    choices=("exponential", "gaussian", "linear", "power"))
    ap.add_argument("--min-weight", type=float, default=1.0,
                    help="filtro de peso minimo (default 1.0 = el del "
                         "pipeline pre-decay)")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="mapa de anonimizacion para resolver GT contra "
                         "parquet anonimizado")
    args = ap.parse_args()

    anon = maybe_load(args.user_alias_map)
    if anon is not None:
        print(f"[anon] resolviendo GT con {args.user_alias_map} "
              f"({len(anon.forward)} usuarios)")

    print(f"Cargando dataset y entidades...")
    df, row_ents = cargar_dataset_y_entidades()
    print(f"  {len(df):,} filas, {sum(1 for e in row_ents if e):,} con "
          f"entidad util")
    by_scenario = load_gt()
    print(f"  {len(by_scenario)} escenario(s) en ground truth: "
          f"{sorted(by_scenario)}")
    scenario_rows, df = scenario_row_indices(df, by_scenario, anon=anon)
    for sc, idx in scenario_rows.items():
        print(f"    {sc}: {len(idx)} filas detectadas")

    scenarios_ord = sorted(by_scenario.keys())

    resultados = []

    # configuracion "sin decay" como referencia (decay-kind none)
    print(f"\n[sin decay] kind=none, min_weight={args.min_weight}")
    res = medir_tau(df, row_ents, by_scenario, scenario_rows,
                    tau=None, decay_kind="none",
                    min_weight=args.min_weight)
    res["tau_s"] = None
    res["decay_kind"] = "none"
    resultados.append(res)
    print(f"  aristas={res['n_aristas']:,}  "
          f"comunidades={res['n_comunidades']}  "
          f"factor={res['factor_reduccion']:.2f}  "
          f"OK={res['n_ok']}/{res['n_escenarios']}")

    # barrido de tau con decay exponencial
    for t in args.taus:
        print(f"\n[tau={t:g}s] kind={args.decay_kind}, "
              f"min_weight={args.min_weight}")
        res = medir_tau(df, row_ents, by_scenario, scenario_rows,
                        tau=float(t), decay_kind=args.decay_kind,
                        min_weight=args.min_weight)
        res["tau_s"] = float(t)
        res["decay_kind"] = args.decay_kind
        resultados.append(res)
        print(f"  aristas={res['n_aristas']:,}  "
              f"comunidades={res['n_comunidades']}  "
              f"factor={res['factor_reduccion']:.2f}  "
              f"OK={res['n_ok']}/{res['n_escenarios']}")
        for sc in scenarios_ord:
            m = res["escenarios"].get(sc, {})
            print(f"    {sc}: recall={m.get('recall',0):.0%} "
                  f"pureza={m.get('purity',0):.0%} "
                  f"main_comm=#{m.get('main_comm')} "
                  f"n_filas={m.get('n_hits',0)}")

    guardar_csv(resultados, scenarios_ord, args.csv)
    print(f"\nCSV guardado: {args.csv}")
    figura_barrido(resultados, scenarios_ord, args.fig)
    print(f"Figura guardada: {args.fig}")

    # Resumen tabular legible
    print("\n" + "=" * 96)
    print("RESUMEN DEL BARRIDO")
    print("=" * 96)
    header = f"{'config':>14}  {'aristas':>8}  {'comm':>6}  {'fact':>6}  "
    for sc in scenarios_ord:
        header += f"{sc:>10}  "
    header += "veredicto"
    print(header)
    print("-" * 96)
    for r in resultados:
        cfg = "sin decay" if r["tau_s"] is None else f"tau={r['tau_s']:g}s"
        row = f"{cfg:>14}  {r['n_aristas']:>8,}  {r['n_comunidades']:>6}  "
        row += f"{r['factor_reduccion']:>6.1f}  "
        for sc in scenarios_ord:
            m = r["escenarios"].get(sc, {})
            row += f"{m.get('recall',0):>4.0%}/{m.get('purity',0):<4.0%} "
        ver = "4/4" if r["n_ok"] == r["n_escenarios"] else \
              f"{r['n_ok']}/{r['n_escenarios']}"
        if r["shared_comms"]:
            ver += f" (compartidas: {r['shared_comms']})"
        row += " " + ver
        print(row)


if __name__ == "__main__":
    main()
