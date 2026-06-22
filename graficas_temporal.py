#!/usr/bin/env python3
"""
graficas_temporal.py — Figuras para el apartado de decaimiento temporal.

Genera un conjunto de PNGs en `capturas_temporal/` que documentan
visualmente el efecto del decaimiento temporal aadido al grafo de la
Capa 3 (`graph_layer_real.py`).

El script es independiente: lee `lab_state/real_alerts_clustered.parquet`
(entrada del grafo C3) y `lab_state/ground_truth.jsonl`, y NO altera el
pipeline ni los parquets de salida. Reutiliza las funciones publicas de
`graph_layer_real.py` (build_row_entities, build_row_graph,
detect_communities, consolidate_small, temporal_decay) para garantizar
que las comparativas se hacen con el mismo codigo que el pipeline real.

Figuras generadas
-----------------
  fig1_decay_funcs.png         Curvas f(Dt) para las cuatro familias.
  fig2_edges_sin_vs_con.png    Recuento de aristas y comunidades sin y
                               con decaimiento temporal.
  fig3_pesos_dist.png          Distribucion de pesos de arista en cada
                               configuracion.
  fig4_hist_deltas.png         Histograma de Dt para las aristas
                               candidatas (escala log).
  fig5_timeline_escenarios.png Ventana temporal ocupada por cada
                               escenario S06-S09.
  fig6_sensibilidad_tau.png    Numero de comunidades y de aristas en
                               funcion de tau (barrido).
  fig7_recall_pureza_tau.png   Recall y pureza de cada escenario en
                               funcion de tau.

Uso
---
    .venv/bin/python graficas_temporal.py
    .venv/bin/python graficas_temporal.py --out otra_carpeta --dpi 200
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # backend sin GUI: util en headless
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Reutilizamos las funciones del pipeline para asegurar coherencia.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from asset_map import AssetMap
from graph_layer_real import (
    DECAY_KINDS,
    build_row_entities,
    build_row_graph,
    consolidate_small,
    detect_communities,
    filter_promiscuous_entities,
    temporal_decay,
)


# ---------------------------------------------------------------- estilo
plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#444444",
    "axes.labelcolor": "#222222",
    "axes.titleweight": "bold",
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "xtick.color": "#444444",
    "ytick.color": "#444444",
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "axes.grid": True,
    "grid.color": "#dddddd",
    "grid.linestyle": "-",
    "grid.linewidth": 0.6,
    "legend.frameon": False,
    "legend.fontsize": 9,
    "font.family": "DejaVu Sans",
})
# Paleta sobria (Color Universal Design): azul, naranja, verde, gris, rojo.
COLORS = {
    "exponential": "#0072B2",
    "gaussian":    "#D55E00",
    "linear":      "#009E73",
    "power":       "#56B4E9",
    "none":        "#888888",
    "S06": "#0072B2",
    "S07": "#D55E00",
    "S08": "#009E73",
    "S09": "#CC79A7",
}


# --------------------------------------------------------------- carga
def cargar_datos(asset_map_path: Path):
    """Devuelve (df, row_ents, t0, t1) listos para construir el grafo."""
    df = pd.read_parquet("lab_state/real_alerts_clustered.parquet") \
        .reset_index(drop=True)
    amap = AssetMap.load(asset_map_path) if asset_map_path.exists() else None
    row_ents = build_row_entities(df, amap)
    decoders = df["decoder.name"].astype(str).tolist()
    row_ents, _ = filter_promiscuous_entities(row_ents, decoders=decoders,
                                               verbose=False)
    t0 = (pd.to_datetime(df["first_seen"], utc=True).astype("int64")
          .to_numpy(dtype=np.float64) / 1e9)
    t1 = (pd.to_datetime(df["last_seen"], utc=True).astype("int64")
          .to_numpy(dtype=np.float64) / 1e9)
    return df, row_ents, t0, t1


def cargar_ground_truth():
    """Devuelve dict {escenario_id: {entidades, t_min, t_max, nombre}}."""
    gt_path = Path("lab_state/ground_truth.jsonl")
    if not gt_path.exists():
        return {}
    sc: dict[str, dict] = {}
    with open(gt_path) as f:
        for line in f:
            rec = json.loads(line)
            iid = rec["incident_id"]
            base = re.sub(r"-[0-9a-f]{6,}$", "", iid)
            d = sc.setdefault(base, {
                "nombre": rec.get("scenario", ""),
                "entidades": set(),
                "t_min": None,
                "t_max": None,
            })
            for v in (rec.get("vars") or {}).values():
                if isinstance(v, str) and v and not v.isdigit():
                    d["entidades"].add(v.lower())
            for v in (rec.get("entities") or {}).values():
                if isinstance(v, str) and v:
                    d["entidades"].add(v.lower())
            # Usamos t_emit como timestamp canonico del evento en GT.
            t_emit = rec.get("t_emit")
            if isinstance(t_emit, str) and t_emit:
                try:
                    t = pd.Timestamp(t_emit)
                except Exception:
                    t = None
                if t is not None:
                    if d["t_min"] is None or t < d["t_min"]:
                        d["t_min"] = t
                    if d["t_max"] is None or t > d["t_max"]:
                        d["t_max"] = t
    return sc


# --------------------------------------------------------- construccion
def pares_candidatos(row_ents, t0, t1):
    """Devuelve dict {(a,b): (shared, dt)} para todos los pares de filas
    que comparten al menos una entidad util. Aplica el mismo limite de
    400 filas por entidad que el grafo real."""
    inv = defaultdict(set)
    for i, ents in enumerate(row_ents):
        for e in ents:
            inv[e].add(i)
    edge_n: dict[tuple[int, int], int] = defaultdict(int)
    for e, rows in inv.items():
        rl = sorted(rows)
        if len(rl) > 400:
            continue
        for i in range(len(rl)):
            for j in range(i + 1, len(rl)):
                edge_n[(rl[i], rl[j])] += 1
    pares = {}
    for (a, b), shared in edge_n.items():
        dt = max(0.0, max(t0[a], t0[b]) - min(t1[a], t1[b]))
        pares[(a, b)] = (shared, dt)
    return pares


def grafo_con_config(df, row_ents, decay_kind, tau, hard_cutoff,
                     min_shared=1, min_weight=0.0,
                     min_comm_size=3, consolidar=True):
    """Construye el grafo con la configuracion dada y devuelve
    (G, particion_final)."""
    G = build_row_graph(
        row_ents, min_shared, min_weight,
        first_seen=df["first_seen"], last_seen=df["last_seen"],
        decay_kind=decay_kind, decay_tau=tau,
        decay_hard_cutoff=hard_cutoff,
    )
    part = detect_communities(G, row_ents)
    if consolidar:
        part = consolidate_small(df, part, row_ents, min_size=min_comm_size)
    return G, part


# ----------------------------------------------------------- figuras
def fig1_decay_funcs(out: Path, tau: float, hard_cutoff: float | None):
    """Curvas de las cuatro familias de decaimiento, con marcas de tau
    y de hard_cutoff."""
    dts = np.linspace(0, max(4 * tau, (hard_cutoff or 0) * 1.2 + 1), 600)
    fig, ax = plt.subplots(figsize=(8.5, 5.0))
    for kind in ("exponential", "gaussian", "linear", "power"):
        ys = [temporal_decay(d, kind=kind, tau=tau) for d in dts]
        ax.plot(dts, ys, label=kind, color=COLORS[kind], linewidth=2.0)
    ax.axvline(tau, color="#444", linestyle="--", linewidth=1.0,
               label=f"tau = {tau:g} s")
    ax.axhline(1.0 / np.e, color="#888", linestyle=":", linewidth=0.8)
    ax.text(tau * 0.02, 1.0 / np.e + 0.015, "1/e",
            color="#666", fontsize=8)
    if hard_cutoff is not None:
        ax.axvline(hard_cutoff, color="#B22222", linestyle="-.",
                   linewidth=1.0, label=f"hard cutoff = {hard_cutoff:g} s")
    ax.set_xlabel("Distancia temporal Dt entre filas (segundos)")
    ax.set_ylabel("Peso relativo f(Dt)")
    ax.set_title("Funciones de decaimiento temporal disponibles")
    ax.set_ylim(-0.02, 1.05)
    ax.set_xlim(0, dts.max())
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)


def fig2_edges_sin_vs_con(out: Path, df, row_ents, tau, hard_cutoff,
                          tau_agresivo=0.2):
    """Comparativa: aristas y comunidades sin / con decaimiento.

    Se incluye una tercera columna con un tau muy bajo (sub-segundo)
    para mostrar el efecto en un dataset cuyos Dt tipicos son <5s.
    """
    configs = [
        ("Sin decay",                  "none",        None,         None),
        (f"Exp tau={tau:g}s",          "exponential", tau,          None),
        (f"Exp tau={tau_agresivo:g}s (agresivo)",
                                       "exponential", tau_agresivo, None),
        (f"Hard cutoff={hard_cutoff or 1:g}s",
                                       "none",        None,
         hard_cutoff or 1.0),
    ]
    res = []
    for label, kind, t, hc in configs:
        G, part = grafo_con_config(df, row_ents, kind, t, hc)
        n_edges = G.number_of_edges()
        n_comm = len({v for v in part.values() if v >= 0})
        ws = [d["weight"] for _, _, d in G.edges(data=True)]
        w_sum = float(np.sum(ws)) if ws else 0.0
        w_mean = float(np.mean(ws)) if ws else 0.0
        res.append({"label": label, "edges": n_edges, "comms": n_comm,
                    "weights": ws, "w_sum": w_sum, "w_mean": w_mean})

    palette = ["#888888", "#0072B2", "#D55E00", "#B22222"]
    fig, axes = plt.subplots(1, 3, figsize=(14.0, 4.8))
    xs = np.arange(len(res))
    labels = [r["label"] for r in res]

    bars = axes[0].bar(xs, [r["edges"] for r in res],
                       color=palette[:len(res)], width=0.55)
    axes[0].set_xticks(xs)
    axes[0].set_xticklabels(labels, rotation=18, ha="right")
    axes[0].set_ylabel("Aristas en el grafo")
    axes[0].set_title("Numero de aristas")
    for b, r in zip(bars, res):
        axes[0].text(b.get_x() + b.get_width() / 2, b.get_height(),
                     f"{r['edges']:,}", ha="center", va="bottom",
                     fontsize=9)

    bars = axes[1].bar(xs, [r["w_sum"] for r in res],
                       color=palette[:len(res)], width=0.55)
    axes[1].set_xticks(xs)
    axes[1].set_xticklabels(labels, rotation=18, ha="right")
    axes[1].set_ylabel("Suma de pesos de las aristas")
    axes[1].set_title("Peso total del grafo")
    for b, r in zip(bars, res):
        axes[1].text(b.get_x() + b.get_width() / 2, b.get_height(),
                     f"{r['w_sum']:,.0f}", ha="center", va="bottom",
                     fontsize=9)

    bars = axes[2].bar(xs, [r["comms"] for r in res],
                       color=palette[:len(res)], width=0.55)
    axes[2].set_xticks(xs)
    axes[2].set_xticklabels(labels, rotation=18, ha="right")
    axes[2].set_ylabel("Comunidades (Louvain + consolidacion)")
    axes[2].set_title("Numero de comunidades")
    for b, r in zip(bars, res):
        axes[2].text(b.get_x() + b.get_width() / 2, b.get_height(),
                     f"{r['comms']:,}", ha="center", va="bottom",
                     fontsize=9)

    fig.suptitle("Efecto del decaimiento temporal en el grafo de filas",
                 fontsize=13)
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)
    return res


def fig3_pesos_dist(out: Path, res):
    """Distribucion de pesos de arista por configuracion."""
    palette = ["#888888", "#0072B2", "#D55E00", "#B22222"]
    fig, ax = plt.subplots(figsize=(9.0, 5.0))
    max_w = max((max(r["weights"]) if r["weights"] else 1) for r in res)
    bins = np.linspace(0, max_w + 0.5, 40)
    for r, color in zip(res, palette):
        if not r["weights"]:
            continue
        ax.hist(r["weights"], bins=bins, alpha=0.55, label=r["label"],
                color=color, edgecolor="white", linewidth=0.4)
    ax.set_xlabel("Peso de arista")
    ax.set_ylabel("Numero de aristas")
    ax.set_title("Distribucion de pesos de arista en cada configuracion")
    ax.set_yscale("log")
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)


def fig4_hist_deltas(out: Path, pares):
    """Histograma del Dt de las aristas candidatas (todas, antes del
    decaimiento)."""
    dts = np.array([dt for _, dt in pares.values()])
    fig, ax = plt.subplots(figsize=(8.5, 5.0))
    # rango: 0 a percentil 99.5 + un colchon
    p995 = np.percentile(dts, 99.5) if len(dts) else 1.0
    bins = np.linspace(0, max(p995 + 0.1, 1.0), 40)
    ax.hist(dts, bins=bins, color="#0072B2", edgecolor="white",
            linewidth=0.4)
    ax.set_xlabel("Dt (segundos) entre las dos filas conectadas")
    ax.set_ylabel("Numero de aristas candidatas")
    ax.set_title(f"Distribucion de Dt en aristas candidatas (N={len(dts):,})")
    ax.set_yscale("log")
    quartiles = np.percentile(dts, [50, 90, 99])
    for q, lab, c in zip(quartiles, ("p50", "p90", "p99"),
                          ("#444", "#666", "#888")):
        ax.axvline(q, color=c, linestyle="--", linewidth=0.8)
        ax.text(q, ax.get_ylim()[1] * 0.5, f" {lab}={q:.2f}s",
                color=c, fontsize=8, rotation=0)
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)


def fig5_timeline_escenarios(out: Path, df, gt):
    """Ventana temporal de cada escenario S06-S09 y volumen de alertas."""
    if not gt:
        return
    # Ordenar escenarios alfabeticamente (S06, S07, S08, S09)
    keys = sorted(gt.keys())
    fig, ax = plt.subplots(figsize=(10.5, 4.3))
    y_pos = np.arange(len(keys))[::-1]
    t_min = min(g["t_min"] for g in gt.values() if g["t_min"] is not None)
    t_max = max(g["t_max"] for g in gt.values() if g["t_max"] is not None)
    for y, k in zip(y_pos, keys):
        g = gt[k]
        if g["t_min"] is None or g["t_max"] is None:
            continue
        dur = (g["t_max"] - g["t_min"]).total_seconds()
        color = COLORS.get(k.replace("INC-", ""), "#444")
        ax.barh(y, dur, left=(g["t_min"] - t_min).total_seconds(),
                height=0.55, color=color, alpha=0.85,
                edgecolor="#222", linewidth=0.5)
        ax.text((g["t_min"] - t_min).total_seconds() + dur / 2, y,
                f"{k}  ({dur:.0f}s)", ha="center", va="center",
                color="white", fontsize=9, weight="bold")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(keys)
    ax.set_xlabel(f"Segundos desde {t_min:%Y-%m-%d %H:%M:%S} UTC")
    ax.set_title("Linea temporal de los escenarios sinteticos")
    ax.set_xlim(-5, (t_max - t_min).total_seconds() + 10)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)


def fig6_sensibilidad_tau(out: Path, df, row_ents, taus, hard_cutoff=None):
    """Peso total del grafo y numero de comunidades en funcion de tau."""
    edges, comms, w_sum = [], [], []
    for t in taus:
        G, part = grafo_con_config(df, row_ents, "exponential", t,
                                   hard_cutoff)
        edges.append(G.number_of_edges())
        comms.append(len({v for v in part.values() if v >= 0}))
        ws = [d["weight"] for _, _, d in G.edges(data=True)]
        w_sum.append(float(np.sum(ws)) if ws else 0.0)

    fig, ax1 = plt.subplots(figsize=(9.5, 5.0))
    ax1.set_xscale("log")
    l1, = ax1.plot(taus, w_sum, marker="o", color="#0072B2",
                   label="suma de pesos")
    ax1.set_xlabel("tau (segundos, escala log)")
    ax1.set_ylabel("Suma de pesos del grafo", color="#0072B2")
    ax1.tick_params(axis="y", labelcolor="#0072B2")

    ax2 = ax1.twinx()
    l2, = ax2.plot(taus, comms, marker="s", color="#D55E00",
                   label="comunidades")
    ax2.set_ylabel("Numero de comunidades", color="#D55E00")
    ax2.tick_params(axis="y", labelcolor="#D55E00")
    ax2.grid(False)

    ax1.set_title("Sensibilidad del grafo frente a tau (decay "
                  "exponencial)")
    ax1.legend(handles=[l1, l2], loc="lower right")
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)
    return list(zip(taus, edges, comms, w_sum))


def fig7_recall_pureza_tau(out: Path, df, row_ents, gt, taus,
                            hard_cutoff=None):
    """Recall y pureza de cada escenario en funcion de tau."""
    if not gt:
        return None

    def normalize_for_match(s):
        out = {s.lower()}
        s2 = s.lower()
        if "@" in s2:
            out.add(s2.split("@")[0])
        if "\\" in s2:
            out.add(s2.split("\\")[-1])
        return out

    GENERIC = {
        "pa-vm300-01", "pa-vm300-02", "host:pa-vm300-01", "host:pa-vm300-02",
        "wazuh-server", "wazuh-manager", "localhost",
        "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255",
        "labcorp.com", "labcorp.local", "vsphere.local",
        "10.252.11.21", "10.252.11.47",
        "", "none", "null", "unknown", "-", "--", "n/a",
        "8.8.8.8", "1.1.1.1",
    }

    def disc(s):
        if not s or s.lower().strip() in GENERIC:
            return False
        if s[:4] in ("2025", "2026"):
            return False
        return True

    # filas que pertenecen a cada escenario (mismo criterio que
    # verify_scenarios.py)
    def collect_row_ents(row):
        out = set()
        for col in ("entity_users", "entity_ips", "entity_hosts"):
            v = row.get(col)
            if v is None:
                continue
            if isinstance(v, (list, tuple, np.ndarray)):
                for x in v:
                    if not x:
                        continue
                    x = str(x).lower()
                    out.add(x)
                    for prefix in ("user:", "ip:", "host:", "asset:"):
                        if x.startswith(prefix):
                            out.add(x[len(prefix):])
            elif isinstance(v, str) and v:
                out.add(v.lower())
        return out

    df_ents = df.apply(collect_row_ents, axis=1)

    scenario_rows = {}
    for k in sorted(gt):
        cands = set()
        for e in gt[k]["entidades"]:
            if disc(e):
                cands |= normalize_for_match(e)
        mask = df_ents.apply(lambda r, c=cands: any(x in r for x in c))
        scenario_rows[k] = set(df.index[mask])

    recall = {k: [] for k in scenario_rows}
    purity = {k: [] for k in scenario_rows}

    for t in taus:
        _, part = grafo_con_config(df, row_ents, "exponential", t,
                                   hard_cutoff)
        comm_arr = np.array([part.get(i, -1) for i in range(len(df))])
        for k, idx in scenario_rows.items():
            if not idx:
                recall[k].append(0.0)
                purity[k].append(0.0)
                continue
            sub_comms = comm_arr[list(idx)]
            sub_comms = sub_comms[sub_comms >= 0]
            if len(sub_comms) == 0:
                recall[k].append(0.0)
                purity[k].append(0.0)
                continue
            main, n_main = max(
                ((c, int((sub_comms == c).sum())) for c in set(sub_comms)),
                key=lambda x: x[1])
            recall[k].append(n_main / len(idx))
            comm_size = int((comm_arr == main).sum())
            purity[k].append(n_main / comm_size if comm_size else 0.0)

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.8), sharex=True)
    for k in sorted(recall):
        c = COLORS.get(k.replace("INC-", ""), "#444")
        axes[0].plot(taus, recall[k], marker="o", color=c, label=k)
        axes[1].plot(taus, purity[k], marker="o", color=c, label=k)
    for ax in axes:
        ax.set_xscale("log")
        ax.set_xlabel("tau (segundos, escala log)")
        ax.set_ylim(-0.05, 1.05)
        ax.axhline(0.30, color="#888", linestyle=":", linewidth=0.8)
    axes[0].set_ylabel("Recall en comunidad principal")
    axes[0].set_title("Recall por escenario vs tau")
    axes[1].set_ylabel("Pureza de la comunidad principal")
    axes[1].set_title("Pureza por escenario vs tau")
    axes[0].legend(loc="lower right", ncol=2)
    fig.tight_layout()
    fig.savefig(out, dpi=180)
    plt.close(fig)
    return {"taus": list(taus), "recall": recall, "purity": purity}


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="capturas_temporal",
                    help="carpeta de salida para los PNG")
    ap.add_argument("--tau", type=float, default=300.0,
                    help="tau (s) usado en las curvas de referencia y en "
                         "fig2-fig3")
    ap.add_argument("--hard-cutoff", type=float, default=60.0,
                    help="hard cutoff (s) usado en fig2 como tercera "
                         "configuracion")
    ap.add_argument("--asset-map", default="lab_state/asset_map.json")
    ap.add_argument("--dpi", type=int, default=180,
                    help="dpi de las figuras (default 180)")
    args = ap.parse_args()

    plt.rcParams["savefig.dpi"] = args.dpi
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Cargando datos...")
    df, row_ents, t0, t1 = cargar_datos(Path(args.asset_map))
    gt = cargar_ground_truth()
    pares = pares_candidatos(row_ents, t0, t1)
    print(f"  {len(df):,} filas, {sum(1 for e in row_ents if e):,} con "
          f"entidad util, {len(pares):,} pares candidatos.")

    print("[1/7] fig1_decay_funcs.png — curvas de decaimiento")
    fig1_decay_funcs(out_dir / "fig1_decay_funcs.png",
                     args.tau, args.hard_cutoff)

    print("[2/7] fig2_edges_sin_vs_con.png — aristas y comunidades")
    res = fig2_edges_sin_vs_con(out_dir / "fig2_edges_sin_vs_con.png",
                                df, row_ents, args.tau, args.hard_cutoff)
    for r in res:
        print(f"      {r['label']:>22}: {r['edges']:>6,} aristas, "
              f"{r['comms']:>3} comunidades")

    print("[3/7] fig3_pesos_dist.png — distribucion de pesos")
    fig3_pesos_dist(out_dir / "fig3_pesos_dist.png", res)

    print("[4/7] fig4_hist_deltas.png — histograma de Dt")
    fig4_hist_deltas(out_dir / "fig4_hist_deltas.png", pares)

    print("[5/7] fig5_timeline_escenarios.png — linea temporal S06-S09")
    fig5_timeline_escenarios(out_dir / "fig5_timeline_escenarios.png",
                             df, gt)

    # Barrido de tau: en este dataset Dt<5s, por lo que el rango
    # ilustrativo combina valores sub-segundo (donde el decay rompe
    # aristas) con valores realistas (300s..1d) donde no hay efecto.
    taus = [0.05, 0.1, 0.3, 0.5, 1.0, 5.0, 30.0, 300.0, 3600.0, 86400.0]
    print(f"[6/7] fig6_sensibilidad_tau.png — barrido tau en {taus}")
    sens = fig6_sensibilidad_tau(out_dir / "fig6_sensibilidad_tau.png",
                                 df, row_ents, taus)
    for t, e, c, ws in sens:
        print(f"      tau={t:>8}s -> {e:>6,} aristas, {c:>3} "
              f"comunidades, peso total {ws:,.0f}")

    print(f"[7/7] fig7_recall_pureza_tau.png — recall y pureza vs tau")
    rp = fig7_recall_pureza_tau(out_dir / "fig7_recall_pureza_tau.png",
                                df, row_ents, gt, taus)
    if rp:
        print("      tau | escenarios -> recall / pureza")
        for i, t in enumerate(rp["taus"]):
            row = []
            for k in sorted(rp["recall"]):
                row.append(f"{k}={rp['recall'][k][i]:.2f}/"
                           f"{rp['purity'][k][i]:.2f}")
            print(f"      {t:>6}s : " + "  ".join(row))

    print(f"\nFiguras guardadas en {out_dir}/")


if __name__ == "__main__":
    main()
