#!/usr/bin/env python3
"""
graficas_decay_s10.py - Figura de contraste para la demo del decaimiento
temporal sobre el escenario S10.

Produce una figura side-by-side que muestra el grafo de filas de S10 (5
filas en Fase A, 4 filas en Fase B, unidas exclusivamente por una IP):

  - Izquierda:  grafo sin decaimiento (decay-kind=none). Las dos fases
                quedan fusionadas en una unica comunidad porque la IP
                compartida tira de las dos sin atenuacion.

  - Derecha:    grafo con decaimiento exponencial (tau=300 s por defecto).
                Las aristas inter-fase pasan a peso ~0 al aplicar
                f(Dt=3210 s, tau=300) ~ 2e-5, mientras que las intra-fase
                conservan peso casi 1, y Louvain encuentra dos
                comunidades distintas.

Salida por defecto: capturas_temporal/fig_decay_s10_contraste.png
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_decay_temporal import (
    SCENARIO_DEFAULT,
    graph_and_partition,
    synthesize_rows_from_yaml,
)


# Paleta sobria coherente con graficas_temporal.py
COLOR_A = "#0072B2"        # azul - Fase A
COLOR_B = "#D55E00"        # naranja - Fase B
COLOR_UNICO = "#666666"    # gris - comunidad fusionada (sin decay)
COLOR_EDGE_FUERTE = "#444444"
COLOR_EDGE_DEBIL  = "#bbbbbb"


plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor":   "white",
    "axes.edgecolor":   "#444444",
    "axes.labelcolor":  "#222222",
    "axes.titleweight": "bold",
    "axes.titlesize":   13,
    "axes.labelsize":   11,
    "xtick.labelsize":  9,
    "ytick.labelsize":  9,
    "axes.grid":        False,
    "legend.frameon":   False,
    "legend.fontsize":  9,
    "font.family":      "DejaVu Sans",
})


def _node_label(idx, phase, source, etype):
    """Nombre corto para etiquetar el nodo en la figura."""
    short = {
        "user_logged_in":      "login",
        "mail_items_accessed": "mail-acc",
        "new_inbox_rule":      "rule",
        "add_mailbox_full_access": "perm",
        "threat_event":        "threat",
        "traffic_drop":        "drop",
        "traffic_allow":       "allow",
    }.get(str(etype), str(etype)[:6])
    return f"{phase}{idx}: {short}"


def _node_color(phase: str, partition: dict, idx: int, modo: str) -> str:
    """Color del nodo segun comunidad / fase."""
    c = partition.get(idx, -1)
    if modo == "sin_decay":
        # esperamos 1 sola comunidad: gris para todos los nodos
        # (la fusion es lo que queremos enfatizar)
        return COLOR_UNICO if c >= 0 else "#cccccc"
    # modo con_decay: color segun fase si Louvain las separa, gris si no
    if c < 0:
        return "#cccccc"
    return COLOR_A if phase == "A" else COLOR_B


def _draw_graph(ax, G, partition, df, layout, titulo, modo, max_weight):
    # Aristas: grosor proporcional al peso, color en escala fuerte/debil
    if G.number_of_edges() > 0:
        pesos = np.array([d["weight"] for _, _, d in G.edges(data=True)],
                         dtype=float)
        anchos = 0.4 + 3.6 * (pesos / max(max_weight, 1e-12))
        # color: graduacion gris->negro segun peso normalizado
        norm = pesos / max(max_weight, 1e-12)
        edge_colors = [(0.20, 0.20, 0.20, 0.30 + 0.65 * w) for w in norm]
        nx.draw_networkx_edges(
            G, layout, ax=ax,
            width=anchos, edge_color=edge_colors,
        )

    # Nodos por fase y comunidad
    node_colors = [
        _node_color(df.iloc[i]["_phase"], partition, i, modo)
        for i in range(len(df))
    ]
    # Forma: circulos para A, cuadrados para B (cuando son visibles)
    fase = df["_phase"].tolist()
    A_idx = [i for i, p in enumerate(fase) if p == "A"]
    B_idx = [i for i, p in enumerate(fase) if p == "B"]
    nx.draw_networkx_nodes(
        G, layout, ax=ax, nodelist=A_idx,
        node_color=[node_colors[i] for i in A_idx],
        node_shape="o", node_size=900,
        edgecolors="#222222", linewidths=1.2,
    )
    nx.draw_networkx_nodes(
        G, layout, ax=ax, nodelist=B_idx,
        node_color=[node_colors[i] for i in B_idx],
        node_shape="s", node_size=900,
        edgecolors="#222222", linewidths=1.2,
    )

    # Etiquetas en blanco para que se vean sobre los nodos coloreados
    labels = {}
    counters = {"A": 0, "B": 0}
    for i in range(len(df)):
        p = df.iloc[i]["_phase"]
        counters[p] = counters.get(p, 0) + 1
        labels[i] = _node_label(counters[p], p,
                                df.iloc[i].get("_source"),
                                df.iloc[i].get("_type"))
    nx.draw_networkx_labels(
        G, layout, ax=ax, labels=labels,
        font_size=8, font_color="white", font_weight="bold",
    )

    ax.set_title(titulo, pad=12)
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)


def figura_contraste(out_path: Path, scenario_path: Path, tau: float):
    df = synthesize_rows_from_yaml(scenario_path)

    G_none, part_none, _ = graph_and_partition(df, "none", tau=tau)
    G_dec, part_dec, _ = graph_and_partition(df, "exponential", tau=tau)

    n_comm_none = len({v for v in part_none.values() if v >= 0})
    n_comm_dec = len({v for v in part_dec.values() if v >= 0})

    # layout comun a los dos paneles para que la comparacion sea visual
    G_layout = nx.Graph()
    G_layout.add_nodes_from(range(len(df)))
    for u, v in G_none.edges():
        G_layout.add_edge(u, v)
    # spring_layout con semilla fija para reproducibilidad
    layout = nx.spring_layout(G_layout, seed=42, k=1.3,
                              iterations=200, weight=None)

    fig, axes = plt.subplots(1, 2, figsize=(14.5, 7.0))

    max_w = max(
        max((d["weight"] for _, _, d in G_none.edges(data=True)),
            default=1.0),
        max((d["weight"] for _, _, d in G_dec.edges(data=True)),
            default=1.0),
    )

    _draw_graph(
        axes[0], G_none, part_none, df, layout,
        titulo=f"Sin decaimiento (kind=none)\n"
               f"{G_none.number_of_edges()} aristas, "
               f"{n_comm_none} comunidad{'es' if n_comm_none != 1 else ''}",
        modo="sin_decay", max_weight=max_w,
    )

    _draw_graph(
        axes[1], G_dec, part_dec, df, layout,
        titulo=f"Con decaimiento exponencial (tau={tau:g}s)\n"
               f"{G_dec.number_of_edges()} aristas, "
               f"{n_comm_dec} comunidades",
        modo="con_decay", max_weight=max_w,
    )

    fig.suptitle(
        "Efecto del decaimiento temporal sobre el escenario S10\n"
        "Las dos fases comparten unicamente la IP atacante; sin decay "
        "Louvain las fusiona, con decay las separa",
        fontsize=14, weight="bold", y=0.99,
    )

    # Leyenda comun debajo
    from matplotlib.lines import Line2D
    handles = [
        Line2D([0], [0], marker="o", color="w", label="Fase A (O365)",
               markerfacecolor=COLOR_A, markeredgecolor="#222",
               markersize=10),
        Line2D([0], [0], marker="s", color="w", label="Fase B (PaloAlto)",
               markerfacecolor=COLOR_B, markeredgecolor="#222",
               markersize=10),
        Line2D([0], [0], marker="o", color="w",
               label="Misma comunidad (fusion)",
               markerfacecolor=COLOR_UNICO, markeredgecolor="#222",
               markersize=10),
        Line2D([0], [0], color="#222222", linewidth=2.5,
               label="Arista (grosor proporcional al peso)"),
    ]
    fig.legend(handles=handles, loc="lower center", ncol=4,
               bbox_to_anchor=(0.5, 0.005),
               frameon=False)

    fig.tight_layout(rect=(0, 0.05, 1, 0.94))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return {
        "n_filas": len(df),
        "n_aristas_sin": G_none.number_of_edges(),
        "n_aristas_con": G_dec.number_of_edges(),
        "n_comunidades_sin": n_comm_none,
        "n_comunidades_con": n_comm_dec,
        "peso_total_sin": float(sum(d["weight"]
                                    for _, _, d in G_none.edges(data=True))),
        "peso_total_con": float(sum(d["weight"]
                                    for _, _, d in G_dec.edges(data=True))),
    }


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", type=Path, default=SCENARIO_DEFAULT,
                    help="Ruta del YAML del escenario S10.")
    ap.add_argument("--tau", type=float, default=300.0,
                    help="Tau en segundos para el panel con decay "
                         "(default 300).")
    ap.add_argument(
        "--out", type=Path,
        default=Path("capturas_temporal/fig_decay_s10_contraste.png"),
        help="Ruta del PNG de salida.")
    args = ap.parse_args()

    print(f"Generando figura {args.out} (tau={args.tau:g}s) ...")
    info = figura_contraste(args.out, args.scenario, args.tau)
    print(f"  filas={info['n_filas']}  "
          f"sin: {info['n_aristas_sin']} aristas, "
          f"{info['n_comunidades_sin']} comm, "
          f"peso={info['peso_total_sin']:.2f}")
    print(f"  con: {info['n_aristas_con']} aristas, "
          f"{info['n_comunidades_con']} comm, "
          f"peso={info['peso_total_con']:.2f}")
    print(f"Guardada en {args.out}")


if __name__ == "__main__":
    main()
