#!/usr/bin/env python3
"""
generar_graficas.py — Genera las figuras de resultados del TFM.

Lee lab_state/real_alerts_incidents.parquet (salida de la Capa 3) y, si
existe, lab_state/ground_truth.jsonl, y produce un conjunto de figuras
en formato PNG dentro de la carpeta capturas/.

Cada figura esta pensada para insertarse directamente en la memoria.
Los nombres de fichero llevan prefijo numerico para que el orden de
lectura sea estable (fig_01_..., fig_02_..., etc.).

Figuras generadas:
  fig_01_embudo_reduccion        Embudo: alertas -> filas -> clusters -> comunidades
  fig_02_alertas_por_decoder     Barras horizontales: volumen por decoder
  fig_03_tamano_comunidades      Histograma del tamano de las comunidades
  fig_04_clusters_vs_comunidades Dispersion: clusters C2 frente a comunidades C3
  fig_05_top_comunidades         Barras: las mayores comunidades por alertas
  fig_06_actividad_temporal      Linea temporal del volumen de alertas
  fig_07_verificacion_escenarios Barras agrupadas: recall y pureza por escenario
  fig_08_cobertura_entidades     Barras: cobertura de entidades por tipo

Uso:
  python3 generar_graficas.py
  python3 generar_graficas.py --parquet otra/ruta.parquet --out otra_carpeta
"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")  # backend sin display, necesario en servidor
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


# ----------------------------------------------------------------------
# Estilo comun de las figuras
# ----------------------------------------------------------------------
# Paleta sobria, apta para impresion en una memoria academica.
COL_PRIMARY = "#2c5f8a"     # azul
COL_SECONDARY = "#c0504d"   # rojo apagado
COL_ACCENT = "#4f8a5b"      # verde
COL_NEUTRAL = "#8c8c8c"     # gris
COL_LIGHT = "#d9e2ec"       # azul claro
PALETTE = ["#2c5f8a", "#c0504d", "#4f8a5b", "#d9a441",
           "#7d5ba6", "#4a9caf", "#b06a3a", "#8c8c8c"]


def _setup_style():
    plt.rcParams.update({
        "figure.dpi": 150,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
        "font.family": "serif",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "grid.linewidth": 0.6,
    })


def _iter_entities(v):
    if v is None:
        return
    if isinstance(v, (list, tuple, np.ndarray)):
        for x in v:
            if x:
                yield x
    elif isinstance(v, str) and v:
        yield v


def _save(fig, out_dir: Path, name: str):
    path = out_dir / f"{name}.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  generada  {path}")


# ----------------------------------------------------------------------
# Figura 1 — Embudo de reduccion
# ----------------------------------------------------------------------
def fig_embudo_reduccion(df, out_dir):
    n_alertas = int(df["count"].sum())
    n_filas = len(df)
    n_clusters = int(df.loc[df["cluster_id"] != -1, "cluster_id"].nunique())
    n_comm = int(df.loc[df["community_id"] >= 0, "community_id"].nunique())

    etapas = ["Alertas\nWazuh", "Filas tras\ndedup",
              "Clusters\nCapa 2", "Comunidades\nCapa 3"]
    valores = [n_alertas, n_filas, n_clusters, n_comm]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    y = np.arange(len(etapas))[::-1]
    maxv = max(valores)
    for i, (et, val) in enumerate(zip(etapas, valores)):
        yy = y[i]
        ancho = val / maxv
        ax.barh(yy, ancho, height=0.6, color=PALETTE[i],
                edgecolor="white")
        ax.text(ancho + 0.02, yy, f"{val:,}", va="center",
                ha="left", fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(etapas)
    ax.set_xlim(0, 1.15)
    ax.set_xticks([])
    ax.set_title("Embudo de reduccion del volumen de alertas")
    factor = n_alertas / n_comm if n_comm else 0
    ax.text(0.5, -0.18,
            f"Factor de reduccion global: {factor:.1f} a 1  "
            f"({100*(1-n_comm/n_alertas):.2f}% de reduccion)",
            transform=ax.transAxes, ha="center", fontsize=10,
            style="italic", color=COL_NEUTRAL)
    ax.grid(False)
    _save(fig, out_dir, "fig_01_embudo_reduccion")


# ----------------------------------------------------------------------
# Figura 2 — Alertas por decoder
# ----------------------------------------------------------------------
def fig_alertas_por_decoder(df, out_dir):
    vol = df.groupby("decoder.name")["count"].sum().sort_values()
    vol = vol[vol > 0]
    fig, ax = plt.subplots(figsize=(8, max(3.5, 0.4 * len(vol))))
    ax.barh(range(len(vol)), vol.values, color=COL_PRIMARY,
            edgecolor="white", height=0.7)
    ax.set_yticks(range(len(vol)))
    ax.set_yticklabels(vol.index)
    ax.set_xlabel("Alertas originales (suma de count)")
    ax.set_title("Volumen de alertas por decoder")
    total = vol.sum()
    for i, v in enumerate(vol.values):
        ax.text(v + total * 0.01, i, f"{v:,}", va="center",
                fontsize=8, color=COL_NEUTRAL)
    ax.margins(x=0.12)
    _save(fig, out_dir, "fig_02_alertas_por_decoder")


# ----------------------------------------------------------------------
# Figura 3 — Histograma del tamano de las comunidades
# ----------------------------------------------------------------------
def fig_tamano_comunidades(df, out_dir):
    valid = df[df["community_id"] >= 0]
    sizes = valid.groupby("community_id").size()
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    bins = np.logspace(0, np.log10(max(sizes.max(), 2)), 20)
    ax.hist(sizes.values, bins=bins, color=COL_PRIMARY,
            edgecolor="white")
    ax.set_xscale("log")
    ax.set_xlabel("Filas por comunidad (escala logaritmica)")
    ax.set_ylabel("Numero de comunidades")
    ax.set_title("Distribucion del tamano de las comunidades")
    ax.axvline(sizes.median(), color=COL_SECONDARY, linestyle="--",
               linewidth=1.5,
               label=f"mediana = {sizes.median():.0f} filas")
    ax.legend()
    _save(fig, out_dir, "fig_03_tamano_comunidades")


# ----------------------------------------------------------------------
# Figura 4 — Clusters C2 frente a comunidades C3
# ----------------------------------------------------------------------
def fig_clusters_vs_comunidades(df, out_dir):
    valid = df[df["community_id"] >= 0]
    agg = valid.groupby("community_id").agg(
        n_clusters=("cluster_id", "nunique"),
        n_alertas=("count", "sum"),
    )
    fig, ax = plt.subplots(figsize=(7, 5))
    sizes_pts = 20 + 80 * (agg["n_alertas"] / agg["n_alertas"].max())
    ax.scatter(agg["n_clusters"], agg["n_alertas"],
               s=sizes_pts, alpha=0.6, color=COL_PRIMARY,
               edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Clusters de Capa 2 agrupados en la comunidad")
    ax.set_ylabel("Alertas originales absorbidas")
    ax.set_title("Relacion entre clusters de Capa 2 y comunidades de Capa 3")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    _save(fig, out_dir, "fig_04_clusters_vs_comunidades")


# ----------------------------------------------------------------------
# Figura 5 — Top comunidades por alertas
# ----------------------------------------------------------------------
def fig_top_comunidades(df, out_dir, top_n=12):
    valid = df[df["community_id"] >= 0]
    agg = valid.groupby("community_id").agg(
        n_alertas=("count", "sum"),
        n_decoders=("decoder.name", "nunique"),
    ).sort_values("n_alertas", ascending=False).head(top_n)

    fig, ax = plt.subplots(figsize=(8, max(3.5, 0.45 * len(agg))))
    colores = [COL_ACCENT if d > 1 else COL_PRIMARY
               for d in agg["n_decoders"]]
    y = range(len(agg))
    ax.barh(list(y), agg["n_alertas"].values, color=colores,
            edgecolor="white", height=0.7)
    ax.set_yticks(list(y))
    ax.set_yticklabels([f"#{c}" for c in agg.index])
    ax.invert_yaxis()
    ax.set_xlabel("Alertas originales absorbidas")
    ax.set_title(f"Las {len(agg)} comunidades mayores por volumen")
    # leyenda manual
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(color=COL_ACCENT, label="cross-source (>1 decoder)"),
        Patch(color=COL_PRIMARY, label="un solo decoder"),
    ], loc="lower right")
    _save(fig, out_dir, "fig_05_top_comunidades")


# ----------------------------------------------------------------------
# Figura 6 — Actividad temporal
# ----------------------------------------------------------------------
def fig_actividad_temporal(df, out_dir):
    d = df.dropna(subset=["first_seen"]).copy()
    if d.empty:
        print("  (omitida fig_06: sin timestamps)")
        return
    d["minuto"] = d["first_seen"].dt.floor("1min")
    serie = d.groupby("minuto")["count"].sum()
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.fill_between(serie.index, serie.values, color=COL_LIGHT)
    ax.plot(serie.index, serie.values, color=COL_PRIMARY,
            linewidth=1.5)
    ax.set_xlabel("Tiempo")
    ax.set_ylabel("Alertas por minuto")
    ax.set_title("Actividad temporal del volumen de alertas")
    fig.autofmt_xdate()
    _save(fig, out_dir, "fig_06_actividad_temporal")


# ----------------------------------------------------------------------
# Figura 7 — Verificacion de escenarios (recall y pureza)
# ----------------------------------------------------------------------
def _scenario_metrics(df, gt_path):
    """Reproduce el calculo de recall y pureza de verify_scenarios.py
    de forma compacta. Devuelve lista de dicts por escenario."""
    if not gt_path.exists():
        return None
    # entidades discriminantes por escenario base
    by_scn = defaultdict(set)
    with open(gt_path) as f:
        for line in f:
            rec = json.loads(line)
            base = re.sub(r"-[0-9a-f]{6,}$", "", rec["incident_id"])
            for v in (rec.get("entities") or {}).values():
                if isinstance(v, str) and v:
                    by_scn[base].add(v.lower())
            for v in (rec.get("vars") or {}).values():
                if isinstance(v, str) and v and not v.isdigit():
                    by_scn[base].add(v.lower())

    def row_ents(r):
        out = set()
        for col in ("entity_users", "entity_ips", "entity_hosts"):
            for x in _iter_entities(r.get(col)):
                x = str(x).lower()
                for p in ("user:", "ip:", "host:", "asset:"):
                    if x.startswith(p):
                        out.add(x[len(p):])
                out.add(x)
        return out

    df = df.copy()
    df["_e"] = df.apply(row_ents, axis=1)
    res = []
    for scn in sorted(by_scn):
        cands = set()
        for e in by_scn[scn]:
            cands.add(e)
            if "@" in e:
                cands.add(e.split("@")[0])
            if "\\" in e:
                cands.add(e.split("\\")[-1])
        mask = df["_e"].apply(lambda es: bool(es & cands))
        hits = df[mask]
        if hits.empty:
            res.append({"escenario": scn, "recall": 0, "purity": 0})
            continue
        cd = hits[hits["community_id"] >= 0]["community_id"].value_counts()
        if cd.empty:
            res.append({"escenario": scn, "recall": 0, "purity": 0})
            continue
        main = int(cd.index[0])
        n_in = int(cd.iloc[0])
        csize = int((df["community_id"] == main).sum())
        res.append({
            "escenario": scn,
            "recall": n_in / len(hits),
            "purity": n_in / csize if csize else 0,
        })
    return res


def fig_verificacion_escenarios(df, out_dir, gt_path):
    metrics = _scenario_metrics(df, gt_path)
    if not metrics:
        print("  (omitida fig_07: sin ground_truth.jsonl)")
        return
    nombres = [m["escenario"].replace("INC-", "") for m in metrics]
    recall = [m["recall"] for m in metrics]
    purity = [m["purity"] for m in metrics]

    x = np.arange(len(nombres))
    w = 0.36
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    b1 = ax.bar(x - w/2, recall, w, label="Recall",
                color=COL_PRIMARY, edgecolor="white")
    b2 = ax.bar(x + w/2, purity, w, label="Pureza",
                color=COL_ACCENT, edgecolor="white")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.02,
                    f"{b.get_height():.0%}", ha="center", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(nombres)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Proporcion")
    ax.set_title("Verificacion de escenarios: recall y pureza")
    ax.legend()
    ax.grid(axis="x", visible=False)
    _save(fig, out_dir, "fig_07_verificacion_escenarios")


# ----------------------------------------------------------------------
# Figura 8 — Cobertura de entidades
# ----------------------------------------------------------------------
def fig_cobertura_entidades(df, out_dir):
    n = len(df)
    cov = {}
    for col, etq in [("entity_users", "Usuarios"),
                     ("entity_ips", "Direcciones IP"),
                     ("entity_hosts", "Hosts")]:
        con = sum(1 for _, r in df.iterrows()
                  if any(True for _ in _iter_entities(r.get(col))))
        cov[etq] = con / n
    # filas con al menos una entidad de cualquier tipo
    con_alguna = 0
    for _, r in df.iterrows():
        if any(any(True for _ in _iter_entities(r.get(c)))
               for c in ("entity_users", "entity_ips", "entity_hosts")):
            con_alguna += 1
    cov["Alguna entidad"] = con_alguna / n

    fig, ax = plt.subplots(figsize=(7, 4))
    etqs = list(cov.keys())
    vals = [cov[k] for k in etqs]
    colores = [COL_PRIMARY, COL_PRIMARY, COL_PRIMARY, COL_ACCENT]
    bars = ax.bar(etqs, vals, color=colores, edgecolor="white",
                  width=0.6)
    for b in bars:
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.02,
                f"{b.get_height():.0%}", ha="center", fontweight="bold")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Fraccion de filas con la entidad")
    ax.set_title("Cobertura de entidades extraidas por tipo")
    ax.grid(axis="x", visible=False)
    _save(fig, out_dir, "fig_08_cobertura_entidades")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet",
                    default="lab_state/real_alerts_incidents.parquet")
    ap.add_argument("--ground-truth",
                    default="lab_state/ground_truth.jsonl")
    ap.add_argument("--out", default="capturas")
    args = ap.parse_args()

    parquet = Path(args.parquet)
    if not parquet.exists():
        raise SystemExit(f"No existe {parquet}. Corre la Capa 3 primero.")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    _setup_style()
    df = pd.read_parquet(parquet)
    print(f"Cargado {parquet}: {len(df):,} filas")
    print(f"Generando figuras en {out_dir}/ ...\n")

    fig_embudo_reduccion(df, out_dir)
    fig_alertas_por_decoder(df, out_dir)
    fig_tamano_comunidades(df, out_dir)
    fig_clusters_vs_comunidades(df, out_dir)
    fig_top_comunidades(df, out_dir)
    fig_actividad_temporal(df, out_dir)
    fig_verificacion_escenarios(df, out_dir, Path(args.ground_truth))
    fig_cobertura_entidades(df, out_dir)

    print(f"\nListo. Figuras en {out_dir}/")


if __name__ == "__main__":
    main()
