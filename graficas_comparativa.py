#!/usr/bin/env python3
"""
graficas_comparativa.py - Figura de la comparativa de algoritmos de Capa 2.

Lee comparar_clustering.csv (salida de comparar_clustering.py) y produce
una figura en formato PNG con un panel 2x2 para las cuatro metricas que
sustentan la eleccion de HDBSCAN: ARI, V-measure, pureza por escenario
y fraccion de ruido aislado.

Estilo coherente con generar_graficas.py: paleta sobria, serif, sin
spines superiores/derechos, dpi 200. HDBSCAN se resalta con el color
primario; el resto en un gris neutro para que la lectura sea inmediata.
Para K-Means se dibujan barras de error con la desviacion entre semillas
(la unica columna no determinista de la tabla).

Uso:
  python3 graficas_comparativa.py
  python3 graficas_comparativa.py --csv otra.csv --out otra_carpeta
"""
from __future__ import annotations
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


COL_PRIMARY = "#2c5f8a"     # HDBSCAN (resaltado)
COL_NEUTRAL = "#8c8c8c"     # resto de algoritmos
COL_LIGHT = "#d9e2ec"
COL_TEXT = "#333333"


def _setup_style():
    plt.rcParams.update({
        "figure.dpi": 150,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
        "font.family": "serif",
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.labelsize": 9,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "grid.linewidth": 0.6,
    })


def _panel(ax, df, metric, err_col, title, ylabel, fmt="{:.3f}"):
    nombres = df["algoritmo"].tolist()
    valores = df[metric].values
    errores = df[err_col].values if err_col in df.columns else np.zeros(len(df))

    colores = [COL_PRIMARY if n == "HDBSCAN" else COL_NEUTRAL
               for n in nombres]
    x = np.arange(len(nombres))
    bars = ax.bar(x, valores, color=colores, edgecolor="white",
                  width=0.65, yerr=errores, capsize=4,
                  error_kw={"ecolor": COL_TEXT, "elinewidth": 0.8})

    ax.set_xticks(x)
    ax.set_xticklabels(nombres, rotation=0, fontsize=8.5)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    # Margen vertical para que el texto encima no choque con el eje superior.
    margen = max(abs(valores).max(), 1e-3) * 0.18
    y_top = max(valores) + max(errores.max(), 0) + margen
    y_bot = min(0, min(valores) - margen)
    ax.set_ylim(y_bot, y_top)

    # Etiqueta encima de cada barra.
    for rect, val, err in zip(bars, valores, errores):
        label = fmt.format(val)
        if err > 0:
            label += f" ± {fmt.format(err).lstrip('-')}"
        ax.text(rect.get_x() + rect.get_width() / 2,
                val + (err if err > 0 else 0) + margen * 0.15,
                label, ha="center", va="bottom", fontsize=8,
                color=COL_TEXT)


def grafica(csv_path: Path, out_dir: Path):
    _setup_style()

    df = pd.read_csv(csv_path)
    # Fijamos el orden de aparicion en el panel: HDBSCAN primero por ser
    # el resaltado y porque la lectura del PDF empieza por ahi.
    orden = ["HDBSCAN", "DBSCAN", "KMeans", "Agglomerative"]
    df = df.set_index("algoritmo").loc[orden].reset_index()

    # Si frac_ruido_media viene en fraccion, lo pasamos a porcentaje.
    df["ruido_pct"] = df["frac_ruido_media"] * 100.0
    df["ruido_desv_pct"] = 0.0  # ningun algoritmo reporta dispersion en ruido

    fig, axes = plt.subplots(2, 2, figsize=(10, 7))
    fig.suptitle(
        "Comparativa de algoritmos de agrupamiento (Capa 2)",
        fontsize=13, fontweight="bold", y=0.995,
    )

    _panel(axes[0, 0], df, "ari_media", "ari_desv",
           "ARI - concordancia con el ground truth",
           "ARI (mejor = mas alto)")
    _panel(axes[0, 1], df, "v_media", "v_desv",
           "V-measure - homogeneidad x completitud",
           "V-measure (mejor = mas alto)")
    _panel(axes[1, 0], df, "pureza_escenario_media",
           "pureza_escenario_desv",
           "Pureza por escenario - cluster sin contaminacion",
           "Pureza (mejor = mas alto)")
    _panel(axes[1, 1], df, "ruido_pct", "ruido_desv_pct",
           "Fraccion de filas aisladas como ruido",
           "% ruido (solo HDBSCAN/DBSCAN pueden > 0)",
           fmt="{:.1f}%")

    fig.text(
        0.5, -0.02,
        "Fuente: comparar_clustering.csv. K-Means se reporta como media "
        "y desviacion sobre 5 semillas; el resto son deterministas.",
        ha="center", fontsize=8, style="italic", color=COL_NEUTRAL,
    )

    fig.tight_layout(rect=[0, 0, 1, 0.97])

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fig_comparativa_clustering.png"
    fig.savefig(out_path)
    plt.close(fig)
    print(f"generada  {out_path}")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="comparar_clustering.csv")
    ap.add_argument("--out", default="capturas_nuevas")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(
            f"No existe {csv_path}. Corre comparar_clustering.py primero.")
    grafica(csv_path, Path(args.out))


if __name__ == "__main__":
    main()
