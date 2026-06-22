#!/usr/bin/env python3
"""
comparar_decay_AB.py — Comparativa pareada A vs B de la configuracion de
decaimiento temporal de la Capa 3, sobre EL MISMO conjunto de datos.

Por que pareada
---------------
La pregunta a responder es si la configuracion B (decay activo en su
"sweet spot": min_weight=0, decay exponencial tau=60) mejora respecto a
la A (baseline: decay desactivado) de forma consistente, o si la mejora
observada en una corrida (S07 pureza 77% -> 100%) fue casualidad del
muestreo.

La unica forma honesta de aislar el efecto de la configuracion es
comparar A y B sobre EL MISMO real_alerts_clustered.parquet: asi las
fases 1-6 del pipeline (inyeccion, escenarios, extraccion, Capa 2) son
identicas, y lo unico que cambia es la Capa 3. Repetir esto sobre
varios datasets (varias corridas del pipeline) permite ver si B gana de
forma estable o solo a veces.

Que hace
--------
Para el real_alerts_clustered.parquet actual de lab_state/:
  1. Ejecuta graph_layer_real.py con la config A y luego verify_scenarios.py.
  2. Ejecuta graph_layer_real.py con la config B y luego verify_scenarios.py.
  3. Parsea el recall/pureza por escenario y el veredicto N/4 de cada uno.
  4. Imprime una fila comparativa y la anexa a un CSV acumulativo.

IMPORTANTE: no modifica el pipeline ni run_seguimiento2.sh. Solo invoca
graph_layer_real.py (que reconstruye lab_state/real_alerts_incidents.parquet
en cada pasada) y verify_scenarios.py, igual que lo harias a mano.

Como se usa en una campana de varios runs
-----------------------------------------
  # tras CADA corrida del pipeline (que deja un clustered.parquet nuevo):
  .venv/bin/python comparar_decay_AB.py --run-label run1
  # ...relanzar run_seguimiento2.sh para tener datos nuevos...
  .venv/bin/python comparar_decay_AB.py --run-label run2
  # etc. El CSV va acumulando filas; al final se leen todas juntas.

Al terminar, deja lab_state/real_alerts_incidents.parquet reconstruido
con la config que se indique en --restore (por defecto A, el baseline
4/4), para no dejar el estado en una config a medias.
"""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd

VENV_PY = sys.executable  # el mismo interprete con el que se lanza este script

# Configuraciones a comparar. Cada una es la lista de flags que se pasan a
# graph_layer_real.py. Los parametros estructurales (min-shared, max-rows-frac,
# max-decoders, min-comm-size) son IGUALES en ambas: solo cambia el decay.
COMUN = ["--min-shared", "1", "--max-rows-frac", "0.10",
         "--max-decoders", "4", "--min-comm-size", "3"]

CONFIGS = {
    "A_baseline": COMUN + ["--min-weight", "1.0", "--decay-kind", "none"],
    "B_sweetspot": COMUN + ["--min-weight", "0.0",
                            "--decay-kind", "exponential",
                            "--decay-tau", "60"],
}

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd):
    """Ejecuta un comando y devuelve (returncode, stdout+stderr sin ANSI)."""
    res = subprocess.run(cmd, capture_output=True, text=True)
    out = ANSI.sub("", res.stdout + res.stderr)
    return res.returncode, out


def correr_capa3(config_flags):
    """Reconstruye lab_state/real_alerts_incidents.parquet con la config dada."""
    cmd = [VENV_PY, "graph_layer_real.py"] + config_flags
    rc, out = _run(cmd)
    if rc != 0:
        raise RuntimeError(f"graph_layer_real fallo:\n{out[-1500:]}")
    # extraer nº de comunidades y factor, si estan en la salida
    n_comm = _buscar_int(out, r"Comunidades tras consolidacion:\s*(\d+)")
    if n_comm is None:
        n_comm = _buscar_int(out, r"comunidades:\s*(\d+)")
    factor = _buscar_float(out, r"Reduccion total.*?:\s*([\d.]+)")
    return n_comm, factor


def correr_verificador():
    """Ejecuta verify_scenarios.py y parsea su salida."""
    rc, out = _run([VENV_PY, "verify_scenarios.py"])
    # rc del verificador puede no ser 0 si no todos consolidan; no abortamos
    return parse_verificador(out)


def _buscar_int(texto, patron):
    m = re.search(patron, texto)
    return int(m.group(1)) if m else None


def _buscar_float(texto, patron):
    m = re.search(patron, texto)
    return float(m.group(1)) if m else None


def parse_verificador(out):
    """Extrae recall/pureza por escenario y el N/M final de la salida del
    verificador. Devuelve un dict."""
    resultado = {"escenarios": {}, "n_ok": None, "n_total": None,
                 "raw_tail": out[-400:]}

    # filas de la tabla resumen: "INC-S06   60%   100%   #126   si  OK"
    # (los % y el veredicto). El nombre de escenario empieza por INC-
    for linea in out.splitlines():
        m = re.match(
            r"\s*(INC-S\d+)\s+(\d+%|-)\s+(\d+%|-)\s+(\S+)\s+(\S+)\s+(.+?)\s*$",
            linea)
        if m:
            scn, rec, pur, comm, cross, verd = m.groups()
            resultado["escenarios"][scn] = {
                "recall": rec, "pureza": pur,
                "com": comm, "cross": cross,
                "veredicto": verd.strip(),
            }

    # linea final: "Escenarios consolidados correctamente: 4/4"
    m = re.search(r"consolidados correctamente:\s*(\d+)/(\d+)", out)
    if m:
        resultado["n_ok"] = int(m.group(1))
        resultado["n_total"] = int(m.group(2))
    return resultado


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-label", default="run",
                    help="etiqueta para identificar esta corrida en el CSV")
    ap.add_argument("--csv", default="comparar_decay_AB.csv",
                    help="CSV acumulativo (se anexa, no se sobreescribe)")
    ap.add_argument("--restore", choices=["A_baseline", "B_sweetspot", "none"],
                    default="A_baseline",
                    help="con que config dejar reconstruido el parquet al "
                         "terminar (default: A, el baseline 4/4)")
    args = ap.parse_args()

    clustered = Path("lab_state/real_alerts_clustered.parquet")
    if not clustered.exists():
        raise SystemExit(
            f"No existe {clustered}. Corre el pipeline (al menos hasta la "
            "Capa 2) antes de comparar.")

    print(f"Comparativa pareada A vs B — etiqueta: {args.run_label}")
    print(f"Datos: {clustered} (mismo para A y B)\n")

    filas = []
    resultados = {}
    for nombre, flags in CONFIGS.items():
        print(f"  [{nombre}] reconstruyendo Capa 3 ...", end=" ", flush=True)
        n_comm, factor = correr_capa3(flags)
        verif = correr_verificador()
        resultados[nombre] = verif
        n_ok = verif["n_ok"]
        n_total = verif["n_total"]
        print(f"comunidades={n_comm} factor={factor} "
              f"veredicto={n_ok}/{n_total}")
        for scn, d in sorted(verif["escenarios"].items()):
            print(f"       {scn}: recall={d['recall']} pureza={d['pureza']} "
                  f"({d['veredicto']})")
        # construir fila CSV (una por config)
        fila = {"run": args.run_label, "config": nombre,
                "comunidades": n_comm, "factor": factor,
                "consolidados": f"{n_ok}/{n_total}"}
        for scn, d in verif["escenarios"].items():
            fila[f"{scn}_recall"] = d["recall"]
            fila[f"{scn}_pureza"] = d["pureza"]
            fila[f"{scn}_veredicto"] = d["veredicto"]
        filas.append(fila)
        print()

    # comparacion directa A vs B
    print("  " + "=" * 60)
    a, b = resultados["A_baseline"], resultados["B_sweetspot"]
    print(f"  A consolida {a['n_ok']}/{a['n_total']}   "
          f"B consolida {b['n_ok']}/{b['n_total']}")
    for scn in sorted(set(a["escenarios"]) | set(b["escenarios"])):
        ra = a["escenarios"].get(scn, {})
        rb = b["escenarios"].get(scn, {})
        marca = ""
        # marcar si la pureza cambia entre A y B
        if ra.get("pureza") != rb.get("pureza"):
            marca = "  <-- pureza cambia"
        elif ra.get("recall") != rb.get("recall"):
            marca = "  <-- recall cambia"
        print(f"    {scn}:  A[r={ra.get('recall','?')} "
              f"p={ra.get('pureza','?')}]   "
              f"B[r={rb.get('recall','?')} p={rb.get('pureza','?')}]{marca}")
    print("  " + "=" * 60)

    # anexar al CSV acumulativo
    csv_path = Path(args.csv)
    df_nuevo = pd.DataFrame(filas)
    if csv_path.exists():
        df_prev = pd.read_csv(csv_path)
        df_total = pd.concat([df_prev, df_nuevo], ignore_index=True)
    else:
        df_total = df_nuevo
    df_total.to_csv(csv_path, index=False)
    print(f"\n  Resultados anexados a {csv_path} "
          f"({len(df_total)} filas acumuladas).")

    # restaurar el parquet con la config elegida
    if args.restore != "none":
        print(f"\n  Restaurando lab_state con config {args.restore} ...",
              end=" ", flush=True)
        correr_capa3(CONFIGS[args.restore])
        print("hecho.")
        print(f"  (lab_state/real_alerts_incidents.parquet queda en "
              f"{args.restore})")


if __name__ == "__main__":
    main()
