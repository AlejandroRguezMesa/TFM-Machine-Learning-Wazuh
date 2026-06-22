#!/usr/bin/env python3
"""
demo_decay_temporal.py - Demostracion controlada del decaimiento temporal
de la Capa 3 sobre el escenario S10.

Que hace
--------
1) Carga el escenario S10 (`scenarios/s10_temporal_decay_validation.yaml`)
   y sintetiza directamente las filas que el pipeline produciria tras la
   deduplicacion. Cada evento del YAML se traduce en una fila con:
     - first_seen / last_seen derivados de t_offset (y del span de los
       `repeat` si los hay),
     - entity_users / entity_ips / entity_hosts: el conjunto canonico
       que el pipeline mantendria tras `normalize.py` y tras descartar
       infraestructura conocida (firewalls, IP hardcodeada del generador
       de PaloAlto, etc.).

2) Construye DOS veces el grafo de filas usando `build_row_graph` de
   `graph_layer_real`:
     - sin decaimiento  (--decay-kind none)
     - con decaimiento exponencial, tau configurable (300 s por defecto)

3) Aplica Louvain (`detect_communities`) y la consolidacion estandar
   (`consolidate_small`) en ambos casos, igual que el pipeline.

4) Reporta: numero de comunidades, asignacion de las filas de cada fase,
   y resultado de la prueba (mismo cluster vs. cluster distinto).

Modos
-----
  .venv/bin/python demo_decay_temporal.py
      Sintesis directa del YAML (no requiere Wazuh ni pipeline). Es el
      modo recomendado para reproducir la prueba en cualquier maquina.

  .venv/bin/python demo_decay_temporal.py --tau 60
      Mismo modo, con un tau distinto.

  .venv/bin/python demo_decay_temporal.py --from-pipeline
      Lee `lab_state/real_alerts_clustered.parquet` despues de haber
      lanzado el escenario S10 con `scenario_runner.py` y haber corrido
      `cluster_real.py`. Filtra a las filas que tocan entidades de S10
      y aplica el mismo procedimiento.

  .venv/bin/python demo_decay_temporal.py --parquet ruta.parquet
      Variante del anterior con ruta de parquet arbitraria.

Salida
------
Devuelve codigo 0 si la prueba se ha demostrado (sin decay -> 1 comunidad
que contiene a ambas fases; con decay -> 2 comunidades, cada fase en una).
Devuelve codigo 1 con explicacion en stdout si no se demuestra. NO se
ajustan los datos para forzar el resultado: si falla, falla.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bridge_filter import is_infrastructure
from graph_layer_real import (
    build_row_entities,
    build_row_graph,
    consolidate_small,
    detect_communities,
    filter_promiscuous_entities,
)


SCENARIO_DEFAULT = Path("scenarios/s10_temporal_decay_validation.yaml")
PARQUET_DEFAULT = Path("lab_state/real_alerts_clustered.parquet")


# ---------------------------------------------------------------------------
# Sintesis de filas a partir del YAML
# ---------------------------------------------------------------------------

# Cada par (source, type) declara que entidades CANONICAS quedarian en la
# fila tras `normalize.py` y `bridge_filter.is_infrastructure`. Es decir,
# replicamos AQUI el efecto neto del pipeline, no la salida cruda de los
# generadores. La razon es doble: (i) no necesitamos un Wazuh corriendo
# para reproducir la demo, (ii) si manana cambian los generadores, el
# demo sigue siendo valido siempre que la asuncion de entidades canonicas
# se mantenga.
def _o365_user_entities(vars_resolved: dict) -> list[str]:
    out: list[str] = []
    u = vars_resolved.get("user_id")
    if isinstance(u, str) and u:
        s = u.lower()
        if "@" in s:
            s = s.split("@")[0]
        out.append(f"user:{s}")
    return out


def _o365_ip_entities(vars_resolved: dict) -> list[str]:
    ip = vars_resolved.get("client_ip")
    if isinstance(ip, str) and ip:
        e = f"ip:{ip}"
        if not is_infrastructure(e):
            return [e]
    return []


def _paloalto_traffic_ips(vars_resolved: dict) -> list[str]:
    """TrafficEvent: src_ip y dst_ip se usan literalmente en el log."""
    out: list[str] = []
    for k in ("src_ip", "dst_ip"):
        v = vars_resolved.get(k)
        if isinstance(v, str) and v:
            e = f"ip:{v}"
            if not is_infrastructure(e):
                out.append(e)
    return out


def _paloalto_threat_ips(vars_resolved: dict) -> list[str]:
    """ThreatEvent: el destino REAL en el log esta hardcodeado a
    18.197.147.66 (ver generators/palo_alto.py); el dst_ip del YAML
    aparece como cadena dentro del URL, NO como direccion IP en los
    campos data.source_address / data.destination_address. Por tanto,
    tras normalize.py la unica entidad util es src_ip."""
    v = vars_resolved.get("src_ip")
    if isinstance(v, str) and v:
        e = f"ip:{v}"
        if not is_infrastructure(e):
            return [e]
    return []


# decoder.name que el pipeline asocia a cada fuente del runner
DECODER_MAP = {
    "office365": "json",       # office365 entra como json puro
    "paloalto":  "paloalto",
    "vcenter":   "vcenter",
    "sentinelone_threats":   "json",
    "sentinelone_activity":  "json",
    "sentinelone_device":    "json",
}


# (source, type) -> funciones que devuelven (users, ips, hosts)
ENTITY_BUILDERS = {
    ("office365", "user_logged_in"):
        lambda v: (_o365_user_entities(v), _o365_ip_entities(v), []),
    ("office365", "mail_items_accessed"):
        lambda v: (_o365_user_entities(v), _o365_ip_entities(v), []),
    ("office365", "new_inbox_rule"):
        lambda v: (_o365_user_entities(v), _o365_ip_entities(v), []),
    ("office365", "add_mailbox_full_access"):
        lambda v: (_o365_user_entities(v), [], []),
    ("office365", "phishing_detected"):
        lambda v: ([], [], []),
    ("paloalto", "traffic_drop"):
        lambda v: ([], _paloalto_traffic_ips(v), []),
    ("paloalto", "traffic_allow"):
        lambda v: ([], _paloalto_traffic_ips(v), []),
    ("paloalto", "threat_event"):
        lambda v: ([], _paloalto_threat_ips(v), []),
}


def _resolve(vars_dict: dict, entities: dict) -> dict:
    """Resolucion minima de {{ entity }} en los `vars` del YAML.
    No hace falta soportar {{ randint(...) }} para la sintesis."""
    out = {}
    for k, v in vars_dict.items():
        if isinstance(v, str):
            for name, val in entities.items():
                v = v.replace("{{ " + name + " }}", str(val))
                v = v.replace("{{" + name + "}}", str(val))
        out[k] = v
    return out


def synthesize_rows_from_yaml(
    yaml_path: Path,
    base_time: datetime | None = None,
    time_scale: float = 1.0,
) -> pd.DataFrame:
    """Crea un DataFrame con una fila por evento del YAML.

    Cada evento (con o sin `repeat`) se convierte en UNA sola fila, igual
    que haria la deduplicacion del pipeline al colapsar alertas
    practicamente identicas: first_seen es la primera ocurrencia y
    last_seen la ultima.
    """
    sc = yaml.safe_load(yaml_path.read_text())
    entities = sc.get("entities", {})
    base = base_time or datetime.now(timezone.utc).replace(microsecond=0)

    rows = []
    for ev in sc["events"]:
        key = (ev["source"], ev["type"])
        if key not in ENTITY_BUILDERS:
            print(f"[demo][WARN] sin builder de entidades para {key}; "
                  f"saltando", file=sys.stderr)
            continue
        vars_r = _resolve(ev.get("vars", {}), entities)
        users, ips, hosts = ENTITY_BUILDERS[key](vars_r)
        repeat = int(ev.get("repeat", 1))
        ri = float(ev.get("repeat_interval", 0))
        t0 = float(ev["t_offset"]) * time_scale
        t1 = t0 + max(0, repeat - 1) * ri * time_scale
        first_seen = base + timedelta(seconds=t0)
        last_seen = base + timedelta(seconds=t1)
        rows.append({
            "decoder.name": DECODER_MAP.get(ev["source"], ev["source"]),
            "rule.id":      "synthetic",
            "rule.level":   3,
            "first_seen":   first_seen,
            "last_seen":    last_seen,
            "timestamp":    first_seen,
            "count":        repeat,
            "entity_users": np.array(users, dtype=object),
            "entity_ips":   np.array(ips, dtype=object),
            "entity_hosts": np.array(hosts, dtype=object),
            # metadatos utiles para identificar la fase
            "_source":  ev["source"],
            "_type":    ev["type"],
            "_t_offset": float(ev["t_offset"]),
            "_phase":   "A" if float(ev["t_offset"]) < 1000 else "B",
        })

    df = pd.DataFrame(rows).reset_index(drop=True)
    # Dejamos la serie en su precision natural; graph_layer_real
    # (`_series_to_seconds`) detecta la unidad de datetime64.
    df["first_seen"] = pd.to_datetime(df["first_seen"], utc=True)
    df["last_seen"]  = pd.to_datetime(df["last_seen"], utc=True)
    return df


# ---------------------------------------------------------------------------
# Carga desde parquet del pipeline (modo --from-pipeline / --parquet)
# ---------------------------------------------------------------------------

S10_USER_KEY = "tfm.s10.victima_a"
S10_ATTACKER_IP = "89.248.165.30"
S10_C2_IPS = {"109.248.205.140", "217.78.205.220"}


def _row_entities_str(row) -> set[str]:
    out: set[str] = set()
    for col in ("entity_users", "entity_ips", "entity_hosts"):
        v = row.get(col)
        if v is None:
            continue
        if isinstance(v, (list, tuple, np.ndarray)):
            for x in v:
                if x:
                    out.add(str(x).lower())
        elif isinstance(v, str) and v:
            out.add(v.lower())
    return out


def _phase_of_pipeline_row(ents: set[str]) -> str | None:
    """Asigna fase a una fila del parquet del pipeline mirando que
    entidades de S10 contiene.
      - Fase A: contiene al usuario victima de S10
      - Fase B: contiene una IP de C2 de S10
      - Si solo aparece la IP puente y nada mas de S10: ambigua (None)
    Las filas que no toquen ninguna entidad de S10 se descartan.
    """
    has_user_a = any(S10_USER_KEY in e for e in ents)
    has_c2 = any(c in e for e in ents for c in S10_C2_IPS)
    if has_user_a and not has_c2:
        return "A"
    if has_c2 and not has_user_a:
        return "B"
    if has_user_a and has_c2:
        return "A"  # caso raro, no deberia pasar; lo marcamos A
    has_attacker = any(S10_ATTACKER_IP in e for e in ents)
    if has_attacker:
        # la IP puente sin ningun otro marker de S10 no nos basta para
        # decidir la fase: lo dejamos como None y se reporta aparte
        return None
    return None  # fila ajena a S10


def load_rows_from_parquet(parquet_path: Path) -> pd.DataFrame:
    """Carga el parquet del pipeline y filtra a las filas que tocan al
    menos una entidad de S10. Anade la columna `_phase`."""
    if not parquet_path.exists():
        raise SystemExit(f"No existe {parquet_path}. Ejecuta primero el "
                         f"pipeline tras lanzar S10.")
    df = pd.read_parquet(parquet_path).reset_index(drop=True)
    # filtramos por entidades S10
    is_s10 = []
    phases: list[str | None] = []
    for _, r in df.iterrows():
        ents = _row_entities_str(r)
        relevant = (
            any(S10_USER_KEY in e for e in ents)
            or any(c in e for e in ents for c in S10_C2_IPS)
            or any(S10_ATTACKER_IP in e for e in ents)
        )
        is_s10.append(relevant)
        phases.append(_phase_of_pipeline_row(ents))
    sub = df.loc[is_s10].copy().reset_index(drop=True)
    if len(sub) == 0:
        # No hay filas de S10 todavia: devolvemos un DataFrame vacio con
        # las columnas esperadas para que `main` reporte error claro.
        sub["_phase"] = pd.Series([], dtype=object)
        sub["_t_offset"] = pd.Series([], dtype=float)
        sub["_source"] = pd.Series([], dtype=object)
        sub["_type"] = pd.Series([], dtype=object)
        return sub
    sub["_phase"] = [p for p, keep in zip(phases, is_s10) if keep]
    # Dejamos las series en su precision natural; el divisor se elige
    # dinamicamente en graph_layer_real._series_to_seconds. Para el
    # offset relativo lo calculamos con segundos derivados del propio
    # timestamp (independiente de la unidad subyacente).
    sub["first_seen"] = pd.to_datetime(sub["first_seen"], utc=True)
    sub["last_seen"] = pd.to_datetime(sub["last_seen"], utc=True)
    t_seconds = (sub["first_seen"] - sub["first_seen"].min()
                 ).dt.total_seconds().to_numpy()
    sub["_t_offset"] = t_seconds
    sub["_source"] = sub.get("decoder.name", pd.Series([""] * len(sub)))
    sub["_type"] = pd.Series([""] * len(sub))
    return sub


# ---------------------------------------------------------------------------
# Construccion del grafo y prueba
# ---------------------------------------------------------------------------

def graph_and_partition(df: pd.DataFrame, decay_kind: str, tau: float,
                        min_shared: int = 1, min_weight: float = 0.0,
                        min_comm_size: int = 3, consolidar: bool = True,
                        promiscuous_filter: bool = False,
                        max_rows_frac: float = 0.10,
                        max_decoders: int = 4):
    """Construye row_ents, aplica build_row_graph con/sin decay, Louvain
    y consolidacion. Devuelve (G, partition, row_ents).

    `promiscuous_filter` esta DESACTIVADO por defecto porque sobre un
    subconjunto pequeno y focalizado (las ~9 filas de S10) el filtro de
    entidades promiscuas, calibrado para datasets de miles de filas,
    descartaria de inmediato la IP puente (presente en el 100% de las
    filas) y la prueba no tendria sentido. Cuando el demo se ejecuta
    sobre la salida completa del pipeline (modo --from-pipeline con todo
    el parquet), el filtro vuelve a ser util y se puede activar.
    El filtro de infraestructura (`is_infrastructure`) se aplica siempre
    desde `build_row_entities` y NO depende de esta bandera.
    """
    row_ents = build_row_entities(df, amap=None)
    if promiscuous_filter:
        decoders = df["decoder.name"].astype(str).tolist() \
            if "decoder.name" in df.columns else None
        row_ents, _ = filter_promiscuous_entities(
            row_ents, max_rows_frac=max_rows_frac,
            max_decoders=max_decoders, decoders=decoders, verbose=False)
    G = build_row_graph(
        row_ents, min_shared, min_weight,
        first_seen=df["first_seen"], last_seen=df["last_seen"],
        decay_kind=decay_kind, decay_tau=tau, decay_hard_cutoff=None,
    )
    part = detect_communities(G, row_ents)
    if consolidar:
        part = consolidate_small(df, part, row_ents, min_size=min_comm_size)
    return G, part, row_ents


def partition_summary(df: pd.DataFrame, partition: dict) -> dict:
    """Mapeo {fase: {comunidad: numero de filas}}. -1 = ruido / aislado."""
    summary: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for i in range(len(df)):
        phase = df.iloc[i]["_phase"]
        c = partition.get(i, -1)
        key = phase if phase in ("A", "B") else "?"
        summary[key][c] += 1
    return {k: dict(v) for k, v in summary.items()}


def phases_in_same_comm(summary: dict) -> bool:
    """True si Fase A y Fase B comparten alguna comunidad (>=0)."""
    a_comms = {c for c, n in summary.get("A", {}).items() if c >= 0 and n > 0}
    b_comms = {c for c, n in summary.get("B", {}).items() if c >= 0 and n > 0}
    return bool(a_comms & b_comms)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_summary(label: str, G, partition: dict, df: pd.DataFrame) -> dict:
    n_comm = len({v for v in partition.values() if v >= 0})
    print(f"\n[{label}]")
    print(f"  aristas={G.number_of_edges():,}  "
          f"peso_total={sum(d['weight'] for _,_,d in G.edges(data=True)):.3f}  "
          f"comunidades(>=0)={n_comm}")
    summary = partition_summary(df, partition)
    for ph in ("A", "B"):
        if ph in summary:
            parts = ", ".join(
                f"c{c}={n}" if c >= 0 else f"ruido={n}"
                for c, n in sorted(summary[ph].items()))
            print(f"  Fase {ph}: {sum(summary[ph].values())} filas -> "
                  f"{parts}")
    if "?" in summary:
        parts = ", ".join(f"c{c}={n}" for c, n in sorted(summary['?'].items()))
        print(f"  fase ambigua: {parts}")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", type=Path, default=SCENARIO_DEFAULT,
                    help="Ruta del YAML del escenario (modo sintesis).")
    ap.add_argument("--from-pipeline", action="store_true",
                    help="Lee lab_state/real_alerts_clustered.parquet en "
                         "lugar de sintetizar.")
    ap.add_argument("--parquet", type=Path, default=None,
                    help="Ruta de parquet arbitraria (implica modo "
                         "pipeline).")
    ap.add_argument("--tau", type=float, default=300.0,
                    help="Escala temporal tau en segundos (default 300).")
    ap.add_argument("--decay-kind", default="exponential",
                    choices=("exponential", "gaussian", "linear", "power",
                             "none"),
                    help="Familia del decaimiento (default exponential).")
    ap.add_argument("--min-comm-size", type=int, default=3,
                    help="Umbral de consolidacion (default 3).")
    ap.add_argument("--no-consolidate", action="store_true",
                    help="Desactiva la consolidacion (no se recomienda).")
    ap.add_argument("--save-json", type=Path, default=None,
                    help="Si se indica, guarda el resultado en un JSON con "
                         "los conteos por fase y por comunidad.")
    args = ap.parse_args()

    print("=" * 72)
    print("  DEMO: efecto del decaimiento temporal de la Capa 3 (S10)")
    print("=" * 72)

    if args.parquet or args.from_pipeline:
        parquet = args.parquet or PARQUET_DEFAULT
        print(f"Modo: pipeline (parquet={parquet})")
        df = load_rows_from_parquet(parquet)
        if len(df) == 0:
            print("ERROR: 0 filas tocan entidades de S10. Verifica que has "
                  "lanzado el escenario y reprocesado el parquet.",
                  file=sys.stderr)
            return 2
    else:
        print(f"Modo: sintesis desde YAML ({args.scenario})")
        df = synthesize_rows_from_yaml(args.scenario)

    n_a = int((df["_phase"] == "A").sum())
    n_b = int((df["_phase"] == "B").sum())
    n_q = int((df["_phase"].isna() | (df["_phase"] == "?")).sum()) \
        if df["_phase"].dtype == object else 0
    print(f"Filas cargadas: {len(df)}   Fase A: {n_a}   Fase B: {n_b}"
          + (f"   ambiguas: {n_q}" if n_q else ""))
    if n_a == 0 or n_b == 0:
        print("ERROR: alguna fase no tiene filas; la prueba no es valida.",
              file=sys.stderr)
        return 2

    # --- SIN DECAY ---
    G_none, part_none, _ = graph_and_partition(
        df, "none", tau=args.tau,
        min_comm_size=args.min_comm_size,
        consolidar=not args.no_consolidate,
    )
    sum_none = _print_summary(f"SIN decay (kind=none)",
                              G_none, part_none, df)
    same_none = phases_in_same_comm(sum_none)

    # --- CON DECAY ---
    G_dec, part_dec, _ = graph_and_partition(
        df, args.decay_kind, tau=args.tau,
        min_comm_size=args.min_comm_size,
        consolidar=not args.no_consolidate,
    )
    sum_dec = _print_summary(
        f"CON decay (kind={args.decay_kind}, tau={args.tau}s)",
        G_dec, part_dec, df)
    same_dec = phases_in_same_comm(sum_dec)

    # --- VEREDICTO ---
    print("\n" + "=" * 72)
    print("  VEREDICTO")
    print("=" * 72)
    print(f"  Sin decay  : fases en la MISMA comunidad ? {same_none}")
    print(f"  Con decay  : fases en la MISMA comunidad ? {same_dec}")
    n_comm_none = len({v for v in part_none.values() if v >= 0})
    n_comm_dec  = len({v for v in part_dec.values() if v >= 0})
    print(f"  Comunidades: sin decay = {n_comm_none}   "
          f"con decay = {n_comm_dec}")

    demostrado = same_none and not same_dec
    if demostrado:
        print("\n  OK -> el decaimiento temporal SEPARA las dos fases "
              "que comparten IP.")
        rc = 0
    else:
        print("\n  NO demostrado:")
        if not same_none:
            print("    * Sin decay las dos fases ya estaban en comunidades "
                  "distintas (no hay nada que separar).")
        if same_dec:
            print("    * Con decay las dos fases siguen en la misma "
                  "comunidad (tau insuficiente o gap insuficiente).")
        rc = 1

    if args.save_json:
        out = {
            "tau": args.tau,
            "decay_kind": args.decay_kind,
            "n_filas": len(df),
            "n_fase_A": n_a,
            "n_fase_B": n_b,
            "sin_decay": {
                "n_aristas": G_none.number_of_edges(),
                "n_comunidades": n_comm_none,
                "fases_en_misma_comunidad": same_none,
                "summary": sum_none,
            },
            "con_decay": {
                "n_aristas": G_dec.number_of_edges(),
                "n_comunidades": n_comm_dec,
                "fases_en_misma_comunidad": same_dec,
                "summary": sum_dec,
            },
            "demostrado": demostrado,
        }
        args.save_json.write_text(json.dumps(out, indent=2, default=str))
        print(f"\nResultado JSON guardado en {args.save_json}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
