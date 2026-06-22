#!/usr/bin/env python3
"""
verify_scenarios.py — Verificacion de los escenarios sinteticos contra
las comunidades producidas por el pipeline.

Cruza `ground_truth.jsonl` (entidades inyectadas por scenario_runner)
con `real_alerts_incidents.parquet` (comunidades de la Capa 3) y
evalua, para cada escenario, si el sistema lo ha consolidado bien.

Metricas
--------
- RECALL: fraccion de las filas del escenario que han caido en su
  comunidad principal. Mide consolidacion.
- PUREZA: fraccion de la comunidad principal que pertenece de verdad
  al escenario. Una comunidad-vertedero tiene pureza muy baja.
- SEPARACION: dos escenarios distintos no pueden compartir comunidad
  principal. Si la comparten, ambos se reportan como FALLO aunque la
  comunidad sea multi-decoder.

La comunidad principal de un escenario es la que contiene MAS filas
suyas, sin sesgo por que sea cross-source. El veredicto final exige
las tres condiciones a la vez.

Uso:
  python3 verify_scenarios.py
  python3 verify_scenarios.py --min-recall 0.30 --min-purity 0.50
"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from anonymization import maybe_load, DEFAULT_MAP_PATH


GT = Path("lab_state/ground_truth.jsonl")
INCIDENTS = Path("lab_state/real_alerts_incidents.parquet")

BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
BLUE = "\033[34m"; CYAN = "\033[36m"
RESET = "\033[0m"


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


# Entidades genericas que no discriminan un escenario.
GENERIC_ENTITIES = {
    "pa-vm300-01", "pa-vm300-02", "host:pa-vm300-01", "host:pa-vm300-02",
    "wazuh-server", "wazuh-manager", "localhost",
    "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255",
    "labcorp.com", "labcorp.local", "vsphere.local",
    "10.252.11.21", "10.252.11.47",
    "", "none", "null", "unknown", "-", "--", "n/a",
    "8.8.8.8", "1.1.1.1",
}


def _is_discriminating(s: str) -> bool:
    """Es la entidad lo bastante especifica para usarla en el matching?"""
    if not s or not isinstance(s, str):
        return False
    s_low = s.lower().strip()
    if s_low in GENERIC_ENTITIES:
        return False
    if s_low.startswith("2026-") or s_low.startswith("2025-"):
        return False
    return True


def load_gt() -> dict:
    """Devuelve dict {incident_id: {base, scenario, entities, n_events,
    sources}}."""
    if not GT.exists():
        raise SystemExit(f"No existe {GT}. Corre primero el scenario_runner.")
    incidents = {}
    with open(GT) as f:
        for line in f:
            rec = json.loads(line)
            iid = rec["incident_id"]
            base = re.sub(r"-[0-9a-f]{6,}$", "", iid)
            if iid not in incidents:
                incidents[iid] = {
                    "base": base,
                    "scenario": rec["scenario"],
                    "entities": set(),
                    "n_events": 0,
                    "sources": set(),
                }
            inc = incidents[iid]
            inc["n_events"] += 1
            inc["sources"].add(rec["source"])
            for v in (rec.get("vars") or {}).values():
                if (isinstance(v, str) and _is_discriminating(v)
                        and not v.isdigit()):
                    inc["entities"].add(v.lower())
            for v in (rec.get("entities") or {}).values():
                if isinstance(v, str) and _is_discriminating(v):
                    inc["entities"].add(v.lower())
    return incidents


def normalize_for_match(s: str, anon=None) -> set:
    """Variantes de un valor de entidad para buscar coincidencias.

    Si `anon` se pasa (UserAnonymizer cargado), anade ademas el alias
    anonimizado correspondiente a cada variante que se parezca a un
    usuario. Esto permite que el matching contra un parquet anonimizado
    funcione: el GT viene con nombres crudos ('tfm.s06.victim1') y el
    parquet con aliases ('user_0042_anonymized'); aqui los unificamos.

    IPs y hosts no se anonimizan y se buscan tal cual.
    """
    out = {s.lower()}
    s2 = s.lower()
    if "@" in s2:
        out.add(s2.split("@")[0])
    if "\\" in s2:
        out.add(s2.split("\\")[-1])
    if anon is not None:
        # `lookup_raw` solo devuelve alias si el canonico esta en el
        # mapa (no auto-registra). Anadimos tanto la forma plana como
        # con prefijo 'user:' porque `collect_alert_entities` mete las
        # dos en el set de cada fila.
        from normalize import norm_ip
        extra = set()
        for v in list(out):
            if norm_ip(v):
                continue  # IP: no se anonimiza
            alias = anon.lookup_raw(v)
            if alias and alias != v:
                extra.add(alias)
                extra.add(f"user:{alias}")
        out |= extra
    return out


def collect_alert_entities(row) -> set:
    """Todas las entidades de una fila del Parquet, en minusculas, con y
    sin prefijo canonico."""
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-recall", type=float, default=0.30,
                    help="recall minimo en la comunidad principal para "
                         "considerar el escenario consolidado")
    ap.add_argument("--min-purity", type=float, default=0.50,
                    help="pureza minima de la comunidad principal para "
                         "no considerarla un vertedero")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="ruta del mapa de anonimizacion para resolver "
                         "entidades del ground_truth contra el parquet "
                         "anonimizado")
    args = ap.parse_args()

    if not INCIDENTS.exists():
        raise SystemExit(f"No existe {INCIDENTS}.")
    df = pd.read_parquet(INCIDENTS)
    gt = load_gt()

    # Si existe un mapa de aliases (extract_indexer lo deja en
    # lab_state/user_alias_map.json), se carga para que el matching del
    # GT contra el parquet anonimizado funcione. Si no existe, se asume
    # que el parquet NO esta anonimizado y el matching va por nombres
    # reales (compatibilidad con runs anteriores a la capa de
    # anonimizacion).
    anon = maybe_load(args.user_alias_map)
    if anon is not None:
        print(f"{DIM}[anon] resolviendo GT con {args.user_alias_map} "
              f"({len(anon.forward)} usuarios){RESET}")

    print(f"\n{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}  VERIFICACION DE ESCENARIOS SINTETICOS{RESET}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}\n")
    print(f"{DIM}Ground truth: {len(gt)} incidente(s) inyectado(s){RESET}")
    print(f"{DIM}Comunidades en pipeline: "
          f"{df[df['community_id'] >= 0]['community_id'].nunique()}{RESET}")
    print(f"{DIM}Umbrales: recall >= {args.min_recall:.0%}, "
          f"pureza >= {args.min_purity:.0%}{RESET}\n")

    # entidades del GT agrupadas por escenario base
    by_scenario = defaultdict(lambda: {"entities": set(), "sources": set(),
                                       "n_events": 0, "name": ""})
    for iid, inc in gt.items():
        bs = inc["base"]
        by_scenario[bs]["name"] = inc["scenario"]
        by_scenario[bs]["entities"].update(inc["entities"])
        by_scenario[bs]["sources"].update(inc["sources"])
        by_scenario[bs]["n_events"] += inc["n_events"]

    df = df.copy()
    df["_ents"] = df.apply(collect_alert_entities, axis=1)

    # marcar, para cada fila, a que escenarios pertenece
    scenario_rows: dict[str, set] = {}
    for scenario_id in sorted(by_scenario):
        info = by_scenario[scenario_id]
        candidates = set()
        for e in info["entities"]:
            candidates.update(normalize_for_match(e, anon=anon))

        def has_overlap(row_ents, cands=candidates):
            return any(c in row_ents for c in cands)

        mask = df["_ents"].apply(has_overlap)
        scenario_rows[scenario_id] = set(df[mask].index)

    summary_rows = []
    main_comm_by_scenario: dict[str, int] = {}

    for scenario_id in sorted(by_scenario):
        info = by_scenario[scenario_id]
        idx = scenario_rows[scenario_id]
        hits = df.loc[sorted(idx)].copy()
        n_hits = len(hits)
        n_alertas_hit = int(hits["count"].sum()) if n_hits else 0

        print(f"{BOLD}{scenario_id}{RESET}  "
              f"{DIM}{info['name'][:52]}{RESET}")
        print(f"  {DIM}fuentes en GT:{RESET}    "
              f"{', '.join(sorted(info['sources']))}")
        print(f"  {DIM}eventos en GT:{RESET}    {info['n_events']}")
        print(f"  filas detectadas:  {BOLD}{n_hits}{RESET}  "
              f"({n_alertas_hit:,} alertas absorbidas)")

        if n_hits == 0:
            print(f"  {RED}x sin filas detectadas{RESET}\n")
            summary_rows.append({
                "escenario": scenario_id, "filas": 0, "alertas": 0,
                "recall": 0.0, "purity": 0.0, "main_comm": None,
                "cross": False, "veredicto": "NO DETECTADO",
            })
            continue

        comm_dist = hits[hits["community_id"] >= 0]["community_id"] \
            .value_counts()
        if comm_dist.empty:
            print(f"  {RED}x filas sin comunidad asignada{RESET}\n")
            summary_rows.append({
                "escenario": scenario_id, "filas": n_hits,
                "alertas": n_alertas_hit, "recall": 0.0, "purity": 0.0,
                "main_comm": None, "cross": False,
                "veredicto": "SIN COMUNIDAD",
            })
            continue

        # Comunidad principal = la que contiene MAS filas del escenario.
        # Sin sesgo cross-source (preferir cross-source haria que
        # comunidades-vertedero ganasen automaticamente).
        main_comm = int(comm_dist.index[0])
        n_in_main = int(comm_dist.iloc[0])
        main_comm_by_scenario[scenario_id] = main_comm

        sub = df[df["community_id"] == main_comm]
        comm_size = len(sub)
        decoders = sorted(set(sub["decoder.name"].dropna().astype(str)))
        is_cross = len(decoders) > 1

        recall = n_in_main / n_hits
        purity = n_in_main / comm_size if comm_size else 0.0

        rec_ok = recall >= args.min_recall
        pur_ok = purity >= args.min_purity

        rc = GREEN if rec_ok else RED
        pc = GREEN if pur_ok else RED
        xc = GREEN if is_cross else YELLOW

        print(f"  comunidad principal: {BOLD}#{main_comm}{RESET} "
              f"({comm_size} filas totales, "
              f"{xc}{'cross-source' if is_cross else 'intra-fuente'}{RESET})")
        print(f"  decoders: [{', '.join(decoders)}]")
        print(f"  {DIM}recall:{RESET}  {rc}{recall:.0%}{RESET} "
              f"({n_in_main}/{n_hits} filas del escenario en la comunidad)")
        print(f"  {DIM}pureza:{RESET}  {pc}{purity:.0%}{RESET} "
              f"({n_in_main}/{comm_size} filas de la comunidad "
              f"son del escenario)")

        other = [(int(c), int(n)) for c, n in comm_dist.items()
                 if int(c) != main_comm]
        if other:
            ostr = ", ".join(f"#{c}({n})" for c, n in other[:6])
            print(f"  {DIM}dispersion en otras comunidades: {ostr}{RESET}")

        summary_rows.append({
            "escenario": scenario_id, "filas": n_hits,
            "alertas": n_alertas_hit, "recall": recall, "purity": purity,
            "main_comm": main_comm, "cross": is_cross,
            "rec_ok": rec_ok, "pur_ok": pur_ok,
        })
        print()

    # comprobacion de SEPARACION entre escenarios
    comm_usage = Counter(v for v in main_comm_by_scenario.values())
    shared = {c for c, n in comm_usage.items() if n > 1}

    print(f"{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}  RESUMEN{RESET}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}{'Escenario':<10} {'Recall':>8} {'Pureza':>8} "
          f"{'ComPrin':>8} {'Cross':>7} {'Veredicto'}{RESET}")
    print("-" * 72)

    n_ok = 0
    for r in summary_rows:
        if r.get("veredicto") in ("NO DETECTADO", "SIN COMUNIDAD"):
            verdict = r["veredicto"]
            vcolor = RED
        else:
            comparte = r["main_comm"] in shared
            if comparte:
                verdict = "FALLO: comunidad compartida"
                vcolor = RED
            elif r["rec_ok"] and r["pur_ok"]:
                verdict = "OK"
                vcolor = GREEN
                n_ok += 1
            elif not r["pur_ok"]:
                verdict = "DEBIL: pureza baja"
                vcolor = YELLOW
            else:
                verdict = "DEBIL: recall bajo"
                vcolor = YELLOW
        rec = f"{r['recall']:.0%}" if r["filas"] else "-"
        pur = f"{r['purity']:.0%}" if r["filas"] else "-"
        cm = f"#{r['main_comm']}" if r["main_comm"] is not None else "-"
        cross = ("si" if r["cross"] else "no") if r["filas"] else "-"
        print(f"{r['escenario']:<10} {rec:>8} {pur:>8} {cm:>8} "
              f"{cross:>7} {vcolor}{verdict}{RESET}")

    print()
    if shared:
        print(f"{RED}! Comunidades compartidas por varios escenarios: "
              f"{', '.join('#'+str(c) for c in sorted(shared))}{RESET}")
        print(f"{RED}  El sistema NO ha separado esos escenarios en "
              f"incidentes distintos.{RESET}")
    else:
        print(f"{GREEN}OK Cada escenario cae en una comunidad principal "
              f"distinta (separacion correcta).{RESET}")

    n_total = len(summary_rows)
    color = GREEN if n_ok == n_total else (YELLOW if n_ok else RED)
    print(f"\n{BOLD}Escenarios consolidados correctamente: "
          f"{color}{n_ok}/{n_total}{RESET}")
    print(f"{DIM}(OK exige: recall >= {args.min_recall:.0%}, "
          f"pureza >= {args.min_purity:.0%} y comunidad principal "
          f"no compartida){RESET}\n")


if __name__ == "__main__":
    main()
