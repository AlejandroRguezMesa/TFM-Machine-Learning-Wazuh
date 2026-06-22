#!/usr/bin/env python3
"""
push_to_indexer.py — Sube los resultados del pipeline al Wazuh Indexer.

Genera DOS índices nuevos:

  wazuh-correlation-alerts-YYYY.MM.DD
    Una fila por alerta agregada (post-dedup), enriquecida con:
      - cluster_id (Capa 2)
      - community_id (Capa 3)
      - entity_users / entity_ips / entity_hosts (normalizadas)
      - count, first_seen, last_seen
    Sirve para hacer drill-down: filtras por community_id en el dashboard
    y ves todas las alertas que componen ese incidente.

  wazuh-correlation-communities-YYYY.MM.DD
    Un documento POR COMUNIDAD, con sus métricas agregadas:
      - n_alertas, n_clusters, n_filas
      - periodo (first/last)
      - decoders, reglas, IPs, usuarios y hosts top
      - severity_score (placeholder para futuro LLM)
      - incident_summary (placeholder para futuro LLM)
    Sirve para vista resumen: tabla de comunidades en el dashboard.

Uso:
  python3 push_to_indexer.py
  python3 push_to_indexer.py --recreate     # borrar índices previos y recrear
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from indexer_client import get_client
from anonymization import maybe_load, DEFAULT_MAP_PATH

INCIDENTS_PARQUET = Path("lab_state/real_alerts_incidents.parquet")

# Mapeos de los índices nuevos. Los campos clave en formato correcto
# para que el Dashboard sepa filtrar, agregar y mostrar bien.
ALERTS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "decoder.name": {"type": "keyword"},
            "rule.id": {"type": "keyword"},
            "rule.level": {"type": "integer"},
            "rule.description": {"type": "text",
                                 "fields": {"keyword": {"type": "keyword",
                                                        "ignore_above": 256}}},
            "rule.groups": {"type": "keyword"},
            "rule.mitre.tactic": {"type": "keyword"},
            "rule.mitre.technique": {"type": "keyword"},
            "rule.mitre.id": {"type": "keyword"},
            "data.source_address": {"type": "ip", "ignore_malformed": True},
            "data.destination_address": {"type": "ip", "ignore_malformed": True},
            "count": {"type": "long"},
            "cluster_id": {"type": "integer"},
            "community_id": {"type": "integer"},
            "entity_users": {"type": "keyword"},
            "entity_ips": {"type": "keyword"},
            "entity_hosts": {"type": "keyword"},
            "is_replay": {"type": "boolean"},
            "agent.name": {"type": "keyword"},
        }
    }
}

COMMUNITIES_MAPPING = {
    "mappings": {
        "properties": {
            "community_id": {"type": "integer"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "duration_seconds": {"type": "long"},
            "n_alerts": {"type": "long"},
            "n_clusters": {"type": "integer"},
            "n_rows": {"type": "integer"},
            "reduction_factor": {"type": "float"},
            "is_summary": {"type": "boolean"},
            "decoders": {"type": "keyword"},
            "rules": {"type": "keyword"},
            "rule_descriptions": {"type": "text"},
            "top_ips": {"type": "keyword"},
            "top_users": {"type": "keyword"},
            "top_hosts": {"type": "keyword"},
            "mitre_tactics": {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "has_replay": {"type": "boolean"},
            # Placeholders para la Capa LLM (entrega final)
            "severity_score": {"type": "float"},
            "incident_summary": {"type": "text"},
            "incident_category": {"type": "keyword"},
        }
    }
}


def _ensure_index(client, index: str, mapping: dict, recreate: bool):
    if client.indices.exists(index=index):
        if recreate:
            print(f"  borrando índice existente {index}...")
            client.indices.delete(index=index)
        else:
            print(f"  índice {index} ya existe, se añadirán docs")
            return
    client.indices.create(index=index, body=mapping)
    print(f"  creado {index} con mapping")


def _to_native(v):
    """Convierte numpy types y listas/arrays a tipos JSON-safe."""
    if v is None:
        return None
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        f = float(v)
        return None if np.isnan(f) else f
    if isinstance(v, (np.bool_,)):
        return bool(v)
    if isinstance(v, np.ndarray):
        return [_to_native(x) for x in v.tolist()]
    if isinstance(v, list):
        return [_to_native(x) for x in v]
    if isinstance(v, pd.Timestamp):
        return v.isoformat()
    return v


# Campos del parquet que contienen TEXTO LIBRE con posibles nombres de
# usuario. Se les aplica anonymize_text antes de subir al Indexer.
_TEXT_FIELDS_TO_ANON = (
    "rule.description",
    "rule.description_full",
)


def _row_to_alert_doc(row, anon=None):
    """Convierte una fila del Parquet a un documento del índice de
    alertas. Si `anon` esta cargado, sustituye nombres de usuario que
    aparezcan en campos de texto libre (rule.description) por sus alias.
    Los campos `entity_users` del parquet ya vienen anonimizados desde
    `extract_indexer.py`, por lo que aqui no hace falta tocarlos."""
    doc = {}
    for col in row.index:
        v = row[col]
        if isinstance(v, float) and np.isnan(v):
            continue
        if anon is not None and col in _TEXT_FIELDS_TO_ANON \
                and isinstance(v, str):
            v = anon.anonymize_text(v)
        doc[col] = _to_native(v)
    return doc


def _iter_entities(v):
    """Itera de forma segura sobre entidades de una celda Parquet
    (lista, ndarray, str o None)."""
    if v is None:
        return
    # numpy.ndarray no acepta 'or []' por ambigüedad → tratar aparte
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


_ROWS_WARN_THRESHOLD = 50_000


def _build_community_docs(df: pd.DataFrame, run_id: str,
                          anon=None) -> list[dict]:
    """Agrega df por community_id y construye un doc por comunidad.

    Si `anon` esta cargado, las descripciones de regla agregadas
    (`rule_descriptions`) se anonimizan antes de subirlas. Los
    `top_users` provienen de `entity_users` del parquet, que ya esta
    anonimizado en origen."""
    docs = []
    valid = df[df["community_id"] >= 0]
    # El bucle de abajo usa .iterrows() dentro de un groupby. Para los
    # volumenes del lab (<= 10k filas tipicamente) es asumible, pero
    # escala mal: para 50k+ filas se nota mucho. Avisamos para que sea
    # explicito si esto se vuelve cuello de botella.
    if len(valid) > _ROWS_WARN_THRESHOLD:
        print(f"  ⚠ _build_community_docs sobre {len(valid):,} filas; "
              f"iterrows() puede tardar varios minutos. Considera "
              f"vectorizar si esto pasa a ser habitual.")
    for cid, sub in valid.groupby("community_id"):
        ips, users, hosts, tactics, techs = Counter(), Counter(), Counter(), Counter(), Counter()
        for _, r in sub.iterrows():
            for x in _iter_entities(r.get("entity_ips")):    ips[x] += 1
            for x in _iter_entities(r.get("entity_users")):  users[x] += 1
            for x in _iter_entities(r.get("entity_hosts")):  hosts[x] += 1
            mt = r.get("rule.mitre.tactic")
            if isinstance(mt, str) and mt:
                for x in mt.split(","):
                    x = x.strip()
                    if x: tactics[x] += 1
            mtech = r.get("rule.mitre.technique")
            if isinstance(mtech, str) and mtech:
                for x in mtech.split(","):
                    x = x.strip()
                    if x: techs[x] += 1

        first = sub["first_seen"].min()
        last = sub["last_seen"].max()
        duration = (last - first).total_seconds() if pd.notna(first) and pd.notna(last) else 0
        has_replay = bool(sub.get("is_replay", pd.Series([False])).any()) \
            if "is_replay" in sub.columns else False

        n_alerts_comm = int(sub["count"].sum())
        n_rows_comm = int(len(sub))
        reduction_comm = (n_alerts_comm / n_rows_comm) if n_rows_comm else 0.0

        doc = {
            "community_id": int(cid),
            "run_id": run_id,
            "is_summary": False,
            "first_seen": first.isoformat() if pd.notna(first) else None,
            "last_seen": last.isoformat() if pd.notna(last) else None,
            "duration_seconds": int(duration),
            "n_alerts": n_alerts_comm,
            "n_clusters": int(sub["cluster_id"].nunique()),
            "n_rows": n_rows_comm,
            "reduction_factor": round(reduction_comm, 2),
            "decoders": sorted(set(sub["decoder.name"].dropna().astype(str))),
            "rules": sorted(set(sub["rule.id"].dropna().astype(str))),
            "rule_descriptions": (
                anon.anonymize_text(" | ".join(
                    sub["rule.description"].dropna().astype(str).unique()[:5]
                )) if anon is not None
                else " | ".join(
                    sub["rule.description"].dropna().astype(str).unique()[:5]
                )
            ),
            "top_ips":   [k for k, _ in ips.most_common(10)],
            "top_users": [k for k, _ in users.most_common(10)],
            "top_hosts": [k for k, _ in hosts.most_common(10)],
            "mitre_tactics":    [k for k, _ in tactics.most_common(10)],
            "mitre_techniques": [k for k, _ in techs.most_common(10)],
            "has_replay": has_replay,
            # Placeholders LLM
            "severity_score": None,
            "incident_summary": None,
            "incident_category": None,
        }
        docs.append(doc)

    # Documento resumen del run completo: agrega TODOS los datos.
    # Se identifica por is_summary=true y community_id=-1.
    # Permite KPIs globales sin tener que recalcular en cada visualización.
    valid_all = df  # incluye también filas con community_id<0 si las hubiera
    n_alerts_total = int(valid_all["count"].sum())
    n_rows_total = int(len(valid_all))
    n_comms_total = int(valid["community_id"].nunique())
    n_clusters_total = int(valid_all.loc[valid_all["cluster_id"] != -1,
                                          "cluster_id"].nunique())
    # Factor de reducción operativa: alertas crudas → comunidades
    reduction_factor = (n_alerts_total / n_comms_total) if n_comms_total else 0.0

    first_all = valid_all["first_seen"].min()
    last_all = valid_all["last_seen"].max()
    summary = {
        "community_id": -1,
        "run_id": run_id,
        "is_summary": True,
        "first_seen": first_all.isoformat() if pd.notna(first_all) else None,
        "last_seen": last_all.isoformat() if pd.notna(last_all) else None,
        "duration_seconds": int((last_all - first_all).total_seconds())
                            if pd.notna(first_all) and pd.notna(last_all) else 0,
        "n_alerts": n_alerts_total,
        "n_clusters": n_clusters_total,
        "n_rows": n_rows_total,
        "reduction_factor": round(reduction_factor, 2),
        "decoders": sorted(set(valid_all["decoder.name"].dropna().astype(str))),
        "rules": sorted(set(valid_all["rule.id"].dropna().astype(str))),
        "rule_descriptions": "Resumen del run",
        "top_ips": [], "top_users": [], "top_hosts": [],
        "mitre_tactics": [], "mitre_techniques": [],
        "has_replay": False,
        "severity_score": None,
        "incident_summary": None,
        "incident_category": "__summary__",
    }
    docs.append(summary)
    return docs


def _bulk_index(client, index: str, docs: list[dict], batch_size: int = 500):
    n_ok = n_fail = 0
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        body = []
        for d in batch:
            body.append({"index": {"_index": index}})
            body.append(d)
        res = client.bulk(body=body, refresh=False)
        for item in res.get("items", []):
            if item.get("index", {}).get("status", 0) < 300:
                n_ok += 1
            else:
                n_fail += 1
                if n_fail <= 3:
                    print(f"    [!] fail: {item['index'].get('error', '?')}",
                          file=sys.stderr)
    return n_ok, n_fail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(INCIDENTS_PARQUET),
                    help="Parquet de entrada (default: real_alerts_incidents.parquet)")
    ap.add_argument("--recreate", action="store_true",
                    help="borrar índices previos antes de escribir")
    ap.add_argument("--date-suffix", default=None,
                    help="sufijo del índice (default: hoy YYYY.MM.DD)")
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="mapa de anonimizacion; si existe, se aplica a "
                         "rule.description antes de subir al Indexer")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f"No existe {src}. "
                         "Corre primero graph_layer_real.py")

    df = pd.read_parquet(src)
    print(f"Cargadas {len(df):,} filas desde {src}")
    print(f"  comunidades: {df.loc[df['community_id'] >= 0, 'community_id'].nunique()}")
    print(f"  total alertas (sum count): {int(df['count'].sum()):,}")

    anon = maybe_load(args.user_alias_map)
    if anon is not None:
        print(f"[anon] anonimizando rule.description con "
              f"{args.user_alias_map} ({len(anon.forward)} usuarios)")
    else:
        print("[anon] no hay mapa cargado: rule.description se sube tal cual")

    suffix = args.date_suffix or datetime.now(timezone.utc).strftime("%Y.%m.%d")
    alerts_index = f"wazuh-correlation-alerts-{suffix}"
    comms_index  = f"wazuh-correlation-communities-{suffix}"
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    client = get_client()

    # 1. Crear/asegurar índices
    print("\nAsegurando índices...")
    _ensure_index(client, alerts_index, ALERTS_MAPPING, args.recreate)
    _ensure_index(client, comms_index,  COMMUNITIES_MAPPING, args.recreate)

    # 2. Subir alertas enriquecidas
    print(f"\nSubiendo {len(df):,} alertas a {alerts_index}...")
    docs_alerts = []
    for _, row in df.iterrows():
        d = _row_to_alert_doc(row, anon=anon)
        d["run_id"] = run_id
        docs_alerts.append(d)
    n_ok, n_fail = _bulk_index(client, alerts_index, docs_alerts, args.batch_size)
    print(f"  → ok={n_ok:,}  fail={n_fail:,}")

    # 3. Subir comunidades
    docs_comms = _build_community_docs(df, run_id, anon=anon)
    print(f"\nSubiendo {len(docs_comms)} comunidades a {comms_index}...")
    n_ok, n_fail = _bulk_index(client, comms_index, docs_comms, args.batch_size)
    print(f"  → ok={n_ok:,}  fail={n_fail:,}")

    print("\nListo. Para visualizar en el Dashboard:")
    print(f"  1. Stack Management → Index patterns → crear:")
    print(f"       'wazuh-correlation-alerts-*'      (timefield: timestamp)")
    print(f"       'wazuh-correlation-communities-*' (timefield: first_seen)")
    print(f"  2. Importar dashboard NDJSON (Stack Management → Saved Objects)")


if __name__ == "__main__":
    main()
