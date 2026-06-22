#!/usr/bin/env python3
"""
extract_indexer.py — Lee alertas del Wazuh Indexer (vía scroll API),
aplica normalización + dedup y persiste un Parquet listo para clustering.

Equivalente a extract_real.py pero leyendo del Indexer en vez de un
fichero alerts.json plano. Esto es lo que valida la arquitectura del
TFM: "el sistema consume del mismo backend que usa el Wazuh Dashboard".

Uso típico:
  # Últimos 60 minutos:
  python3 extract_indexer.py --since "now-60m"

  # Rango concreto:
  python3 extract_indexer.py --since "2026-05-13T18:00:00Z" \\
                              --until "2026-05-13T19:00:00Z"

  # Solo alertas inyectadas en el lab:
  python3 extract_indexer.py --since "now-2h" --replay-only

  # Filtrar reglas que sabes que son ruido masivo:
  python3 extract_indexer.py --since "now-2h" --exclude-rule 64508
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from indexer_client import get_client
from entity_normalization import (
    normalize_user, normalize_ip, normalize_host,
)
from anonymization import UserAnonymizer, DEFAULT_MAP_PATH

OUT = Path("lab_state/real_alerts.parquet")


def _get(d, path):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return cur


def _flatten_data(alert: dict) -> dict:
    out = {}
    data = alert.get("data", {})
    if not isinstance(data, dict):
        return out
    for k, v in data.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, (str, int, float, bool)) or v2 is None:
                    out[f"data.{k}.{k2}"] = v2
                elif isinstance(v2, dict):
                    # segundo nivel: necesario para data.win.system.* y
                    # data.win.eventdata.* de windows_eventchannel
                    for k3, v3 in v2.items():
                        if (isinstance(v3, (str, int, float, bool))
                                or v3 is None):
                            out[f"data.{k}.{k2}.{k3}"] = v3
        elif isinstance(v, list):
            if v and all(isinstance(x, str) for x in v):
                out[f"data.{k}"] = ",".join(v)
            else:
                out[f"data.{k}"] = json.dumps(v) if v else None
        else:
            out[f"data.{k}"] = v
    return out


def _extract_entities(flat: dict, alert: dict):
    """Devuelve (users, ips, hosts) como sets de strings canónicos
    con prefijo 'user:', 'ip:', 'host:'."""
    users, ips, hosts = set(), set(), set()

    # USER columns
    for col in [
        "data.office365.UserId", "data.office365.MailboxOwnerUPN",
        "data.vc_user", "data.userEmail",
        "data.srcuser", "data.dstuser",
        "data.source_user", "data.destination_user",
        "data.agentDetectionInfo.agentLastLoggedInUserName",
    ]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = normalize_user(v)
            if n: users.add(f"user:{n}")

    # IP columns
    for col in [
        "data.source_address", "data.destination_address",
        "data.srcip", "data.dstip", "data.srcip2",
        "data.office365.ClientIP", "data.office365.ClientIPAddress",
        "data.office365.ActorIpAddress",
        "data.agentDetectionInfo.agentIpV4",
        "data.win.eventdata.ipAddress",
    ]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = normalize_ip(v)
            if n: ips.add(f"ip:{n}")

    # IP embebida en data.description de vCenter:
    # las alertas de login/logout traen "@<IP>" dentro del texto,
    # p.ej. "User VSPHERE.LOCAL\\usuario@10.99.8.50 logged in ...".
    # Es la IP de origen del acceso y la unica fuente de IP en vCenter.
    desc = flat.get("data.description")
    if isinstance(desc, str):
        m = re.search(r"@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", desc)
        if m:
            n = normalize_ip(m.group(1))
            if n:
                ips.add(f"ip:{n}")

    # HOST columns
    for col in [
        "data.computerName",
        "data.agentRealtimeInfo.agentComputerName",
        "data.device_name",
        "predecoder.hostname",
    ]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = normalize_host(v)
            if n: hosts.add(f"host:{n}")

    return users, ips, hosts


def _bucket_ts(ts_str: str, bucket_s: int) -> int:
    try:
        s = ts_str.replace("Z", "+00:00").replace("+0000", "+00:00")
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp()) // bucket_s
    except Exception:
        return 0


def _ts_fingerprint(ts_str: str) -> str:
    """Sustituye digitos por 'd' y deja TZ visible, para detectar mezclas
    de formato de timestamp que romperian la comparacion lexicografica
    del dedup. Ver invariante en el bucle principal."""
    return re.sub(r"\d", "d", ts_str)


def stream_alerts(client, query: dict, index_pattern: str,
                  page_size: int = 2000, scroll: str = "5m"):
    """Generator que yields documentos uno a uno usando scroll API."""
    from opensearchpy.helpers import scan
    for hit in scan(client, index=index_pattern, query=query,
                    size=page_size, scroll=scroll, preserve_order=False):
        yield hit.get("_source", {})


def build_query(since: str, until: str, exclude_rules, exclude_decoders,
                min_level: int, replay_only: bool):
    must = [{"range": {"@timestamp": {"gte": since, "lte": until}}}]
    must_not = []
    for rid in exclude_rules:
        must_not.append({"term": {"rule.id": rid}})
    for dec in exclude_decoders:
        must_not.append({"term": {"decoder.name": dec}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if replay_only:
        must.append({"term": {"tfm_replay": True}})
    return {
        "query": {
            "bool": {
                "must": must,
                "must_not": must_not,
            }
        }
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="now-60m",
                    help="inicio del rango (ISO o 'now-Nm', default now-60m)")
    ap.add_argument("--until", default="now",
                    help="fin del rango (default now)")
    ap.add_argument("--index-pattern", default="wazuh-alerts-*")
    ap.add_argument("--bucket", type=int, default=60,
                    help="ventana de dedup en segundos (default 60)")
    ap.add_argument("--exclude-rule", action="append", default=[])
    ap.add_argument("--exclude-decoder", action="append", default=[])
    ap.add_argument("--min-level", type=int, default=0)
    ap.add_argument("--replay-only", action="store_true",
                    help="solo alertas con tfm_replay=true")
    ap.add_argument("--page-size", type=int, default=2000)
    ap.add_argument("--max-docs", type=int, default=None,
                    help="máximo nº de docs a procesar (debug)")
    ap.add_argument("--out", default=str(OUT))
    # Anonimizacion de usuarios: on por defecto. Para reproducir
    # exactamente el run canonico documentado en run_final.log (con
    # nombres de usuario crudos), pasar --no-anonymize-users.
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--anonymize-users", dest="anonymize",
                     action="store_true", default=True,
                     help="anonimiza nombres de usuario con alias "
                          "estables (default: activado)")
    grp.add_argument("--no-anonymize-users", dest="anonymize",
                     action="store_false",
                     help="desactiva la anonimizacion de usuarios "
                          "(reproduce el comportamiento previo)")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="ruta del mapa de alias persistido "
                         f"(default {DEFAULT_MAP_PATH})")
    args = ap.parse_args()

    anon = UserAnonymizer(args.user_alias_map) if args.anonymize else None
    if anon is not None:
        print(f"[anon] mapa de alias: {args.user_alias_map}  "
              f"(usuarios previos: {len(anon.forward)})")
    else:
        print("[anon] anonimizacion DESACTIVADA (--no-anonymize-users)")

    client = get_client()
    query = build_query(args.since, args.until,
                         args.exclude_rule, args.exclude_decoder,
                         args.min_level, args.replay_only)

    # Conteo previo
    try:
        n = client.count(index=args.index_pattern, body=query)["count"]
        print(f"Alertas en rango: {n:,}")
    except Exception as e:
        print(f"[!] no se pudo contar: {e}")
        n = -1

    if n == 0:
        raise SystemExit("Ninguna alerta en el rango.")

    agg: dict[tuple, dict] = {}
    n_seen = 0
    # Huella del formato del primer timestamp visto. Sirve para detectar
    # mezclas de TZ que romperian la comparacion lexicografica usada en
    # el dedup (first_seen/last_seen). Wazuh emite siempre el mismo
    # formato; si en algun momento aparece otro, lo avisamos.
    ts_fmt_ref = None
    print(f"\nLeyendo del Indexer (page_size={args.page_size})...")

    for a in stream_alerts(client, query, args.index_pattern,
                            page_size=args.page_size):
        n_seen += 1
        if args.max_docs and n_seen > args.max_docs:
            break
        if n_seen % 5000 == 0:
            print(f"  {n_seen:,} alertas | claves: {len(agg):,}")

        ts = _get(a, "timestamp") or _get(a, "@timestamp") or ""
        if ts and ts_fmt_ref is None:
            ts_fmt_ref = _ts_fingerprint(ts)
        elif ts and ts_fmt_ref != "__warned__" and \
                _ts_fingerprint(ts) != ts_fmt_ref:
            print(f"  ⚠ formato de timestamp inconsistente: "
                  f"{ts!r} difiere del primero ({ts_fmt_ref!r}). "
                  "El dedup por bucket y first_seen/last_seen "
                  "asumen formato uniforme.")
            ts_fmt_ref = "__warned__"
        rid = str(_get(a, "rule.id") or "")
        dec = _get(a, "decoder.name") or ""
        desc = _get(a, "rule.description") or ""
        lvl = _get(a, "rule.level")

        flat = _flatten_data(a)
        ph = _get(a, "predecoder.hostname")
        if ph:
            flat["predecoder.hostname"] = ph

        users, ips, hosts = _extract_entities(flat, a)

        # Anonimizacion: si esta activada, sustituye CADA usuario
        # canonico por su alias estable ANTES de cualquier uso
        # posterior (dedup key, parquet, Indexer). Las IPs y hosts no
        # se anonimizan por decision del proyecto.
        if anon is not None and users:
            users = {anon.anonymize(u) for u in users}

        # Clave para dedup
        sa = flat.get("data.source_address") or flat.get("data.srcip")
        da = flat.get("data.destination_address") or flat.get("data.dstip")
        src = normalize_ip(sa) or "" if sa else ""
        dst = normalize_ip(da) or "" if da else ""
        if src: src = f"ip:{src}"
        if dst: dst = f"ip:{dst}"
        # user_key se calcula sobre `users`, que ya esta anonimizado si
        # corresponde, asi que el dedup agrupa por alias y NO por nombre
        # real (importante: dos runs con el mismo mapa producen las
        # mismas claves de dedup).
        user_key = next(iter(sorted(users)), "") if users else ""

        bucket = _bucket_ts(ts, args.bucket)
        key = (dec, rid, src, dst, user_key, bucket)

        rec = agg.get(key)
        if rec is None:
            agg[key] = {
                "decoder.name": dec,
                "rule.id": rid,
                "rule.level": lvl,
                "rule.description": desc,
                "rule.groups": ",".join(_get(a, "rule.groups") or []),
                "rule.mitre.tactic": ",".join(_get(a, "rule.mitre.tactic") or []),
                "rule.mitre.technique": ",".join(_get(a, "rule.mitre.technique") or []),
                "rule.mitre.id": ",".join(_get(a, "rule.mitre.id") or []),
                "timestamp": ts,
                "first_seen": ts,
                "last_seen": ts,
                "count": 1,
                "entity_users": sorted(users),
                "entity_ips": sorted(ips),
                "entity_hosts": sorted(hosts),
                "data.source_address": src.replace("ip:", "") if src else "",
                "data.destination_address": dst.replace("ip:", "") if dst else "",
                "is_replay": bool(_get(a, "tfm_replay")),
                "agent.name": _get(a, "agent.name") or "",
            }
        else:
            rec["count"] += 1
            if ts and ts < rec["first_seen"]: rec["first_seen"] = ts
            if ts and ts > rec["last_seen"]:  rec["last_seen"]  = ts
            rec["entity_users"] = sorted(set(rec["entity_users"]) | users)
            rec["entity_ips"]   = sorted(set(rec["entity_ips"])   | ips)
            rec["entity_hosts"] = sorted(set(rec["entity_hosts"]) | hosts)

    print(f"\nTotal alertas leídas: {n_seen:,}")
    print(f"Filas tras dedup: {len(agg):,}")
    if n_seen:
        print(f"Reducción: {(1 - len(agg)/n_seen):.1%}")

    df = pd.DataFrame(agg.values())
    for col in ("timestamp", "first_seen", "last_seen"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"\nGuardado → {out}  ({out.stat().st_size / 1e6:.1f} MB)")

    if anon is not None:
        anon.save()
        st = anon.stats()
        print(f"[anon] mapa guardado en {st['path']}  "
              f"(usuarios totales: {st['n_usuarios']})")

    print("\nTop 10 por count:")
    print(df.nlargest(10, "count")[
        ["decoder.name", "rule.id", "count",
         "data.source_address", "data.destination_address"]
    ].to_string(index=False))


if __name__ == "__main__":
    main()
