#!/usr/bin/env python3
"""
extract_real.py — Lee alerts.json grande en streaming, normaliza,
deduplica y exporta a Parquet listo para clustering.

Pipeline en una pasada (sin cargar el JSON entero en memoria):

  1. Lee línea a línea.
  2. Aplana data.* (incluyendo data.office365.* anidado).
  3. Extrae entidades normalizadas (user:, ip:, host:).
  4. Construye clave de dedup: (decoder, rule.id, src, dst, user, bucket_temporal).
  5. Agrega: cada clave única → 1 fila con count, first_seen, last_seen,
     y conjunto de entidades.

Dedup temporal: bucket de N segundos (default 60). Esto significa que
una alerta repetida en 60s consecutivos se colapsa en una sola fila;
si la misma alerta reaparece tras 60s, se crea una nueva fila (preserva
la dinámica temporal).

Uso:
  python3 extract_real.py /ruta/alerts.json
  python3 extract_real.py /ruta/alerts.json --bucket 30
  python3 extract_real.py /ruta/alerts.json --min-level 3
"""
from __future__ import annotations
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize import (
    norm_user, norm_ip, norm_host, ENTITY_COLUMNS, ORG_DOMAINS_DEFAULT
)
from anonymization import UserAnonymizer, DEFAULT_MAP_PATH


OUT_PARQUET = Path("lab_state/real_alerts.parquet")


# Captura el token despues de '@' en data.description de vCenter. Admite:
#   - IPv4:               @10.0.0.1
#   - IPv4-mapped IPv6:   @::ffff:10.0.0.1
#   - IPv6 abreviado:     @fe80::1, @2001:db8::1
# Solo nos interesa el token; la validacion real la hace norm_ip().
_IP_AFTER_AT_RX = re.compile(r"@([0-9A-Fa-f:.]+)")


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
    """Aplana data.* a un solo nivel con dot notation, y desciende un
    nivel más en sub-dicts (data.X.Y.Z) — necesario para data.win.* de
    windows_eventchannel, cuyos campos de entidad están anidados en
    data.win.system.* y data.win.eventdata.*.
    No usa pd.json_normalize porque es muy lento para una sola fila."""
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
                    # segundo nivel: data.win.system.*, data.win.eventdata.*
                    for k3, v3 in v2.items():
                        if (isinstance(v3, (str, int, float, bool))
                                or v3 is None):
                            out[f"data.{k}.{k2}.{k3}"] = v3
        elif isinstance(v, list):
            # convertir lista a string (Recipients, etc.)
            if v and all(isinstance(x, str) for x in v):
                out[f"data.{k}"] = ",".join(v)
            else:
                out[f"data.{k}"] = json.dumps(v) if v else None
        else:
            out[f"data.{k}"] = v
    return out


def _extract_entities_from_alert(flat: dict, alert: dict) -> tuple[set, set, set]:
    """Extrae entidades fuente, destino y usuario.
    Usa el dict aplanado para acceso directo.
    """
    users, ips, hosts = set(), set(), set()

    for col in ENTITY_COLUMNS["user"]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = norm_user(v)
            if n: users.add(n)

    for col in ENTITY_COLUMNS["ip"]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = norm_ip(v)
            if n: ips.add(n)

    # IP embebida en data.description de vCenter: las alertas de
    # login/logout traen "@<IP>" dentro del texto. Es la IP de origen
    # del acceso y la unica fuente de IP de la fuente vCenter.
    # Aceptamos IPv4, IPv4-mapped (::ffff:N.N.N.N) e IPv6 abreviado.
    # norm_ip se encarga de filtrar lo que no sea IP valida.
    desc = flat.get("data.description")
    if isinstance(desc, str):
        for cand in _IP_AFTER_AT_RX.findall(desc):
            n = norm_ip(cand)
            if n:
                ips.add(n)

    for col in ENTITY_COLUMNS["host"]:
        v = flat.get(col) if col.startswith("data.") else _get(alert, col)
        if isinstance(v, str):
            n = norm_host(v)
            if n: hosts.add(n)

    return users, ips, hosts


def _bucket_ts(ts_str: str, bucket_s: int) -> int:
    """Convierte timestamp a entero bucket de bucket_s segundos desde epoch."""
    try:
        # tolerar tanto +0000 como Z
        s = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp()) // bucket_s
    except Exception:
        return 0


def _ts_fingerprint(ts_str: str) -> str:
    """Devuelve la 'huella' del formato de un timestamp ISO-8601 para
    detectar mezclas de zona horaria. Reemplaza digitos por 'd' y deja
    la TZ visible. Ejemplos:
        '2025-01-02T03:04:05.123+0000' -> 'dddd-dd-ddTdd:dd:dd.ddd+dddd'
        '2025-01-02T03:04:05Z'         -> 'dddd-dd-ddTdd:dd:ddZ'
    Si dos timestamps producen huellas distintas, las comparaciones
    lexicograficas entre ellos NO son seguras."""
    return re.sub(r"\d", "d", ts_str)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="ruta al alerts.json")
    ap.add_argument("--bucket", type=int, default=60,
                    help="ventana de dedup en segundos (default 60)")
    ap.add_argument("--min-level", type=int, default=0,
                    help="descartar alertas con rule.level < N")
    ap.add_argument("--max-lines", type=int, default=None,
                    help="limitar nº líneas (debug)")
    ap.add_argument("--out", default=str(OUT_PARQUET))
    # Anonimizacion de usuarios (mismo flag que extract_indexer.py)
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--anonymize-users", dest="anonymize",
                     action="store_true", default=True,
                     help="anonimiza nombres de usuario con alias estables "
                          "(default: activado)")
    grp.add_argument("--no-anonymize-users", dest="anonymize",
                     action="store_false",
                     help="desactiva la anonimizacion de usuarios")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="ruta del mapa de alias persistido")
    args = ap.parse_args()

    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"No existe {path}")

    anon = UserAnonymizer(args.user_alias_map) if args.anonymize else None
    if anon is not None:
        print(f"[anon] mapa de alias: {args.user_alias_map}  "
              f"(usuarios previos: {len(anon.forward)})")
    else:
        print("[anon] anonimizacion DESACTIVADA (--no-anonymize-users)")

    print(f"Leyendo {path} ({path.stat().st_size / 1e9:.2f} GB)")
    print(f"  bucket dedup: {args.bucket}s")
    print(f"  filtro level≥{args.min_level}")

    # Agregador: clave → record acumulado
    agg: dict[tuple, dict] = {}

    n_total = 0
    n_kept = 0
    n_errors = 0
    n_encoding_errors = 0
    # Formato del primer timestamp visto. Se usa para detectar mas tarde
    # mezclas de TZ que romperian la comparacion lexicografica en el
    # bucle de dedup (first_seen/last_seen). Ver _validate_ts_format.
    ts_fmt_ref = None

    # encoding="utf-8" sin "replace": queremos que un fichero corrupto se
    # note. Capturamos la UnicodeDecodeError por linea, descartamos solo
    # la linea ofensiva y llevamos contador para reporte final honesto.
    with open(path, "rb") as f_bin:
        for raw_line in f_bin:
            try:
                line = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                n_encoding_errors += 1
                continue
            if not line:
                continue
            n_total += 1
            if n_total % 100000 == 0:
                print(f"  {n_total:,} líneas | claves únicas: {len(agg):,}")
            if args.max_lines and n_total > args.max_lines:
                break
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                n_errors += 1
                continue

            lvl = _get(a, "rule.level")
            if isinstance(lvl, (int, float)) and lvl < args.min_level:
                continue

            ts = _get(a, "timestamp") or ""
            # Invariante para la comparacion lexicografica de timestamps
            # mas abajo (first_seen/last_seen). Wazuh emite ISO-8601 con
            # zona horaria al final (`...+0000` o `...Z`). Mientras todas
            # las alertas compartan formato y TZ, `ts < other` equivale a
            # comparacion cronologica. Si en algun momento llegan
            # timestamps con TZ distinta (p.ej. `+02:00` y `Z` mezclados),
            # la comparacion da resultados incorrectos. Detectamos el
            # cambio aqui en cuanto ocurra.
            if ts and ts_fmt_ref is None:
                ts_fmt_ref = _ts_fingerprint(ts)
            elif ts and _ts_fingerprint(ts) != ts_fmt_ref:
                print(f"  ⚠ formato de timestamp inconsistente: "
                      f"{ts!r} difiere del primero ({ts_fmt_ref!r}). "
                      "El dedup por bucket y first_seen/last_seen "
                      "asumen formato uniforme.")
                # solo avisamos una vez para no inundar el log
                ts_fmt_ref = "__warned__"
            rid = str(_get(a, "rule.id") or "")
            dec = _get(a, "decoder.name") or ""
            desc = _get(a, "rule.description") or ""

            flat = _flatten_data(a)
            # añadimos los predecoder.hostname al flat para extracción
            ph = _get(a, "predecoder.hostname")
            if ph:
                flat["predecoder.hostname"] = ph

            users, ips, hosts = _extract_entities_from_alert(flat, a)

            # Anonimizacion (ver extract_indexer.py para detalles).
            # IPs y hosts NO se anonimizan, solo usuarios.
            if anon is not None and users:
                users = {anon.anonymize(u) for u in users}

            # Selección de "principal" para clave de dedup
            src_for_key = ""
            dst_for_key = ""
            sa = flat.get("data.source_address") or flat.get("data.srcip")
            da = flat.get("data.destination_address") or flat.get("data.dstip")
            src_for_key = norm_ip(sa) or ""
            dst_for_key = norm_ip(da) or ""
            user_for_key = next(iter(sorted(users)), "") if users else ""

            bucket = _bucket_ts(ts, args.bucket)
            key = (dec, rid, src_for_key, dst_for_key, user_for_key, bucket)

            rec = agg.get(key)
            if rec is None:
                # primera ocurrencia
                rec = {
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
                    # un par de campos representativos para análisis posterior
                    "data.source_address": src_for_key.replace("ip:", ""),
                    "data.destination_address": dst_for_key.replace("ip:", ""),
                    "rule.description_full": desc,
                }
                agg[key] = rec
                n_kept += 1
            else:
                rec["count"] += 1
                if ts < rec["first_seen"]:
                    rec["first_seen"] = ts
                if ts > rec["last_seen"]:
                    rec["last_seen"] = ts
                # acumular entidades adicionales que aparezcan
                cu = set(rec["entity_users"]) | users
                ci = set(rec["entity_ips"]) | ips
                ch = set(rec["entity_hosts"]) | hosts
                rec["entity_users"] = sorted(cu)
                rec["entity_ips"] = sorted(ci)
                rec["entity_hosts"] = sorted(ch)

    print(f"\nProcesadas: {n_total:,} líneas")
    print(f"Errores parseo: {n_errors:,}")
    if n_encoding_errors:
        # Las lineas con bytes invalidos se descartan en vez de
        # reemplazarlas silenciosamente: si este contador crece, el
        # fichero fuente trae corrupcion y los conteos no son fiables.
        print(f"Errores de encoding (lineas descartadas): "
              f"{n_encoding_errors:,}")
    print(f"Filas tras dedup: {n_kept:,}")
    if n_total:
        print(f"Reducción: {(1 - n_kept/n_total):.1%}")

    df = pd.DataFrame(agg.values())
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["first_seen"] = pd.to_datetime(df["first_seen"], utc=True, errors="coerce")
    df["last_seen"] = pd.to_datetime(df["last_seen"], utc=True, errors="coerce")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    print(f"\nGuardado → {out_path}  ({out_path.stat().st_size / 1e6:.1f} MB)")

    if anon is not None:
        anon.save()
        st = anon.stats()
        print(f"[anon] mapa guardado en {st['path']}  "
              f"(usuarios totales: {st['n_usuarios']})")

    # mini-resumen
    print("\nTop 10 filas por count:")
    cols_show = ["decoder.name", "rule.id", "count",
                 "data.source_address", "data.destination_address"]
    print(df.nlargest(10, "count")[cols_show].to_string(index=False))


if __name__ == "__main__":
    main()
