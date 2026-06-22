"""
entity_normalization.py — Normalización canónica de entidades.

Convierte representaciones distintas de la misma entidad a una forma
canónica, para que el clustering y el grafo las traten como iguales.

Reglas aplicadas:
  Users:
    - 'LABCORP\\lab.user1' → 'lab.user1'
    - 'lab.user1@labcorp.local' → 'lab.user1'
    - 'VSPHERE.LOCAL\\svc-vsc' → 'svc-vsc'
    - 'lab.user1@DOMAIN' (mayúsculas) → 'lab.user1'
    Siempre quedan en lowercase.

  IPs:
    - quitar prefijo CIDR si está
    - quitar prefijo IPv6-mapped '::ffff:'
    - validar que tiene forma de IP

  Hosts:
    - quitar dominios FQDN: 'srv-file01.labcorp.local' → 'srv-file01'
    - lowercase

Uso:
    from entity_normalization import normalize_user, normalize_ip, normalize_host
    u = normalize_user('LABCORP\\lab.user1')        # 'lab.user1'
    i = normalize_ip('::ffff:10.0.5.20')      # '10.0.5.20'
    h = normalize_host('SRV-FILE01.local')    # 'srv-file01'
"""
from __future__ import annotations
import ipaddress
import re
from typing import Optional


def _safe_str(v) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def normalize_user(v) -> Optional[str]:
    s = _safe_str(v)
    if s is None:
        return None
    # 'DOMAIN\user' → 'user'
    if "\\" in s:
        s = s.split("\\")[-1]
    # 'user@domain' → 'user'
    if "@" in s:
        s = s.split("@")[0]
    # cortar después del primer espacio (algunas alertas tienen 'user (admin)')
    s = s.split()[0] if s else s
    s = s.lower()
    # filtrar usuarios genéricos que no aportan a la correlación
    if s in {"", "system", "anonymous", "guest", "-", "root"}:
        return None
    return s


def normalize_ip(v) -> Optional[str]:
    s = _safe_str(v)
    if s is None:
        return None
    # algunos campos vienen con CIDR
    if "/" in s:
        s = s.split("/")[0]
    # IPv6-mapped IPv4
    if s.startswith("::ffff:"):
        s = s[7:]
    # validación
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    # filtrar IPs que no discriminan
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr)


def normalize_host(v) -> Optional[str]:
    s = _safe_str(v)
    if s is None:
        return None
    s = s.lower()
    # quitar dominios FQDN frecuentes: keep solo el hostname corto
    # 'srv-file01.labcorp.local' → 'srv-file01'
    if "." in s:
        # solo si el primer token no es una IP
        try:
            ipaddress.ip_address(s)
            return None  # es una IP, no un hostname
        except ValueError:
            pass
        head = s.split(".")[0]
        if head:
            s = head
    # filtrar hosts genéricos
    if s in {"", "localhost", "unknown", "-", "wazuh-server",
             "wazuh", "wazuh-manager"}:
        return None
    return s


# Mapeo de columnas Wazuh → tipo de entidad
# Para usar desde el feature engineering y el matcher de forma consistente.
USER_COLS = [
    "data.office365.UserId",
    "data.office365.MailboxOwnerUPN",
    "data.vc_user",
    "data.agentDetectionInfo.agentLastLoggedInUserName",
    "data.userEmail",
    "data.source_user", "data.destination_user",
    "data.srcuser", "data.dstuser",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserName",
]
IP_COLS = [
    "data.srcip", "data.source_address",
    "data.dstip", "data.destination_address",
    "data.office365.ClientIP", "data.office365.ClientIPAddress",
    "data.agentDetectionInfo.agentIpV4",
    "data.nat_source_ip", "data.nat_destination_ip",
]
# IPs que actúan SOLO como source (atacante, no víctima)
IP_SRC_COLS = [
    "data.srcip", "data.source_address",
    "data.office365.ClientIP", "data.office365.ClientIPAddress",
    "data.agentDetectionInfo.agentIpV4",
]
# IPs que actúan SOLO como destination
IP_DST_COLS = [
    "data.dstip", "data.destination_address",
    "data.nat_destination_ip",
]
HOST_COLS = [
    "data.computerName",
    "data.agentRealtimeInfo.agentComputerName",
    "predecoder.hostname",
    "agent.name",
    "data.win.system.computer",
]


def extract_all_entities(row) -> dict:
    """Devuelve un dict con TODAS las entidades normalizadas de una alerta:
        {'users': {...}, 'src_ips': {...}, 'dst_ips': {...}, 'hosts': {...}}
    """
    users, src_ips, dst_ips, hosts = set(), set(), set(), set()

    for col in USER_COLS:
        v = row.get(col) if col in row.index else None
        if isinstance(v, (list, tuple)):
            for item in v:
                n = normalize_user(item)
                if n:
                    users.add(n)
        else:
            n = normalize_user(v)
            if n:
                users.add(n)

    for col in IP_SRC_COLS:
        v = row.get(col) if col in row.index else None
        n = normalize_ip(v)
        if n:
            src_ips.add(n)

    for col in IP_DST_COLS:
        v = row.get(col) if col in row.index else None
        n = normalize_ip(v)
        if n:
            dst_ips.add(n)

    for col in HOST_COLS:
        v = row.get(col) if col in row.index else None
        n = normalize_host(v)
        if n:
            hosts.add(n)

    return {
        "users": users,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "hosts": hosts,
    }


def primary_entities(row) -> dict:
    """Versión 'una por categoría' compatible con el pipeline actual.
    Devuelve solo la primera entidad encontrada de cada tipo.
    """
    all_e = extract_all_entities(row)
    return {
        "entity_user": next(iter(sorted(all_e["users"])), None),
        "entity_src_ip": next(iter(sorted(all_e["src_ips"])), None),
        "entity_dst_ip": next(iter(sorted(all_e["dst_ips"])), None),
        "entity_host": next(iter(sorted(all_e["hosts"])), None),
    }
