"""
normalize.py — Normalización canónica de entidades (usuarios, IPs, hosts).

Convierte variantes sintácticas distintas del mismo objeto lógico a una
única forma canónica, para que el grafo y el clustering los traten como
la misma entidad:

  Usuarios:
    'LABCORP\\lab.user1'                 → 'user:lab.user1'
    'lab.user1@labcorp.local'        → 'user:lab.user1'
    'VSPHERE.LOCAL\\svc-horizon'  → 'user:svc-horizon'
    'svc-horizon'                 → 'user:svc-horizon'

  IPs:
    '10.252.1.49'                 → 'ip:10.252.1.49'
    '::ffff:10.252.1.49'          → 'ip:10.252.1.49'
    '10.252.1.49/32'              → 'ip:10.252.1.49'

  Hosts:
    'srv-file01.labcorp.local' → 'host:srv-file01'
    'SRV-FILE01'                   → 'host:srv-file01'
    'srv-file01.corp.local'        → 'host:srv-file01'

El prefijo (user:/ip:/host:) garantiza que no se confunde un usuario
'admin' con un host 'admin'.

Uso desde otros scripts:
    from normalize import norm_user, norm_ip, norm_host, norm_entity
"""
from __future__ import annotations
import re
import ipaddress

# Dominios que se eliminan al normalizar usuarios (por defecto los
# detectados en el dataset; añade los tuyos si hace falta)
ORG_DOMAINS_DEFAULT = {
    "labcorp.local", "labcorp.com",
    "vsphere.local",
    "corp.local", "domain.local",
    "onmicrosoft.com",
}

# Sufijos de hostname a eliminar
ORG_HOST_SUFFIXES_DEFAULT = {
    ".labcorp.local", ".labcorp.com",
    ".corp.local", ".domain.local",
    ".local",
}


def norm_user(v: str | None, org_domains: set[str] = None) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip().lower()

    org_domains = org_domains or ORG_DOMAINS_DEFAULT

    # Caso 1: DOMINIO\usuario  o  DOMINIO\\usuario
    if "\\" in s:
        s = s.split("\\")[-1]

    # Caso 2: usuario@dominio
    if "@" in s:
        head, _, tail = s.partition("@")
        if tail in org_domains or any(tail.endswith(f".{d}") for d in org_domains):
            s = head
        # si no es de un dominio org, conserva entero para no confundir
        # 'attacker@evil.tld' con un usuario local

    # Caso 3: sufijo '(uid=NNNN)' que añade PAM, p.ej. 'lab.user1(uid=1002)'
    if "(" in s:
        s = s.split("(")[0]

    # quita posibles espacios o caracteres residuales
    s = s.strip().rstrip(",.;:")
    if not s:
        return None
    return f"user:{s}"


def norm_ip(v: str | None) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip()

    # Quita máscaras de subred /N
    if "/" in s:
        s = s.split("/")[0]
    # Notación IPv4 mapped en IPv6: ::ffff:10.0.0.1
    if s.lower().startswith("::ffff:"):
        s = s[7:]

    # Filtra valores no-IP que pueden colarse en data.srcip (vimos el caso
    # en web-accesslog con timestamps)
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None

    # Filtra IPs no informativas
    if addr.is_unspecified or addr.is_loopback:
        return None
    if str(addr) in ("255.255.255.255",):
        return None

    return f"ip:{addr}"


def norm_host(v: str | None, suffixes: set[str] = None) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip().lower()

    suffixes = suffixes or ORG_HOST_SUFFIXES_DEFAULT
    # quita sufijos organizacionales (más largos primero)
    for suf in sorted(suffixes, key=lambda x: -len(x)):
        if s.endswith(suf):
            s = s[:-len(suf)]
            break

    # si aún queda un FQDN con puntos (dominio no listado en suffixes,
    # p.ej. 'dc2.labcorp.local'), reducir al nombre corto antes del primer
    # punto. Se evita hacerlo si el valor es en realidad una IP.
    if "." in s:
        try:
            ipaddress.ip_address(s)
        except ValueError:
            s = s.split(".")[0]

    # filtra valores genéricos
    if s in ("localhost", "wazuh-server", "wazuh-manager", "",
             "none", "null", "unknown", "-", "n/a"):
        return None

    # filtra si en realidad es una IP (ya tiene su categoría)
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass

    return f"host:{s}"


def norm_entity(v: str | None, kind: str) -> str | None:
    """Dispatch según tipo declarado."""
    if kind == "user":
        return norm_user(v)
    if kind == "ip":
        return norm_ip(v)
    if kind == "host":
        return norm_host(v)
    return None


# ---------------------------------------------------------------
# Mapping declarativo de columnas → tipo de entidad.
# Construido a partir del EDA del dataset real.
# ---------------------------------------------------------------
ENTITY_COLUMNS = {
    "user": [
        "data.office365.UserId", "data.office365.MailboxOwnerUPN",
        "data.office365.UserKey", "data.office365.userPrincipalName",
        "data.vc_user",
        "data.agentDetectionInfo.agentLastLoggedInUserName",
        "data.userEmail",
        "data.source_user", "data.destination_user",
        "data.srcuser", "data.dstuser",
        # windows_eventchannel: usuario objetivo del evento de seguridad
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.samAccountName",
    ],
    "ip": [
        # PaloAlto usa data.source_address / data.destination_address
        "data.source_address", "data.destination_address",
        "data.nat_source_ip", "data.nat_destination_ip",
        # Otras fuentes
        "data.srcip", "data.dstip", "data.srcip2",
        "data.office365.ClientIP", "data.office365.ClientIPAddress",
        "data.office365.ActorIpAddress",
        "data.agentDetectionInfo.agentIpV4",
        # windows_eventchannel: IP de origen del logon
        "data.win.eventdata.ipAddress",
    ],
    "host": [
        "data.computerName",
        "data.agentRealtimeInfo.agentComputerName",
        "data.device_name",
        "predecoder.hostname",
        # windows_eventchannel: equipo donde ocurre el evento
        "data.win.system.computer",
        # agent.name suele ser el manager Wazuh, no aporta
    ],
}


def extract_all_entities(row) -> dict[str, set[str]]:
    """Extrae TODAS las entidades de una fila (no solo la primera) y
    las devuelve clasificadas por tipo en un dict {kind: {entity, ...}}.

    A diferencia del primer matcher, aquí NO devolvemos un único valor
    sino el conjunto completo — clave para datos reales con src+dst+user
    en la misma alerta.
    """
    out = {"user": set(), "ip": set(), "host": set()}
    for kind, cols in ENTITY_COLUMNS.items():
        for col in cols:
            v = row.get(col) if col in row.index else None
            if v is None:
                continue
            # listas (Recipients, etc.)
            if isinstance(v, list):
                for item in v:
                    n = norm_entity(item, kind)
                    if n:
                        out[kind].add(n)
            else:
                n = norm_entity(v, kind)
                if n:
                    out[kind].add(n)
    return out


def all_entities_flat(row) -> set[str]:
    """Versión plana: todas las entidades en un solo set."""
    by_kind = extract_all_entities(row)
    return by_kind["user"] | by_kind["ip"] | by_kind["host"]


if __name__ == "__main__":
    # Tests rápidos
    tests = [
        ("LABCORP\\lab.user1",                          norm_user,  "user:lab.user1"),
        ("lab.user1@labcorp.local",                  norm_user,  "user:lab.user1"),
        ("VSPHERE.LOCAL\\svc-horizon",            norm_user,  "user:svc-horizon"),
        ("attacker@malicious.tld",                norm_user,  "user:attacker@malicious.tld"),
        ("10.252.1.49",                           norm_ip,    "ip:10.252.1.49"),
        ("10.252.1.49/32",                        norm_ip,    "ip:10.252.1.49"),
        ("::ffff:10.252.1.49",                    norm_ip,    "ip:10.252.1.49"),
        ("127.0.0.1",                             norm_ip,    None),
        ("not-an-ip",                             norm_ip,    None),
        ("SRV-FILE01.labcorp.local",          norm_host,  "host:srv-file01"),
        ("srv-file01",                            norm_host,  "host:srv-file01"),
        ("PA-VM300-01.labcorp.local",         norm_host,  "host:pa-vm300-01"),
        ("localhost",                             norm_host,  None),
        ("10.0.0.1",                              norm_host,  None),  # es IP, no host
    ]
    print("Tests:")
    all_ok = True
    for inp, fn, expected in tests:
        actual = fn(inp)
        ok = actual == expected
        all_ok &= ok
        mark = "✓" if ok else "✗"
        print(f"  {mark}  {fn.__name__}({inp!r}) → {actual!r}  (esperado {expected!r})")
    print(f"\n{'TODOS OK' if all_ok else 'HAY FALLOS'}")
