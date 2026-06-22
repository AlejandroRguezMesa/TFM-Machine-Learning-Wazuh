#!/usr/bin/env python3
"""
asset_map.py — Mapa de activos y resolución de la dualidad IP <-> hostname.

PROBLEMA QUE RESUELVE
---------------------
Una misma máquina aparece identificada de forma distinta según la fuente:

  - SentinelOne / vCenter  ->  por hostname    (host:tfm-srv-file01)
  - PaloAlto               ->  por dirección IP (ip:10.99.7.49)

La normalización canónica de normalize.py trata 'host:tfm-srv-file01' e
'ip:10.99.7.49' como DOS entidades distintas. El grafo de la Capa 3 nunca
construye la arista que las conectaría, y los escenarios cross-source que
dependen de esa equivalencia (S07, S08) quedan partidos.

Este módulo construye un mapa IP<->hostname y expone una funcion de
resolucion que unifica ambas formas en una unica entidad canonica de
activo, con prefijo 'asset:'.

FUENTES DE VERDAD DEL MAPA (por orden de fiabilidad)
----------------------------------------------------
  1. SentinelOne: cada alerta del EDR trae agentIpV4 Y agentComputerName
     en el MISMO documento. Es un par (ip, host) observado y fiable.
  2. Escenarios YAML: declaran explicitamente victim_hostN junto a
     victim_ipN. Son pares conocidos por diseno.
  3. vCenter vMotion y eventos 'host (ip)': pares adicionales que algunos
     eventos exponen de forma conjunta.
  4. Mapa estatico semilla: pares conocidos del laboratorio que no
     aparecen de forma conjunta en ninguna alerta.

DUALIDAD DE IDENTIDAD DE USUARIO
--------------------------------
El mismo problema afecta a los usuarios. Un mismo individuo aparece como
'tfm.s08.carlos' en Office 365 y como 'tfm-s08-carlos' en vCenter / AD
(punto frente a guion). normalize.py los deja como dos usuarios distintos.
Este modulo tambien resuelve esos alias a una identidad canonica de
usuario, a partir de los bloques 'entities' de los YAML, que declaran las
formas victimN_o365 y victimN_ad de la misma persona.

El mapa se construye una vez por ejecucion y se persiste en
lab_state/asset_map.json para inspeccion y reproducibilidad.

USO
---
    from asset_map import AssetMap

    amap = AssetMap.build(scenario_dir="scenarios",
                          sentinelone_pairs=descubiertos,
                          seed=SEED_PAIRS)
    amap.save("lab_state/asset_map.json")

    # Resolver una entidad canonica a su activo (o devolverla intacta):
    canon = amap.resolve("ip:10.99.7.49")     # -> "asset:tfm-srv-file01"
    canon = amap.resolve("host:tfm-srv-file01")# -> "asset:tfm-srv-file01"
    canon = amap.resolve("ip:8.8.8.8")         # -> "ip:8.8.8.8" (sin mapa)
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ImportError:
    yaml = None


# ----------------------------------------------------------------------
# Mapa estatico semilla.
# Pares (ip, hostname) conocidos del laboratorio que pueden no aparecer
# de forma conjunta en ninguna alerta. Anade aqui los activos fijos del
# entorno (controladores de dominio, servidores de servicio, etc.).
# Los nombres se guardan ya en minusculas; las IPs como cadena.
# ----------------------------------------------------------------------
SEED_PAIRS: list[tuple[str, str]] = [
    # IP de laboratorio del agente SentinelOne por defecto
    ("10.0.5.20", "desktop-user001"),
]


# Entidades que NUNCA deben entrar al mapa de activos como nodo: son
# infraestructura compartida o direcciones no informativas. Si se
# mapearan, fusionarian medio grafo.
_BLOCKLIST_HOSTS = {
    "pa-vm300-01", "pa-vm300-02", "wazuh-server", "wazuh-manager",
    "localhost", "none", "null", "unknown", "-",
}
_BLOCKLIST_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1",
}


def _clean_host(h: str | None) -> str | None:
    """Reduce un hostname a su nombre corto en minusculas, sin sufijos
    de dominio. Devuelve None si no es utilizable."""
    if not isinstance(h, str) or not h.strip():
        return None
    s = h.strip().lower()
    # quitar prefijo canonico si lo trae
    if s.startswith("host:"):
        s = s[5:]
    # quitar sufijos de dominio
    for suf in (".labcorp.local", ".labcorp.local", ".corp.local",
                ".domain.local", ".vsphere.local", ".local"):
        if s.endswith(suf):
            s = s[: -len(suf)]
            break
    s = s.strip()
    if not s or s in _BLOCKLIST_HOSTS:
        return None
    return s


def _clean_ip(ip: str | None) -> str | None:
    """Reduce una IP a su forma simple. Devuelve None si no es utilizable."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    s = ip.strip()
    if s.startswith("ip:"):
        s = s[3:]
    if "/" in s:
        s = s.split("/")[0]
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    s = s.strip()
    if not s or s in _BLOCKLIST_IPS:
        return None
    # validacion minima de forma IPv4
    parts = s.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255
                                  for p in parts):
        return None
    return s


# Usuarios genericos que no identifican a una persona y no deben
# participar en la resolucion de alias.
_BLOCKLIST_USERS = {
    "system", "anonymous", "guest", "root", "administrator", "admin",
    "none", "null", "unknown", "-", "",
}


def _clean_user(u: str | None) -> str | None:
    """Reduce un usuario a su nombre corto en minusculas, sin dominio.

    Aplica la misma logica que normalize.norm_user: quita 'DOMINIO\\' y
    '@dominio'. Devuelve el nombre tal cual (con sus puntos o guiones),
    NO la clave de identidad: para eso esta _user_identity_key.
    """
    if not isinstance(u, str) or not u.strip():
        return None
    s = u.strip().lower()
    if s.startswith("user:"):
        s = s[5:]
    if "\\" in s:
        s = s.split("\\")[-1]
    if "@" in s:
        s = s.split("@")[0]
    s = s.strip().rstrip(",.;:")
    if not s or s in _BLOCKLIST_USERS:
        return None
    return s


def _user_identity_key(u: str | None) -> str | None:
    """Clave de comparacion de identidad: nombre corto con separadores
    unificados. 'tfm.s08.carlos' y 'tfm-s08-carlos' producen la misma
    clave 'tfm s08 carlos', lo que permite detectar que son la misma
    persona pese a la distinta convencion de nomenclatura."""
    s = _clean_user(u)
    if s is None:
        return None
    # unificar puntos, guiones y guiones bajos a un separador comun
    return re.sub(r"[._\-]+", " ", s).strip()


class AssetMap:
    """Mapa bidireccional IP <-> hostname con resolucion a entidad de activo.

    El identificador canonico de un activo es siempre su hostname corto.
    La entidad canonica que expone resolve() es 'asset:<hostname>'.
    """

    def __init__(self) -> None:
        self.ip_to_host: dict[str, str] = {}
        self.host_to_ips: dict[str, set[str]] = defaultdict(set)
        # trazabilidad: de donde sale cada par
        self.sources: dict[tuple[str, str], str] = {}
        # alias de identidad de usuario: nombre corto -> usuario canonico.
        # La forma canonica elegida es la variante con puntos (estilo
        # Office 365), por ser la mas legible.
        self.user_alias: dict[str, str] = {}
        # trazabilidad de los alias
        self.user_sources: dict[str, str] = {}
        # UserAnonymizer opcional. Si esta presente, resolve() puede
        # unificar identidades en parquets anonimizados: alias ->
        # canonico real (tfm-s08-alberto) -> forma unificada en
        # user_alias (tfm.s08.alberto) -> alias destino.
        self._anonymizer = None

    # ------------------------------------------------------------------
    # Construccion del mapa
    # ------------------------------------------------------------------
    def add_pair(self, ip: str | None, host: str | None,
                 source: str = "?") -> bool:
        """Registra un par (ip, host). Devuelve True si se anadio."""
        ci = _clean_ip(ip)
        ch = _clean_host(host)
        if ci is None or ch is None:
            return False
        # conflicto: una IP ya mapeada a otro host. Conservamos el primero
        # y lo registramos, pero no sobreescribimos (la IP puede haberse
        # reasignado; preferimos estabilidad sobre recencia).
        if ci in self.ip_to_host and self.ip_to_host[ci] != ch:
            return False
        self.ip_to_host[ci] = ch
        self.host_to_ips[ch].add(ci)
        self.sources[(ci, ch)] = source
        return True

    def add_user_alias(self, variants: Iterable[str],
                       source: str = "?") -> bool:
        """Registra que un conjunto de formas de usuario son la misma
        persona. Todas las variantes se mapean a una forma canonica.

        Se elige como canonica la variante que contiene un punto (estilo
        Office 365); si ninguna lo tiene, la primera por orden alfabetico.
        Devuelve True si se registro al menos un alias nuevo.
        """
        clean = [c for c in (_clean_user(v) for v in variants) if c]
        # deduplicar conservando orden
        seen: set[str] = set()
        uniq = [c for c in clean if not (c in seen or seen.add(c))]
        if len(uniq) < 2:
            return False
        # forma canonica: la que tiene punto, o la primera ordenada
        canon = next((u for u in uniq if "." in u), sorted(uniq)[0])
        added = False
        for v in uniq:
            if v != canon and self.user_alias.get(v) != canon:
                self.user_alias[v] = canon
                self.user_sources[v] = source
                added = True
        return added

    @classmethod
    def build(cls,
              scenario_dir: str | None = "scenarios",
              sentinelone_pairs: Iterable[tuple[str, str]] | None = None,
              extra_pairs: Iterable[tuple[str, str]] | None = None,
              seed: Iterable[tuple[str, str]] | None = SEED_PAIRS,
              verbose: bool = True) -> "AssetMap":
        """Construye el mapa combinando todas las fuentes de verdad."""
        amap = cls()
        n_seed = n_s1 = n_yaml = n_extra = n_alias = 0

        # 1. Semilla estatica
        for ip, host in (seed or []):
            if amap.add_pair(ip, host, source="seed"):
                n_seed += 1

        # 2. Pares descubiertos en alertas de SentinelOne
        for ip, host in (sentinelone_pairs or []):
            if amap.add_pair(ip, host, source="sentinelone"):
                n_s1 += 1

        # 3. Escenarios YAML: pares ip/host y grupos de alias de usuario
        if scenario_dir:
            yaml_pairs, alias_groups = cls._scan_scenarios(scenario_dir)
            for ip, host in yaml_pairs:
                if amap.add_pair(ip, host, source="scenario_yaml"):
                    n_yaml += 1
            for group in alias_groups:
                if amap.add_user_alias(group, source="scenario_yaml"):
                    n_alias += 1

        # 4. Pares adicionales (p.ej. vMotion de vCenter)
        for ip, host in (extra_pairs or []):
            if amap.add_pair(ip, host, source="extra"):
                n_extra += 1

        if verbose:
            print(f"[asset_map] mapa construido: {len(amap.ip_to_host)} "
                  f"IPs -> {len(amap.host_to_ips)} hosts; "
                  f"{len(amap.user_alias)} alias de usuario")
            print(f"[asset_map]   semilla={n_seed}  sentinelone={n_s1}  "
                  f"yaml={n_yaml}  extra={n_extra}  grupos_alias={n_alias}")
        return amap

    @staticmethod
    def _scan_scenarios(scenario_dir: str
                        ) -> tuple[list[tuple[str, str]],
                                   list[list[str]]]:
        """Recorre los YAML de escenario una sola vez y extrae:

          - pares (ip, host): emparejados por sufijo numerico compartido
            (victim_host1 con victim_ip1, etc.)
          - grupos de alias de usuario: claves de una misma victima en
            sus formas o365 y ad (victim1_o365 con victim1_ad, etc.)

        Devuelve la tupla (pares, grupos_de_alias).
        """
        pairs: list[tuple[str, str]] = []
        alias_groups: list[list[str]] = []
        d = Path(scenario_dir)
        if not d.is_dir():
            return pairs, alias_groups
        if yaml is None:
            print("[asset_map] aviso: PyYAML no disponible, se omiten YAML")
            return pairs, alias_groups

        for yf in sorted(d.glob("*.yaml")):
            try:
                doc = yaml.safe_load(yf.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[asset_map] aviso: no se pudo leer {yf.name}: {e}")
                continue
            ents = (doc or {}).get("entities", {})
            if not isinstance(ents, dict):
                continue

            # --- pares ip/host ---
            host_keys = {k: v for k, v in ents.items()
                         if "host" in k.lower()}
            ip_keys = {k: v for k, v in ents.items()
                       if re.search(r"(^|_)ip(\d|_|$)", k.lower())}
            for hk, hv in host_keys.items():
                m = re.search(r"(\d+)$", hk)
                suffix = m.group(1) if m else ""
                cand = None
                for ik, iv in ip_keys.items():
                    if suffix and ik.endswith(suffix):
                        cand = iv
                        break
                if cand is None and len(ip_keys) == 1 and len(host_keys) == 1:
                    cand = next(iter(ip_keys.values()))
                if cand:
                    pairs.append((str(cand), str(hv)))

            # --- grupos de alias de usuario ---
            # se agrupan las claves de usuario por su raiz comun, es decir
            # el nombre de clave sin el sufijo de fuente (_o365, _ad, ...).
            # Ejemplo: victim1_o365 y victim1_ad comparten raiz 'victim1'.
            user_keys = {k: v for k, v in ents.items()
                         if isinstance(v, str)
                         and ("victim" in k.lower() or "user" in k.lower())
                         and "ip" not in k.lower()
                         and "host" not in k.lower()}
            by_root: dict[str, list[str]] = defaultdict(list)
            for k, v in user_keys.items():
                root = re.sub(
                    r"_(o365|ad|azure|vcenter|vc|win|windows|email|upn)$",
                    "", k.lower())
                by_root[root].append(v)
            for root, vals in by_root.items():
                if len(vals) >= 2:
                    alias_groups.append([str(x) for x in vals])

        return pairs, alias_groups

    # ------------------------------------------------------------------
    # Resolucion
    # ------------------------------------------------------------------
    def resolve(self, entity: str | None) -> str | None:
        """Resuelve una entidad canonica a su forma unificada.

        - 'ip:X'   -> 'asset:<host>' si X esta en el mapa, si no 'ip:X'
        - 'host:Y' -> 'asset:<y>'    si Y esta en el mapa, si no 'host:Y'
        - 'user:Z' -> 'user:<canon>' si Z es un alias conocido, si no
                      'user:Z'
        - None     -> None

        La resolucion de IP/host unifica la dualidad maquina; la de
        usuario unifica la dualidad de identidad (punto frente a guion
        entre Office 365 y vCenter / AD).
        """
        if not entity or not isinstance(entity, str):
            return entity
        if entity.startswith("ip:"):
            ip = _clean_ip(entity)
            if ip and ip in self.ip_to_host:
                return f"asset:{self.ip_to_host[ip]}"
            return entity
        if entity.startswith("host:"):
            host = _clean_host(entity)
            if host and host in self.host_to_ips:
                return f"asset:{host}"
            return entity
        if entity.startswith("user:"):
            user = _clean_user(entity)
            if user is None:
                return entity
            # Parquet anonimizado: 'user' es 'user_NNNN_anonymized' y no
            # esta en user_alias (cuyas claves son canonicos reales como
            # 'tfm-s08-alberto'). Si hay UserAnonymizer asociado se hace
            # el rebote alias -> canonico -> forma unificada -> alias.
            if self._anonymizer is not None:
                raw = self._anonymizer.reverse(user)
                if raw and raw != user:
                    canon_unified = self.user_alias.get(raw)
                    if canon_unified and canon_unified != raw:
                        new_alias = self._anonymizer.lookup(canon_unified)
                        if new_alias:
                            return f"user:{new_alias}"
                    return entity
            # Parquet sin anonimizar: lookup directo contra el mapa canonico.
            if user in self.user_alias:
                return f"user:{self.user_alias[user]}"
            return entity
        # cualquier otro prefijo: intacto
        return entity

    def attach_anonymizer(self, anonymizer) -> None:
        """Asocia un UserAnonymizer para activar la resolucion de alias
        de usuario tambien en espacio anonimizado. Ver __init__."""
        self._anonymizer = anonymizer

    def resolve_set(self, entities: Iterable[str]) -> set[str]:
        """Resuelve un conjunto de entidades, deduplicando el resultado."""
        out: set[str] = set()
        for e in entities or []:
            r = self.resolve(e)
            if r:
                out.add(r)
        return out

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ip_to_host": self.ip_to_host,
            "host_to_ips": {h: sorted(ips)
                            for h, ips in self.host_to_ips.items()},
            "sources": {f"{ip}|{host}": src
                        for (ip, host), src in self.sources.items()},
            "user_alias": self.user_alias,
            "user_sources": self.user_sources,
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        print(f"[asset_map] guardado -> {path}")

    @classmethod
    def load(cls, path: str | Path) -> "AssetMap":
        amap = cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        amap.ip_to_host = dict(data.get("ip_to_host", {}))
        for h, ips in data.get("host_to_ips", {}).items():
            amap.host_to_ips[h] = set(ips)
        for k, src in data.get("sources", {}).items():
            ip, _, host = k.partition("|")
            amap.sources[(ip, host)] = src
        amap.user_alias = dict(data.get("user_alias", {}))
        amap.user_sources = dict(data.get("user_sources", {}))
        return amap

    def stats(self) -> dict:
        """Resumen numerico del mapa, util para logs y para la memoria."""
        return {
            "n_ips": len(self.ip_to_host),
            "n_hosts": len(self.host_to_ips),
            "n_user_aliases": len(self.user_alias),
            "n_canonical_users": len(set(self.user_alias.values())),
        }

    def __len__(self) -> int:
        return len(self.ip_to_host)


# ----------------------------------------------------------------------
# Descubrimiento de pares desde alertas de SentinelOne
# ----------------------------------------------------------------------
def discover_sentinelone_pairs(alerts: Iterable[dict]) -> list[tuple[str, str]]:
    """Recorre alertas crudas de Wazuh y extrae pares (ip, host) de los
    documentos de SentinelOne, que traen agentIpV4 y agentComputerName
    en la misma alerta.

    Acepta alertas ya aplanadas (claves 'data.<...>') o anidadas.
    """
    pairs: list[tuple[str, str]] = []
    for a in alerts:
        ip = host = None
        # forma aplanada
        for k in ("data.agentDetectionInfo.agentIpV4",
                  "data.agentRealtimeInfo.agentComputerName",
                  "data.agentDetectionInfo.agentComputerName",
                  "data.computerName"):
            v = a.get(k) if hasattr(a, "get") else None
            if v and ("IpV4" in k) and ip is None:
                ip = v
            elif v and ("ComputerName" in k or k.endswith("computerName")) \
                    and host is None:
                host = v
        if ip and host:
            pairs.append((str(ip), str(host)))
    return pairs


if __name__ == "__main__":
    # Construccion de prueba: solo semilla + escenarios YAML
    amap = AssetMap.build(scenario_dir="scenarios", verbose=True)
    print()
    print("Pares IP <-> host:")
    for ip, host in sorted(amap.ip_to_host.items()):
        src = amap.sources.get((ip, host), "?")
        print(f"  ip:{ip:18} -> asset:{host:24} [{src}]")
    print()
    print("Alias de identidad de usuario:")
    for variant, canon in sorted(amap.user_alias.items()):
        print(f"  user:{variant:24} -> user:{canon}")
    print()
    # Pruebas de resolucion
    tests = [
        "ip:10.99.7.49", "host:tfm-srv-file01", "ip:8.8.8.8",
        "host:pa-vm300-01",
        "user:tfm.s08.carlos", "user:tfm-s08-carlos",
        "user:tfm-s08-maria", "user:lab.user1",
    ]
    print("Pruebas de resolucion:")
    for t in tests:
        print(f"  {t:28} -> {amap.resolve(t)}")
    print()
    print("Stats:", amap.stats())
