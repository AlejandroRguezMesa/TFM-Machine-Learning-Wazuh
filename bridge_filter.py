#!/usr/bin/env python3
"""
bridge_filter.py — Filtrado refinado de entidades puente espurias.

Una entidad puente es un identificador (IP, host, usuario) que aparece
en muchos clusters y, al participar en el grafo, fusiona incidentes
distintos en una comunidad-vertedero. Filtrar solo por "fraccion de
clusters" no basta: el hostname del firewall, por ejemplo, aparece
concentrado en pocos clusters grandes pero arrastra todo el volumen.

Este modulo aplica cuatro criterios complementarios. Una entidad se
descarta como puente espurio si cumple CUALQUIERA de ellos:

  1. Fraccion de clusters: aparece en mas del max_cluster_frac del
     total de clusters.
  2. Volumen de alertas: los clusters que la contienen suman mas del
     max_alert_frac del volumen total.
  3. Promiscuidad entre decoders: aparece en clusters de mas de
     max_decoders decoders distintos. Una correlacion cross-source
     genuina conecta 2 o 3 fuentes; tocar 6 o 7 indica infraestructura
     compartida.
  4. Promiscuidad intra-decoder: aparece en mas de max_same_decoder
     clusters que comparten el MISMO decoder dominante. Una entidad
     en 36 clusters de Office 365 es un usuario corporativo o una IP
     proxy comun, no un puente discriminante.

Ademas se mantiene una BLOCKLIST explicita de entidades de
infraestructura conocidas (firewalls, el propio servidor Wazuh,
cuentas de servicio), que se descartan siempre.

USO
---
    from bridge_filter import filter_bridge_entities_v2

    ce_filtrado, info = filter_bridge_entities_v2(
        ce, cluster_alert_count, cluster_decoder,
        max_cluster_frac=0.25, max_alert_frac=0.30, max_decoders=4)

donde:
    ce                  = {cluster_id: set(entidades)}
    cluster_alert_count = {cluster_id: nº alertas originales del cluster}
    cluster_decoder     = {cluster_id: decoder dominante del cluster}
"""
from __future__ import annotations

import re
from collections import defaultdict


# ----------------------------------------------------------------------
# Blocklist de entidades de infraestructura.
# Estas entidades se descartan SIEMPRE: no identifican un activo concreto
# implicado en un incidente, sino infraestructura por la que pasa casi
# todo el trafico. Si participaran en el grafo, fusionarian incidentes no
# relacionados.
#
# Los patrones se comparan contra la entidad ya normalizada (con prefijo
# user:/ip:/host:/asset:). Soportan comodines via expresion regular.
# ----------------------------------------------------------------------
BLOCKLIST_EXACT = {
    # firewalls perimetrales: aparecen en todas las alertas de PaloAlto
    "host:pa-vm300-01", "host:pa-vm300-02",
    "asset:pa-vm300-01", "asset:pa-vm300-02",
    # el propio servidor Wazuh: presente en alertas locales (pam, auditd,
    # ossec, systemd) que no pertenecen a ningun incidente de los escenarios
    "host:wazuh-server", "host:wazuh-manager", "asset:wazuh-server",
    # direcciones e identidades no informativas
    "ip:0.0.0.0", "ip:127.0.0.1", "ip:255.255.255.255",
    "ip:1.1.1.1", "ip:8.8.8.8",
    "user:system", "user:root", "user:anonymous", "user:guest",
    "user:-", "user:none",
    # IPs de relleno emitidas de forma CONSTANTE por el generador de
    # PaloAlto (palo_alto.py): aparecen como destino fijo en alertas
    # THREAT de varios escenarios y actuarian de puente espurio.
    "ip:18.197.147.66", "ip:192.168.3.1",
}

# Patrones regex de entidades de infraestructura. Se comparan contra la
# entidad completa en minusculas.
BLOCKLIST_PATTERNS = [
    re.compile(r"^user:svc-"),          # cuentas de servicio (svc-horizon, svc-vsc, svc-hcx...)
    re.compile(r"^user:lab\..*\.adm$"),  # cuentas administrativas lab.*.adm
    re.compile(r"^host:dc\d+$"),         # controladores de dominio dc1, dc2...
    re.compile(r"^ip:10\.253\.13\."),    # subred de infraestructura del lab
]


def is_infrastructure(entity: str) -> bool:
    """True si la entidad es infraestructura conocida (blocklist)."""
    if not entity:
        return True
    e = entity.lower()
    if e in BLOCKLIST_EXACT:
        return True
    for pat in BLOCKLIST_PATTERNS:
        if pat.search(e):
            return True
    return False


def filter_bridge_entities_v2(ce: dict,
                              cluster_alert_count: dict | None = None,
                              cluster_decoder: dict | None = None,
                              max_cluster_frac: float = 0.25,
                              max_alert_frac: float = 0.30,
                              max_decoders: int = 4,
                              max_same_decoder: int = 12,
                              verbose: bool = True):
    """Filtra entidades puente espurias con cuatro criterios + blocklist.

    Parametros
    ----------
    ce : dict[int, set[str]]
        Entidades por cluster.
    cluster_alert_count : dict[int, int] | None
        Numero de alertas originales por cluster. Si es None, el criterio
        de volumen se desactiva.
    cluster_decoder : dict[int, str] | None
        Decoder dominante por cluster. Si es None, los criterios de
        promiscuidad entre y dentro de decoders se desactivan.
    max_cluster_frac : float
        Umbral del criterio 1 (fraccion de clusters).
    max_alert_frac : float
        Umbral del criterio 2 (fraccion de volumen de alertas).
    max_decoders : int
        Umbral del criterio 3 (numero de decoders distintos).
    max_same_decoder : int
        Umbral del criterio 4 (numero de clusters del mismo decoder).

    Devuelve
    --------
    (ce_filtrado, info) donde info es un dict con las entidades
    descartadas por cada criterio, para trazabilidad y para la memoria.
    """
    n = len(ce)
    if n == 0:
        return ce, {"blocklist": set(), "by_clusters": set(),
                    "by_volume": set(), "by_decoders": set(),
                    "by_same_decoder": set(), "total": set()}

    total_alerts = (sum(cluster_alert_count.values())
                    if cluster_alert_count else 0)
    thr_clusters = max(2, int(round(n * max_cluster_frac)))

    # acumular, por entidad: clusters, alertas, decoders y clusters por
    # decoder en que aparece
    ent_clusters: dict[str, set] = defaultdict(set)
    ent_alerts: dict[str, int] = defaultdict(int)
    ent_decoders: dict[str, set] = defaultdict(set)
    ent_dec_clusters: dict[str, dict] = defaultdict(
        lambda: defaultdict(int))
    for cid, ents in ce.items():
        nalert = (cluster_alert_count or {}).get(cid, 0)
        dec = (cluster_decoder or {}).get(cid)
        for e in ents:
            ent_clusters[e].add(cid)
            ent_alerts[e] += nalert
            if dec:
                ent_decoders[e].add(dec)
                ent_dec_clusters[e][dec] += 1

    drop_blocklist: set[str] = set()
    drop_clusters: set[str] = set()
    drop_volume: set[str] = set()
    drop_decoders: set[str] = set()
    drop_same_decoder: set[str] = set()

    for e in ent_clusters:
        # criterio 0: blocklist explicita
        if is_infrastructure(e):
            drop_blocklist.add(e)
            continue
        # criterio 1: fraccion de clusters
        if len(ent_clusters[e]) >= thr_clusters:
            drop_clusters.add(e)
        # criterio 2: fraccion de volumen de alertas
        if total_alerts and ent_alerts[e] >= total_alerts * max_alert_frac:
            drop_volume.add(e)
        # criterio 3: promiscuidad entre decoders
        # NOTA: usamos > estricto (no >=) deliberadamente. Una correlacion
        # cross-source legitima entre 2-4 fuentes (max_decoders=4 por
        # defecto) NO debe filtrarse; solo descartamos cuando se supera
        # ese limite. Es la principal diferencia con los criterios 1 y 2,
        # que sí usan >=, porque allí el umbral se calcula como fraccion
        # del total y queremos cortar justo al alcanzarlo.
        if len(ent_decoders[e]) > max_decoders:
            drop_decoders.add(e)
        # criterio 4: promiscuidad dentro de un mismo decoder
        # Mismo razonamiento: > estricto deja pasar entidades que tocan
        # exactamente max_same_decoder clusters de un decoder.
        if ent_dec_clusters[e]:
            max_in_one = max(ent_dec_clusters[e].values())
            if max_in_one > max_same_decoder:
                drop_same_decoder.add(e)

    too_common = (drop_blocklist | drop_clusters | drop_volume
                  | drop_decoders | drop_same_decoder)

    if verbose:
        print(f"\n  Filtro de puentes refinado (sobre {n} clusters, "
              f"{total_alerts:,} alertas):")
        print(f"    blocklist infraestructura : {len(drop_blocklist)}")
        print(f"    por fraccion de clusters  : {len(drop_clusters)} "
              f"(umbral ≥{thr_clusters} clusters)")
        print(f"    por volumen de alertas    : {len(drop_volume)} "
              f"(umbral ≥{max_alert_frac:.0%} del volumen)")
        print(f"    por promiscuidad decoders : {len(drop_decoders)} "
              f"(umbral >{max_decoders} decoders)")
        print(f"    por promiscuidad intra-dec: {len(drop_same_decoder)} "
              f"(umbral >{max_same_decoder} clusters de un decoder)")
        print(f"    TOTAL entidades filtradas : {len(too_common)}")
        # mostrar las mas relevantes con su motivo
        shown = sorted(too_common,
                       key=lambda x: -ent_alerts.get(x, 0))[:12]
        if shown:
            print("    entidades filtradas mas voluminosas:")
            for e in shown:
                motivos = []
                if e in drop_blocklist:     motivos.append("blocklist")
                if e in drop_clusters:      motivos.append("clusters")
                if e in drop_volume:        motivos.append("volumen")
                if e in drop_decoders:      motivos.append("decoders")
                if e in drop_same_decoder:  motivos.append("intra-dec")
                print(f"      {ent_alerts.get(e,0):>6} alertas  "
                      f"{len(ent_clusters.get(e,set())):>3} clusters  "
                      f"{e}  [{','.join(motivos)}]")

    info = {
        "blocklist": drop_blocklist,
        "by_clusters": drop_clusters,
        "by_volume": drop_volume,
        "by_decoders": drop_decoders,
        "by_same_decoder": drop_same_decoder,
        "total": too_common,
    }
    ce_filtrado = {cid: ents - too_common for cid, ents in ce.items()}
    return ce_filtrado, info


if __name__ == "__main__":
    # Prueba minima con datos sinteticos
    ce = {
        0: {"host:pa-vm300-01", "ip:10.99.6.180", "user:tfm.s06.victim1"},
        1: {"host:pa-vm300-01", "ip:10.99.6.181", "user:tfm.s06.victim2"},
        2: {"host:pa-vm300-01", "user:svc-horizon", "ip:10.253.13.25"},
        3: {"user:tfm.s06.victim1", "ip:185.220.101.45"},
    }
    cac = {0: 100, 1: 90, 2: 500, 3: 30}
    cdec = {0: "paloalto", 1: "paloalto", 2: "vcenter", 3: "json"}
    ce2, info = filter_bridge_entities_v2(ce, cac, cdec,
                                          max_cluster_frac=0.5,
                                          max_alert_frac=0.30,
                                          max_decoders=2)
    print("\nResultado:")
    for cid, ents in ce2.items():
        print(f"  cluster {cid}: {sorted(ents)}")
