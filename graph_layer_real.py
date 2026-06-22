#!/usr/bin/env python3
"""
graph_layer_real.py — Capa 3 sobre datos reales (grafo de FILAS).

Construye un grafo con un nodo por fila deduplicada del parquet y
traza aristas entre filas que comparten entidades resueltas
(IP, host, usuario). Sobre ese grafo corre Louvain para detectar
comunidades de filas que representan incidentes correlacionados.

Trabajar en granularidad de fila evita que un cluster de la Capa 2
que haya mezclado dos incidentes distintos arrastre a ambos a la
misma comunidad: dos filas solo se conectan si comparten una entidad
real. La Capa 2 sigue corriendo y su `cluster_id` se conserva en la
salida para KPIs de reduccion y analisis, pero no es el sustrato del
grafo.

Para acotar la fragmentacion que un grafo de filas puede producir, se
aplica una consolidacion final: las comunidades muy pequenas que
comparten entidad dominante y ventana temporal con una comunidad mayor
se absorben en ella.

Uso:
  python3 graph_layer_real.py
  python3 graph_layer_real.py --min-shared 1 --min-weight 1.5
"""
from __future__ import annotations
import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import networkx as nx
    from networkx.algorithms.community import louvain_communities
except ImportError:
    raise SystemExit("pip install networkx")

# Mapa de activos: resuelve la dualidad IP/host e identidad de usuario
sys.path.insert(0, str(Path(__file__).resolve().parent))
from asset_map import AssetMap
from bridge_filter import is_infrastructure
from anonymization import maybe_load as _maybe_load_anon


IN  = Path("lab_state/real_alerts_clustered.parquet")
OUT = Path("lab_state/real_alerts_incidents.parquet")


def _iter_entities(v):
    """Itera sobre entidades de una celda Parquet (lista, np.ndarray o
    None) de forma segura."""
    if v is None:
        return
    if isinstance(v, (list, tuple, np.ndarray)):
        for x in v:
            if x:
                yield x
    elif isinstance(v, str) and v:
        yield v


def _sentinelone_pairs_from_df(df):
    """Extrae pares (ip, host) de las filas de SentinelOne que traen IP y
    host a la vez. Alimenta el AssetMap con pares observados en datos
    reales."""
    pairs = []
    if "decoder.name" not in df.columns:
        return pairs
    mask = df["decoder.name"].astype(str).str.contains(
        "sentinel", case=False, na=False)
    for _, r in df[mask].iterrows():
        ips = [str(x) for x in _iter_entities(r.get("entity_ips"))]
        hosts = [str(x) for x in _iter_entities(r.get("entity_hosts"))]
        if len(ips) == 1 and len(hosts) == 1:
            pairs.append((ips[0], hosts[0]))
    return pairs


def build_row_entities(df, amap=None):
    """Para cada FILA del DataFrame, el conjunto de entidades canonicas
    que contiene. Si se pasa un AssetMap, las entidades se resuelven a su
    forma unificada (asset:<host>, usuario canonico). Las entidades de
    infraestructura (blocklist de bridge_filter) se descartan: nunca deben
    actuar de puente entre incidentes."""
    row_ents = []
    for _, r in df.iterrows():
        ents = set()
        for col in ("entity_users", "entity_ips", "entity_hosts"):
            for x in _iter_entities(r.get(col)):
                ents.add(str(x))
        if amap is not None:
            ents = amap.resolve_set(ents)
        # descartar infraestructura: no discrimina incidentes
        ents = {e for e in ents if not is_infrastructure(e)}
        row_ents.append(ents)
    return row_ents


def filter_promiscuous_entities(row_ents, max_rows_frac=0.10,
                                 max_decoders=4, decoders=None,
                                 verbose=True):
    """Descarta entidades demasiado promiscuas para ser puentes utiles:

      - presentes en mas del max_rows_frac de las filas;
      - presentes en filas de mas de max_decoders decoders distintos.

    Devuelve (row_ents_filtrado, set_descartadas)."""
    n = len(row_ents)
    if n == 0:
        return row_ents, set()
    ent_rows = defaultdict(int)
    ent_decs = defaultdict(set)
    for i, ents in enumerate(row_ents):
        dec = decoders[i] if decoders is not None else None
        for e in ents:
            ent_rows[e] += 1
            if dec:
                ent_decs[e].add(dec)
    thr_rows = max(3, int(round(n * max_rows_frac)))
    drop = set()
    for e, c in ent_rows.items():
        if c >= thr_rows:
            drop.add(e)
        elif len(ent_decs[e]) > max_decoders:
            drop.add(e)
    if verbose and drop:
        print(f"\n  Filtro de entidades promiscuas: {len(drop)} descartadas")
        print(f"    (umbral: >={thr_rows} filas o >{max_decoders} decoders)")
        for e in sorted(drop, key=lambda x: -ent_rows[x])[:10]:
            print(f"      {ent_rows[e]:>5} filas  {len(ent_decs[e])} dec  {e}")
    return [ents - drop for ents in row_ents], drop


DECAY_KINDS = ("exponential", "gaussian", "linear", "power", "none")


def temporal_decay(dt_seconds, kind="exponential", tau=300.0,
                   hard_cutoff=None):
    """Funcion de decaimiento temporal f(Dt) usada para modular el peso
    de las aristas del grafo de correlacion.

    Parametros
    ----------
    dt_seconds : float
        Distancia temporal entre dos filas, en segundos. Convencion: si
        sus intervalos [first_seen, last_seen] solapan, Dt = 0; en otro
        caso, Dt es el gap entre el final de uno y el inicio del otro.
    kind : str
        Familia de la funcion de decaimiento. Una de:
          - 'exponential': f(Dt) = exp(-Dt/tau).  f(tau) ~ 0.37.
          - 'gaussian':    f(Dt) = exp(-(Dt/tau)^2). Pendiente suave
                           cerca de 0, abrupta mas alla de tau.
          - 'linear':      f(Dt) = max(0, 1 - Dt/tau). Llega a 0 en tau.
          - 'power':       f(Dt) = 1 / (1 + Dt/tau). Cola larga.
          - 'none':        f(Dt) = 1 siempre (desactiva el decaimiento).
    tau : float
        Escala temporal en segundos. Controla la rapidez con la que el
        peso decae. Debe ser > 0 si kind != 'none'.
    hard_cutoff : float or None
        Si no es None y Dt > hard_cutoff, devuelve 0 (no se crea
        arista). Util para imponer una ventana de correlacion maxima
        dura, independiente de la forma de f.
    """
    if hard_cutoff is not None and dt_seconds > hard_cutoff:
        return 0.0
    if kind == "none":
        return 1.0
    if tau is None or tau <= 0:
        return 1.0 if dt_seconds <= 0 else 0.0
    x = float(dt_seconds) / float(tau)
    if kind == "exponential":
        return float(np.exp(-x))
    if kind == "gaussian":
        return float(np.exp(-x * x))
    if kind == "linear":
        return max(0.0, 1.0 - x)
    if kind == "power":
        return 1.0 / (1.0 + x)
    raise ValueError(f"Funcion de decaimiento desconocida: {kind!r}")


_UNIT_TO_SECONDS = {
    "s":  1.0,
    "ms": 1e3,
    "us": 1e6,
    "ns": 1e9,
}


def _series_to_seconds(series):
    """Convierte una Series datetime64 a float64 con segundos desde epoch.

    La resolucion del datetime64 (s / ms / us / ns) se detecta a partir
    de `dtype.unit`; pandas >= 2.0 preserva la precision original del
    parquet (aqui 'us'), por lo que un divisor fijo a 1e9 daria valores
    1000x mas pequenos. Si la unidad es desconocida se asume 'ns'."""
    s = pd.to_datetime(series, utc=True)
    unit = getattr(s.dtype, "unit", None) or "ns"
    divisor = _UNIT_TO_SECONDS.get(unit, 1e9)
    arr = np.asarray(s.astype("int64"), dtype=np.float64) / divisor
    return arr


def _row_intervals_seconds(first_seen, last_seen):
    """Convierte dos Series datetime64 a arrays float64 (segundos desde
    epoch). Devuelve (None, None) si alguna falta. La resolucion se
    detecta dinamicamente (ver `_series_to_seconds`)."""
    if first_seen is None or last_seen is None:
        return None, None
    t0 = _series_to_seconds(first_seen)
    t1 = _series_to_seconds(last_seen)
    return t0, t1


def build_row_graph(row_ents, min_shared, min_weight,
                    first_seen=None, last_seen=None,
                    decay_kind="exponential", decay_tau=300.0,
                    decay_hard_cutoff=None):
    """Construye el grafo de filas, conectando pares que comparten
    entidades y modulando el peso por la distancia temporal entre ellas.

    El peso base es el numero de entidades compartidas. Sobre ese
    valor se multiplica f(Dt), una funcion decreciente de la distancia
    temporal entre los intervalos [first_seen, last_seen] de las dos
    filas. Asi dos alertas con la misma IP separadas por horas pesan
    menos que dos separadas por segundos y son mas faciles de cortar
    en Louvain.

    Parametros temporales
    ---------------------
    first_seen, last_seen : array-like de timestamps (mismo orden que
        row_ents). Si alguno es None se desactiva el decaimiento y el
        peso se queda en el numero crudo de entidades compartidas.
    decay_kind : ver `temporal_decay`. Default 'exponential'.
    decay_tau  : escala en segundos. Default 300 s (5 min).
    decay_hard_cutoff : segundos. None = sin corte duro.

    Filtros de peso
    ---------------
    `min_shared` filtra por el numero CRUDO de entidades compartidas
    (entero >= 1). `min_weight` filtra por el peso FINAL tras el
    decaimiento. Con decay activo y `min_weight=1.0`, dos filas con
    una sola entidad compartida caen bajo el umbral en cuanto f(Dt)<1;
    por eso el default es 0.0 y la poda por debilidad temporal se
    controla con `decay_hard_cutoff` o subiendo `min_weight`
    explicitamente.
    """
    G = nx.Graph()
    G.add_nodes_from(range(len(row_ents)))

    inverted = defaultdict(set)
    for i, ents in enumerate(row_ents):
        for e in ents:
            inverted[e].add(i)

    edge_n = defaultdict(int)
    for e, rows in inverted.items():
        rl = sorted(rows)
        # entidades que tocan demasiadas filas ya se filtraron antes;
        # aqui acotamos el coste cuadratico por seguridad
        if len(rl) > 400:
            continue
        for i in range(len(rl)):
            for j in range(i + 1, len(rl)):
                edge_n[(rl[i], rl[j])] += 1

    t0, t1 = _row_intervals_seconds(first_seen, last_seen)
    # Solo nos saltamos el calculo de Dt si no hay timestamps. Si los
    # hay, evaluamos siempre temporal_decay para que `hard_cutoff`
    # funcione incluso con decay_kind='none'.
    use_dt = (t0 is not None and t1 is not None)

    for (a, b), shared in edge_n.items():
        if shared < min_shared:
            continue
        if use_dt:
            dt = max(0.0, max(t0[a], t0[b]) - min(t1[a], t1[b]))
            f = temporal_decay(dt, kind=decay_kind, tau=decay_tau,
                               hard_cutoff=decay_hard_cutoff)
            if f <= 0.0:
                continue
            w = float(shared) * f
        else:
            w = float(shared)
        if w >= min_weight:
            G.add_edge(a, b, weight=w)
    return G


def detect_communities(G, row_ents):
    """Detecta comunidades con Louvain. Las filas sin ninguna entidad
    util (nodos aislados que solo lo estan por carecer de entidad, no
    por ser un incidente unipersonal) se marcan como ruido (-1): no
    deben inflar el recuento de comunidades ni el factor de reduccion.
    Un nodo aislado que SI tiene entidad se conserva como comunidad
    propia (es un incidente real de una sola fila)."""
    if G.number_of_edges() == 0:
        part = {}
        nxt = 0
        for n in G.nodes():
            if row_ents[n]:
                part[n] = nxt
                nxt += 1
            else:
                part[n] = -1
        return part
    comms = louvain_communities(G, weight="weight", seed=42)
    part = {int(n): i for i, nodes in enumerate(comms) for n in nodes}
    # reasignar a ruido los nodos aislados sin entidad
    for n in G.nodes():
        if G.degree(n) == 0 and not row_ents[n]:
            part[n] = -1
    # renumerar compacto
    uniq = sorted({v for v in part.values() if v >= 0})
    relabel = {old: new for new, old in enumerate(uniq)}
    return {n: relabel.get(c, -1) for n, c in part.items()}


def consolidate_small(df, partition, row_ents, min_size=3):
    """Reduce la fragmentacion del grafo de filas mediante un segundo
    pase de agrupacion SOBRE LAS COMUNIDADES.

    Una comunidad pequena (menos de min_size filas) se fusiona con otra
    comunidad si ambas comparten al menos una entidad y sus ventanas
    temporales se solapan. Esto reabsorbe las filas que el grafo de
    filas dejo aisladas por no alcanzar el umbral de arista, sin volver
    a fusionar incidentes distintos: la condicion de entidad compartida
    + solape temporal es la misma que usa el grafo de filas, solo que
    aplicada a nivel de comunidad.

    Devuelve un nuevo dict {row_idx: community_id} renumerado.
    """
    df = df.copy()
    df["_c"] = [partition.get(i, -1) for i in range(len(df))]

    # entidades y ventana de cada comunidad
    comm_ents = defaultdict(set)
    comm_t0, comm_t1, comm_size = {}, {}, {}
    for c, sub in df.groupby("_c"):
        if c < 0:
            continue
        for idx in sub.index:
            comm_ents[c] |= row_ents[idx]
        comm_t0[c] = sub["first_seen"].min()
        comm_t1[c] = sub["last_seen"].max()
        comm_size[c] = len(sub)

    # grafo de comunidades: une comunidades con entidad compartida y
    # solape temporal; SOLO se permite fusionar si al menos una de las
    # dos es pequena (evita re-fundir dos incidentes grandes)
    inv = defaultdict(set)
    for c, ents in comm_ents.items():
        for e in ents:
            inv[e].add(c)

    Gc = nx.Graph()
    Gc.add_nodes_from(comm_ents.keys())
    for e, comms in inv.items():
        cl = sorted(comms)
        for i in range(len(cl)):
            for j in range(i + 1, len(cl)):
                a, b = cl[i], cl[j]
                if comm_size[a] >= min_size and comm_size[b] >= min_size:
                    continue  # dos comunidades grandes: no fusionar
                # solape temporal
                if comm_t0[a] <= comm_t1[b] and comm_t1[a] >= comm_t0[b]:
                    Gc.add_edge(a, b)

    # componentes conexas -> nueva etiqueta
    remap = {}
    for comp in nx.connected_components(Gc):
        # la etiqueta destino es la comunidad mayor de la componente
        target = max(comp, key=lambda c: comm_size.get(c, 0))
        for c in comp:
            remap[c] = target
    for c in comm_ents:
        remap.setdefault(c, c)

    new_part = {}
    for i in range(len(df)):
        c = partition.get(i, -1)
        new_part[i] = remap.get(c, c) if c >= 0 else -1
    # renumerar compacto
    uniq = sorted({v for v in new_part.values() if v >= 0})
    relabel = {old: new for new, old in enumerate(uniq)}
    return {i: relabel.get(c, -1) for i, c in new_part.items()}


def report_communities(df):
    print("\n" + "=" * 72)
    print("  TOP COMUNIDADES POR ALERTAS ABSORBIDAS")
    print("=" * 72)
    summary = df[df["community_id"] >= 0].groupby("community_id").agg(
        n_filas=("community_id", "size"),
        n_clusters=("cluster_id", "nunique"),
        n_alerts=("count", "sum"),
        decoders=("decoder.name", lambda s: ",".join(sorted(set(s)))),
        first=("first_seen", "min"),
        last=("last_seen", "max"),
    ).sort_values("n_alerts", ascending=False)

    for comm, row in summary.head(15).iterrows():
        sub = df[df["community_id"] == comm]
        ips, users, hosts, rules = Counter(), Counter(), Counter(), Counter()
        for _, r in sub.iterrows():
            for x in _iter_entities(r["entity_ips"]):    ips[x] += 1
            for x in _iter_entities(r["entity_users"]):  users[x] += 1
            for x in _iter_entities(r["entity_hosts"]):  hosts[x] += 1
            rules[str(r["rule.id"])] += 1
        top_ips   = ", ".join(f"{i}({n})" for i, n in ips.most_common(3))
        top_users = ", ".join(f"{u}({n})" for u, n in users.most_common(3))
        top_hosts = ", ".join(f"{h}({n})" for h, n in hosts.most_common(2))
        top_rules = ", ".join(f"{r}({n})" for r, n in rules.most_common(4))
        print(f"\n  comunidad {comm}  "
              f"({row['n_filas']} filas, {row['n_clusters']} clusters C2, "
              f"{int(row['n_alerts']):,} alertas originales)")
        print(f"     decoder: {row['decoders']}")
        print(f"     reglas:  {top_rules}")
        print(f"     periodo: {row['first']} -> {row['last']}")
        if top_ips:
            print(f"     IPs:     {top_ips}")
        if top_users:
            print(f"     usuarios: {top_users}")
        if top_hosts:
            print(f"     hosts:   {top_hosts}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-shared", type=int, default=1,
                    help="entidades distintas minimas para unir dos filas")
    ap.add_argument("--min-weight", type=float, default=0.0,
                    help="peso minimo de arista despues del decaimiento "
                         "temporal (default 0.0; el filtro principal es "
                         "--min-shared)")
    ap.add_argument("--max-rows-frac", type=float, default=0.10,
                    help="filtra entidades presentes en mas de X%% de las "
                         "filas (default 0.10)")
    ap.add_argument("--max-decoders", type=int, default=4,
                    help="filtra entidades presentes en filas de mas de N "
                         "decoders distintos (default 4)")
    ap.add_argument("--min-comm-size", type=int, default=3,
                    help="comunidades menores se intentan consolidar "
                         "(default 3)")
    ap.add_argument("--no-consolidate", action="store_true",
                    help="desactiva la consolidacion de comunidades "
                         "pequenas")
    ap.add_argument("--decay-kind", choices=list(DECAY_KINDS),
                    default="exponential",
                    help="forma del decaimiento temporal aplicado al peso "
                         "de las aristas (default exponential; 'none' "
                         "desactiva el decaimiento)")
    ap.add_argument("--decay-tau", type=float, default=300.0,
                    help="escala temporal en segundos del decaimiento "
                         "(default 300 = 5 min)")
    ap.add_argument("--decay-hard-cutoff", type=float, default=None,
                    help="si Dt entre dos filas supera este valor en "
                         "segundos, no se crea arista (default: sin "
                         "corte duro)")
    ap.add_argument("--asset-map", default="lab_state/asset_map.json",
                    help="ruta del mapa de activos persistido")
    ap.add_argument("--scenario-dir", default="scenarios",
                    help="directorio de escenarios YAML para el mapa")
    ap.add_argument("--no-asset-map", action="store_true",
                    help="desactiva la resolucion de activos")
    args = ap.parse_args()

    if not IN.exists():
        raise SystemExit(f"Falta {IN}. Corre cluster_real.py primero.")

    df = pd.read_parquet(IN).reset_index(drop=True)
    print(f"Cargadas {len(df):,} filas, "
          f"{df['count'].sum():,.0f} alertas originales")
    print(f"Clusters Capa 2: "
          f"{df.loc[df['cluster_id'] != -1, 'cluster_id'].nunique()}")

    # --- Mapa de activos ---
    amap = None
    if not args.no_asset_map:
        mp = Path(args.asset_map)
        if mp.exists():
            amap = AssetMap.load(mp)
            print(f"[asset_map] cargado de {mp}: {amap.stats()}")
        else:
            s1_pairs = _sentinelone_pairs_from_df(df)
            amap = AssetMap.build(scenario_dir=args.scenario_dir,
                                  sentinelone_pairs=s1_pairs)
            amap.save(mp)
        # Si el parquet viene anonimizado, asociar el mapa de aliases para
        # que asset_map.resolve unifique tambien 'tfm.s08.X' con
        # 'tfm-s08-X' en espacio anonimizado (user_NNNN_anonymized). Sin
        # esto, la dualidad O365/vCenter no se cierra cuando hay
        # anonimizacion activa y los escenarios cross-source se parten.
        anon = _maybe_load_anon()
        if anon is not None:
            amap.attach_anonymizer(anon)
            print(f"[asset_map] anonymizer asociado "
                  f"({len(anon.forward)} usuarios) -> resolucion de "
                  f"alias activa en espacio anonimizado")

    # --- Entidades por fila (con resolucion y sin infraestructura) ---
    row_ents = build_row_entities(df, amap)
    n_with_ent = sum(1 for e in row_ents if e)
    print(f"\nFilas con al menos una entidad util: "
          f"{n_with_ent}/{len(df)}")
    if amap is not None:
        n_assets = sum(1 for ents in row_ents
                       for e in ents if e.startswith("asset:"))
        print(f"[asset_map] entidades resueltas a 'asset:': {n_assets}")

    # --- Filtro de entidades promiscuas ---
    decoders = df["decoder.name"].astype(str).tolist()
    row_ents, _ = filter_promiscuous_entities(
        row_ents, max_rows_frac=args.max_rows_frac,
        max_decoders=args.max_decoders, decoders=decoders)

    # --- Grafo de filas + comunidades ---
    print(f"\nDecaimiento temporal: kind={args.decay_kind} "
          f"tau={args.decay_tau}s hard_cutoff={args.decay_hard_cutoff}")
    G = build_row_graph(
        row_ents, args.min_shared, args.min_weight,
        first_seen=df["first_seen"], last_seen=df["last_seen"],
        decay_kind=args.decay_kind, decay_tau=args.decay_tau,
        decay_hard_cutoff=args.decay_hard_cutoff,
    )
    print(f"\nGrafo de filas: {G.number_of_nodes()} nodos, "
          f"{G.number_of_edges()} aristas")
    if G.number_of_nodes():
        avg = (2 * G.number_of_edges()) / G.number_of_nodes()
        print(f"Grado medio: {avg:.1f}")

    partition = detect_communities(G, row_ents)
    n_raw = len(set(v for v in partition.values() if v >= 0))
    print(f"Comunidades Louvain (sin consolidar): {n_raw}")

    if not args.no_consolidate:
        partition = consolidate_small(df, partition, row_ents,
                                      min_size=args.min_comm_size)
        n_final = len(set(v for v in partition.values() if v >= 0))
        print(f"Comunidades tras consolidacion: {n_final}")

    df["community_id"] = [partition.get(i, -1) for i in range(len(df))]

    report_communities(df)
    df.to_parquet(OUT, index=False)
    print(f"\nGuardado -> {OUT}")

    # --- KPIs ---
    n_alerts = int(df["count"].sum())
    n_units = df.loc[df["community_id"] >= 0, "community_id"].nunique()
    reduction = 1 - (n_units / n_alerts) if n_alerts else 0
    print(f"\n{'='*72}")
    print(f"  KPIs DE REDUCCION")
    print(f"{'='*72}")
    print(f"  Alertas originales:      {n_alerts:,}")
    print(f"  Filas tras dedup:        {len(df):,}")
    print(f"  Clusters Capa 2:         "
          f"{df.loc[df['cluster_id']!=-1,'cluster_id'].nunique()}")
    print(f"  Comunidades Capa 3:      {n_units}")
    if n_alerts:
        print(f"  Reduccion dedup:         {1 - len(df)/n_alerts:.1%}")
        print(f"  Reduccion total (->C3):  {reduction:.5%}")


if __name__ == "__main__":
    main()
