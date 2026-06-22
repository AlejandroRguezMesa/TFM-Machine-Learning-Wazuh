#!/usr/bin/env python3
"""
cluster_real.py — Clustering HDBSCAN sobre datos reales deduplicados.

Diferencias vs cluster_alerts.py:
  - Lee real_alerts.parquet (formato post-extract_real.py)
  - Usa entity_users/entity_ips/entity_hosts (listas, no columnas data.*)
  - No hay incident_id (no es lab) - sin métricas vs ground truth
  - Resumen orientado a inspección manual: top clusters, ejemplos

Uso:
  python3 cluster_real.py
  python3 cluster_real.py --umap-dims 8 --min-cluster 5
"""
from __future__ import annotations
import argparse
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

try:
    import hdbscan
except ImportError:
    raise SystemExit("pip install hdbscan")


IN  = Path("lab_state/real_alerts.parquet")
OUT = Path("lab_state/real_alerts_clustered.parquet")


def _multi_hot_from_lists(series, k, prefix,
                          min_coverage=0.70, k_max=200):
    """Construye multi-hot a partir de Series cuyas filas son listas.

    `k` es el suelo: se incluyen siempre al menos los k items mas
    frecuentes. Si esos k no cubren `min_coverage` del volumen total
    (suma de apariciones), el top-k se extiende hasta alcanzarlo, con
    techo `k_max`. Asi un k fijo no descarta la cola larga cuando el
    dataset crece y reparte la señal entre muchas entidades."""
    all_items = Counter()
    for lst in series:
        if isinstance(lst, (list, np.ndarray)):
            for x in lst:
                if x:
                    all_items[str(x).lower()] += 1
        elif isinstance(lst, str) and lst:
            for x in lst.split(","):
                x = x.strip().lower()
                if x:
                    all_items[x] += 1
    if not all_items:
        return pd.DataFrame(index=series.index, dtype=np.float32)
    # k adaptativo por cobertura de volumen
    sorted_items = all_items.most_common()
    total = sum(c for _, c in sorted_items)
    actual_k = min(max(k, 1), len(sorted_items))
    if total > 0 and 0 < min_coverage <= 1:
        acc = sum(c for _, c in sorted_items[:actual_k])
        target = total * min_coverage
        cap = min(len(sorted_items), k_max)
        while actual_k < cap and acc < target:
            acc += sorted_items[actual_k][1]
            actual_k += 1
    top = [t for t, _ in sorted_items[:actual_k]]
    cols = [f"{prefix}_{t}" for t in top]
    out = pd.DataFrame(0, index=series.index, columns=cols, dtype=np.float32)
    for i, lst in enumerate(series):
        if isinstance(lst, (list, np.ndarray)):
            items = [str(x).lower() for x in lst if x]
        elif isinstance(lst, str):
            items = [x.strip().lower() for x in lst.split(",") if x.strip()]
        else:
            items = []
        for x in items:
            col = f"{prefix}_{x}"
            if col in out.columns:
                out.iat[i, out.columns.get_loc(col)] = 1.0
    return out


def _top_k_one_hot(series, k, prefix):
    top = series.dropna().astype(str).value_counts().head(k).index
    s = series.where(series.isin(top), other="__other__").fillna("__missing__")
    return pd.get_dummies(s.astype(str), prefix=prefix).astype(np.float32)


def build_features(df, top_k, time_weight,
                   top_k_coverage=0.70, top_k_max=200):
    df = df.copy().sort_values("timestamp").reset_index(drop=True)

    # Temporales
    t0 = df["timestamp"].min()
    df["t_seconds"] = (df["timestamp"] - t0).dt.total_seconds().fillna(0)

    # Severidad y volumen
    df["rule_level_num"] = pd.to_numeric(df["rule.level"], errors="coerce").fillna(0)
    df["log_count"] = np.log1p(df["count"].astype(float))

    num = df[["t_seconds", "rule_level_num", "log_count"]].astype(np.float32).values
    num = StandardScaler().fit_transform(num)
    num[:, 0] = num[:, 0] * time_weight

    mh = lambda s, p: _multi_hot_from_lists(
        s, k=top_k, prefix=p,
        min_coverage=top_k_coverage, k_max=top_k_max)
    parts = [
        pd.DataFrame(num, columns=["t_seconds", "rule_level_num", "log_count"]),
        _top_k_one_hot(df["decoder.name"], k=10, prefix="dec"),
        _top_k_one_hot(df["rule.id"].astype(str), k=top_k, prefix="rid"),
        mh(df["entity_users"], "usr"),
        mh(df["entity_ips"],   "ip"),
        mh(df["entity_hosts"], "host"),
        mh(df["rule.groups"],          "grp"),
        mh(df["rule.mitre.tactic"],    "tac"),
        mh(df["rule.mitre.technique"], "tec"),
    ]

    X = pd.concat([p.reset_index(drop=True) for p in parts], axis=1)
    print(f"Bloques features: {[p.shape[1] for p in parts]} total={X.shape[1]}")
    return df, X


def maybe_umap(X, n_dims):
    if not n_dims:
        return X.values.astype(np.float32)
    try:
        import umap
    except ImportError:
        raise SystemExit("pip install umap-learn")
    return umap.UMAP(n_components=n_dims, metric="euclidean",
                     random_state=42, n_neighbors=15, min_dist=0.0
                     ).fit_transform(X.values.astype(np.float32))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-cluster", type=int, default=5)
    ap.add_argument("--min-samples", type=int, default=None)
    ap.add_argument("--top-k", type=int, default=30,
                    help="suelo del numero de items en multi-hot "
                         "(usuarios, IPs, hosts, MITRE...). El k real se "
                         "extiende segun --top-k-coverage si la cola larga "
                         "acumula señal.")
    ap.add_argument("--top-k-coverage", type=float, default=0.70,
                    help="fraccion del volumen total que el multi-hot "
                         "debe cubrir (default 0.70). Pon 0 para "
                         "desactivar y comportarte como --top-k fijo.")
    ap.add_argument("--top-k-max", type=int, default=200,
                    help="techo absoluto del top-k adaptativo (default 200)")
    ap.add_argument("--time-weight", type=float, default=2.0)
    ap.add_argument("--umap-dims", type=int, default=8)
    args = ap.parse_args()

    if not IN.exists():
        raise SystemExit(f"Falta {IN}. Corre extract_real.py primero.")

    df = pd.read_parquet(IN)
    print(f"Cargadas {len(df):,} filas (post-dedup)")
    print(f"Suma de counts (alertas originales): {int(df['count'].sum()):,}")

    df_feat, X = build_features(df, args.top_k, args.time_weight,
                                top_k_coverage=args.top_k_coverage,
                                top_k_max=args.top_k_max)
    print(f"Matriz: {X.shape}")

    Xr = maybe_umap(X, args.umap_dims)
    if args.umap_dims:
        print(f"Tras UMAP: {Xr.shape}")

    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=args.min_cluster,
        min_samples=args.min_samples,
        metric="euclidean",
        cluster_selection_method="eom",
    )
    labels = clusterer.fit_predict(Xr)
    df_feat["cluster_id"] = labels.astype(int)
    df_feat["cluster_prob"] = clusterer.probabilities_.astype(np.float32)

    df_feat.to_parquet(OUT, index=False)
    print(f"\nGuardado → {OUT}")

    # Resumen
    n_clusters = (df_feat["cluster_id"] != -1).sum() and df_feat.loc[df_feat["cluster_id"] != -1, "cluster_id"].nunique() or 0
    n_noise = (df_feat["cluster_id"] == -1).sum()
    print(f"\nClusters encontrados: {n_clusters}")
    print(f"Filas marcadas ruido: {n_noise:,} ({n_noise/len(df_feat):.1%})")

    # Tamaño de clusters ponderado por count
    print("\n--- TOP 20 CLUSTERS POR ALERTAS ORIGINALES (sum de count) ---")
    df_feat_wcount = df_feat[df_feat["cluster_id"] != -1]
    cluster_summary = df_feat_wcount.groupby("cluster_id").agg(
        n_rows=("cluster_id", "size"),
        n_alerts=("count", "sum"),
        decoders=("decoder.name", lambda s: ",".join(sorted(set(s)))),
        rules=("rule.id", lambda s: ",".join(sorted(set(s.astype(str)))[:5])),
        first=("first_seen", "min"),
        last=("last_seen", "max"),
    ).sort_values("n_alerts", ascending=False)

    for cid, row in cluster_summary.head(20).iterrows():
        # ejemplos de IPs/usuarios del cluster
        sub = df_feat[df_feat["cluster_id"] == cid]
        ips = Counter()
        users = Counter()
        for lst in sub["entity_ips"]:
            if isinstance(lst, (list, np.ndarray)):
                for x in lst: ips[x] += 1
        for lst in sub["entity_users"]:
            if isinstance(lst, (list, np.ndarray)):
                for x in lst: users[x] += 1
        top_ips = ", ".join(f"{i}({n})" for i, n in ips.most_common(3))
        top_users = ", ".join(f"{u}({n})" for u, n in users.most_common(2))

        print(f"\n  cluster {cid}  ({row['n_rows']} filas, {int(row['n_alerts']):,} alertas)")
        print(f"     decoder={row['decoders']}  reglas={row['rules']}")
        print(f"     periodo: {row['first']} → {row['last']}")
        if top_ips:
            print(f"     IPs:    {top_ips}")
        if top_users:
            print(f"     usrs:   {top_users}")
        ej = sub["rule.description"].iloc[0]
        print(f"     ej:     {ej[:100]}")


if __name__ == "__main__":
    main()
