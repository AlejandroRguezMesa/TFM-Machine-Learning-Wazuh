#!/usr/bin/env python3
"""
comparar_clustering.py — Comparativa de algoritmos de clustering (Capa 2).

Justifica de forma cuantitativa la eleccion de HDBSCAN como algoritmo de
la Capa 2, midiendo varios algoritmos sobre EL MISMO espacio de features
y el MISMO conjunto de datos, y contrastando el resultado con el ground
truth de los escenarios sinteticos.

Este script NO forma parte del pipeline y NO modifica cluster_real.py.
Reutiliza sus funciones build_features() y maybe_umap() para garantizar
que la comparativa se hace sobre features identicas a las que usa el
sistema en produccion. Lo unico que cambia entre algoritmos es el
metodo de agrupacion.

Algoritmos comparados:
  - HDBSCAN          el que usa el sistema. Basado en densidad, detecta
                     ruido, no exige fijar el numero de clusters.
  - DBSCAN           tambien basado en densidad, pero con un radio eps
                     global (no jerarquico).
  - KMeans           particional. Exige fijar K de antemano y no modela
                     ruido: cada punto cae en algun cluster.
  - Agglomerative    jerarquico aglomerativo (enlace de Ward). Tambien
                     exige fijar K.

Para KMeans y Agglomerative, que necesitan K, se usa como K el numero
de clusters que HDBSCAN encuentra (asi la comparacion es lo mas justa
posible: mismo numero de grupos).

Metricas (todas contra el ground truth de los escenarios):
  - ARI   Adjusted Rand Index. Concordancia global del agrupamiento.
  - AMI   Adjusted Mutual Information.
  - H     Homogeneidad: cada cluster contiene un solo escenario.
  - C     Completitud: cada escenario cae en un solo cluster.
  - V     V-measure: media armonica de H y C.
  - n     numero de clusters encontrados.
  - ruido fraccion de filas etiquetadas como ruido (solo HDBSCAN/DBSCAN).

Como solo HDBSCAN y DBSCAN son deterministas dado el embedding, y KMeans
depende de la inicializacion, cada algoritmo NO determinista se ejecuta
varias veces con semillas distintas y se reporta media +- desviacion.
Una sola corrida no permite concluir que un algoritmo es mejor que otro;
por eso la comparativa es indicativa y asi debe describirse en la
memoria.

Solo se evaluan las filas que pertenecen a algun escenario (las que el
ground truth etiqueta). El resto del trafico es fondo sin etiqueta y no
entra en el calculo de las metricas.

Uso:
  python3 comparar_clustering.py
  python3 comparar_clustering.py --repeticiones 5 --out comparativa.csv
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.cluster import DBSCAN, KMeans, AgglomerativeClustering
from sklearn.metrics import (adjusted_rand_score,
                             adjusted_mutual_info_score,
                             homogeneity_completeness_v_measure)

# Reutilizamos las funciones del modulo de clustering del pipeline para
# construir EXACTAMENTE las mismas features.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cluster_real import build_features, maybe_umap
from anonymization import maybe_load, DEFAULT_MAP_PATH

try:
    import hdbscan
except ImportError:
    raise SystemExit("pip install hdbscan")


CLUSTERED = Path("lab_state/real_alerts_clustered.parquet")
GT = Path("lab_state/ground_truth.jsonl")


def _iter(v):
    if v is None:
        return
    if isinstance(v, (list, tuple, np.ndarray)):
        for x in v:
            if x:
                yield x
    elif isinstance(v, str) and v:
        yield v


def cargar_ground_truth(path: Path) -> dict:
    """Lee ground_truth.jsonl y devuelve, por cada escenario base, el
    conjunto de entidades discriminantes inyectadas."""
    by_scn = defaultdict(set)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            base = re.sub(r"-[0-9a-f]{6,}$", "",
                          rec.get("incident_id", "?"))
            for v in (rec.get("entities") or {}).values():
                if isinstance(v, str) and v:
                    by_scn[base].add(v.lower())
            for v in (rec.get("vars") or {}).values():
                if isinstance(v, str) and v and not v.isdigit():
                    by_scn[base].add(v.lower())
    return by_scn


def etiquetar_filas(df: pd.DataFrame, by_scn: dict, anon=None) -> np.ndarray:
    """Asigna a cada fila la etiqueta de su escenario (o None si no
    pertenece a ninguno), comparando las entidades de la fila con las
    entidades discriminantes del ground truth.

    Si `anon` se pasa, anade ademas los aliases anonimizados de cada
    candidato que parezca usuario, para que el matching funcione cuando
    el parquet esta anonimizado y el GT no lo esta. IPs no se tocan."""
    from normalize import norm_ip
    # candidatos por escenario (incluye variantes de usuario)
    cands = {}
    for scn, ents in by_scn.items():
        c = set()
        for e in ents:
            c.add(e)
            if "@" in e:
                c.add(e.split("@")[0])
            if "\\" in e:
                c.add(e.split("\\")[-1])
        # anadir aliases anonimizados para los candidatos que parezcan usuario
        if anon is not None:
            extra = set()
            for v in c:
                if norm_ip(v):
                    continue
                alias = anon.lookup_raw(v)
                if alias and alias != v:
                    extra.add(alias)
                    extra.add(f"user:{alias}")
            c |= extra
        cands[scn] = c

    etiquetas = []
    for _, r in df.iterrows():
        fila_ents = set()
        for col in ("entity_users", "entity_ips", "entity_hosts"):
            for x in _iter(r.get(col)):
                x = str(x).lower()
                for p in ("user:", "ip:", "host:", "asset:"):
                    if x.startswith(p):
                        fila_ents.add(x[len(p):])
                fila_ents.add(x)
        encontrado = None
        for scn, c in cands.items():
            if fila_ents & c:
                encontrado = scn
                break
        etiquetas.append(encontrado)
    return np.array(etiquetas, dtype=object)


def metricas(verdad, pred):
    """Calcula las metricas de un agrupamiento frente a la verdad."""
    ari = adjusted_rand_score(verdad, pred)
    ami = adjusted_mutual_info_score(verdad, pred)
    h, c, v = homogeneity_completeness_v_measure(verdad, pred)
    n_clusters = len({x for x in pred if x >= 0})
    n_ruido = int(np.sum(pred < 0))
    return {
        "ari": ari, "ami": ami, "h": h, "c": c, "v": v,
        "n_clusters": n_clusters,
        "frac_ruido": n_ruido / len(pred) if len(pred) else 0.0,
    }


def metricas_por_escenario(verdad, pred):
    """Metricas orientadas a lo que la Capa 2 debe lograr de verdad.

    El ARI global penaliza que un escenario se reparta en varios
    clusters, pero esa fragmentacion es intencionada en esta
    arquitectura: la Capa 3 reune luego los micro-clusters. Por eso,
    ademas del ARI, se miden dos cosas por escenario:

    - cohesion: que fraccion de las filas del escenario cae en el
      cluster que mas filas suyas concentra. Mide si el escenario
      queda 'localizado' o despedazado. 1.0 = todas juntas.
    - pureza: de las filas de ESE cluster mayoritario, que fraccion
      pertenece de verdad al escenario. Mide que el cluster no mezcle
      escenarios distintos. 1.0 = sin contaminacion.

    Se reporta la media de ambas sobre todos los escenarios. Estas
    metricas no penalizan la fragmentacion intra-escenario; penalizan
    lo que si es un fallo: que un escenario se disperse entre clusters
    sin nucleo dominante, o que un cluster mezcle escenarios.
    """
    cohesiones, purezas = [], []
    # solo filas no-ruido para el calculo de cluster mayoritario
    for scn in np.unique(verdad):
        idx_scn = np.where(verdad == scn)[0]
        clusters_scn = pred[idx_scn]
        validos = clusters_scn[clusters_scn >= 0]
        if len(validos) == 0:
            cohesiones.append(0.0)
            purezas.append(0.0)
            continue
        # cluster que mas filas del escenario concentra
        vals, cuentas = np.unique(validos, return_counts=True)
        cluster_may = vals[np.argmax(cuentas)]
        n_en_may = cuentas.max()
        cohesiones.append(n_en_may / len(idx_scn))
        # pureza de ese cluster
        total_en_cluster = int(np.sum(pred == cluster_may))
        purezas.append(n_en_may / total_en_cluster
                       if total_en_cluster else 0.0)
    return {
        "cohesion_media": float(np.mean(cohesiones)),
        "pureza_media": float(np.mean(purezas)),
    }


def correr_algoritmo(nombre, emb, k_objetivo, semilla, min_cluster_size=5):
    """Aplica un algoritmo de clustering al embedding y devuelve las
    etiquetas. k_objetivo solo lo usan los algoritmos que exigen K."""
    if nombre == "HDBSCAN":
        return hdbscan.HDBSCAN(
            min_cluster_size=min_cluster_size, metric="euclidean",
            cluster_selection_method="eom").fit_predict(emb)
    if nombre == "DBSCAN":
        # min_samples se alinea con min_cluster_size para que la
        # comparacion entre algoritmos de densidad sea coherente.
        return DBSCAN(eps=0.5, min_samples=min_cluster_size).fit_predict(emb)
    if nombre == "KMeans":
        return KMeans(n_clusters=max(2, k_objetivo),
                      random_state=semilla, n_init=10).fit_predict(emb)
    if nombre == "Agglomerative":
        return AgglomerativeClustering(
            n_clusters=max(2, k_objetivo),
            linkage="ward").fit_predict(emb)
    raise ValueError(nombre)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(CLUSTERED),
                    help="parquet con features (salida de cluster_real)")
    ap.add_argument("--ground-truth", default=str(GT))
    ap.add_argument("--repeticiones", type=int, default=5,
                    help="repeticiones para los algoritmos no "
                         "deterministas (default 5)")
    ap.add_argument("--top-k", type=int, default=30,
                    help="top_k de build_features (debe coincidir con "
                         "el del pipeline)")
    ap.add_argument("--time-weight", type=float, default=2.0)
    ap.add_argument("--umap-dims", type=int, default=8)
    ap.add_argument("--min-cluster-size", type=int, default=5,
                    help="min_cluster_size de HDBSCAN (y min_samples de "
                         "DBSCAN). El pipeline de produccion usa 3.")
    ap.add_argument("--out", default="comparar_clustering.csv")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="mapa de anonimizacion para resolver GT contra "
                         "parquet anonimizado")
    args = ap.parse_args()

    anon = maybe_load(args.user_alias_map)
    if anon is not None:
        print(f"[anon] resolviendo GT con {args.user_alias_map} "
              f"({len(anon.forward)} usuarios)")

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f"No existe {src}. Corre cluster_real.py primero.")
    gt_path = Path(args.ground_truth)
    if not gt_path.exists():
        raise SystemExit(
            f"No existe {gt_path}. La comparativa necesita el ground "
            "truth de los escenarios; corre el pipeline con escenarios.")

    df = pd.read_parquet(src)
    print(f"Cargadas {len(df):,} filas de {src}")

    # 1. Reconstruir EL MISMO espacio de features que usa el pipeline
    print("Construyendo features (identicas a cluster_real.py)...")
    df_feat, X = build_features(df, args.top_k, args.time_weight)
    emb = maybe_umap(X, args.umap_dims)
    print(f"Embedding: {emb.shape}")

    # Invariante critico: las metricas comparan pred[i] con verdad[i],
    # y pred se calcula sobre emb mientras verdad se deriva de df_feat.
    # Si build_features o maybe_umap rompieran el alineamiento 1-a-1, el
    # ARI seria basura sin error visible. Mejor cortar aqui de forma
    # ruidosa que reportar numeros engañosos.
    assert len(df_feat) == emb.shape[0], (
        f"Desalineamiento fatal: df_feat={len(df_feat)} filas, "
        f"emb={emb.shape[0]} filas. Las metricas posteriores compararian "
        "filas distintas.")

    # 2. Etiquetas de verdad a partir del ground truth
    by_scn = cargar_ground_truth(gt_path)
    print(f"Escenarios en ground truth: {sorted(by_scn)}")
    etiquetas = etiquetar_filas(df_feat, by_scn, anon=anon)
    mask = np.array([e is not None for e in etiquetas])
    n_etiquetadas = int(mask.sum())
    if n_etiquetadas < 4:
        raise SystemExit(
            f"Solo {n_etiquetadas} filas etiquetadas; insuficiente "
            "para una comparativa con sentido.")
    print(f"Filas etiquetadas (pertenecen a un escenario): "
          f"{n_etiquetadas}/{len(df_feat)}")
    # mapear etiquetas de texto a enteros para las metricas
    nombres_scn = sorted(set(etiquetas[mask]))
    scn_a_int = {s: i for i, s in enumerate(nombres_scn)}
    verdad = np.array([scn_a_int[e] for e in etiquetas[mask]])

    # 3. K objetivo: el numero de clusters que encuentra HDBSCAN
    pred_hdb = correr_algoritmo("HDBSCAN", emb, 0, 0,
                                min_cluster_size=args.min_cluster_size)
    k_objetivo = len({x for x in pred_hdb if x >= 0})
    # Si HDBSCAN no encuentra clusters (todo ruido), correr_algoritmo
    # cae internamente a max(2, k_objetivo) para KMeans/Agglomerative.
    # Hacemos esa caida explicita en el mensaje para que el CSV y la
    # tabla no afirmen "se usa K=0" mientras los algoritmos paramétricos
    # corren con K=2 a sus espaldas.
    k_usado = max(2, k_objetivo)
    if k_usado != k_objetivo:
        print(f"[AVISO] HDBSCAN encuentra {k_objetivo} clusters; "
              f"KMeans/Agglomerative no admiten K<2, asi que se ejecutan "
              f"con K={k_usado}. La comparativa no es directa en esta corrida.\n")
    else:
        print(f"HDBSCAN encuentra {k_objetivo} clusters; se usa ese K para "
              f"KMeans y Agglomerative.\n")

    # 4. Comparativa
    deterministas = {"HDBSCAN", "DBSCAN", "Agglomerative"}
    algoritmos = ["HDBSCAN", "DBSCAN", "KMeans", "Agglomerative"]
    filas_csv = []

    print(f"{'Algoritmo':<15}{'ARI':>14}{'V-meas':>14}"
          f"{'Cohesion':>11}{'Pureza':>10}{'nClust':>9}{'Ruido':>9}")
    print("-" * 91)

    for alg in algoritmos:
        reps = 1 if alg in deterministas else args.repeticiones
        acum = defaultdict(list)
        for semilla in range(reps):
            pred = correr_algoritmo(alg, emb, k_objetivo, semilla,
                                    min_cluster_size=args.min_cluster_size)
            m = metricas(verdad, pred[mask])
            m.update(metricas_por_escenario(verdad, pred[mask]))
            for k, val in m.items():
                acum[k].append(val)

        def ms(clave):
            vals = acum[clave]
            return float(np.mean(vals)), float(np.std(vals))

        ari_m, ari_s = ms("ari")
        v_m, v_s = ms("v")
        h_m, _ = ms("h")
        c_m, _ = ms("c")
        n_m, _ = ms("n_clusters")
        ruido_m, _ = ms("frac_ruido")
        coh_m, coh_s = ms("cohesion_media")
        pur_m, pur_s = ms("pureza_media")

        if reps > 1:
            ari_txt = f"{ari_m:.3f}+-{ari_s:.3f}"
            v_txt = f"{v_m:.3f}+-{v_s:.3f}"
        else:
            ari_txt = f"{ari_m:.3f}"
            v_txt = f"{v_m:.3f}"

        print(f"{alg:<15}{ari_txt:>14}{v_txt:>14}"
              f"{coh_m:>11.3f}{pur_m:>10.3f}{n_m:>9.0f}{ruido_m:>9.1%}")

        filas_csv.append({
            "algoritmo": alg,
            "repeticiones": reps,
            "ari_media": round(ari_m, 4),
            "ari_desv": round(ari_s, 4),
            "ami_media": round(ms("ami")[0], 4),
            "v_media": round(v_m, 4),
            "v_desv": round(v_s, 4),
            "homogeneidad_media": round(h_m, 4),
            "completitud_media": round(c_m, 4),
            "cohesion_escenario_media": round(coh_m, 4),
            "cohesion_escenario_desv": round(coh_s, 4),
            "pureza_escenario_media": round(pur_m, 4),
            "pureza_escenario_desv": round(pur_s, 4),
            "n_clusters_media": round(n_m, 1),
            "frac_ruido_media": round(ruido_m, 4),
        })

    out = Path(args.out)
    pd.DataFrame(filas_csv).to_csv(out, index=False)
    print(f"\nComparativa guardada en {out}")
    print(
        "\nLectura de las metricas:\n"
        "  ARI / V-measure: concordancia global con los escenarios. "
        "Penalizan que un\n"
        "    escenario se reparta en varios clusters, algo intencionado "
        "en esta arquitectura\n"
        "    (la Capa 3 reune los micro-clusters), por lo que sus "
        "valores absolutos son\n"
        "    bajos; son utiles para el ORDEN relativo entre algoritmos, "
        "no como nota.\n"
        "  Cohesion: fraccion de filas de cada escenario que caen "
        "juntas en su cluster\n"
        "    mayoritario. Mide si el escenario queda localizado.\n"
        "  Pureza: fraccion de ese cluster mayoritario que pertenece de "
        "verdad al\n"
        "    escenario. Mide que no se mezclen escenarios distintos.\n"
        "  Cohesion y pureza reflejan mejor lo que la Capa 2 debe "
        "lograr.\n"
        "\nNota: comparacion indicativa sobre una unica extraccion de "
        "datos. Las\n"
        "diferencias pequenas pueden no ser significativas; una "
        "conclusion solida\n"
        "exigiria repetir la comparativa sobre varias extracciones "
        "independientes.")


if __name__ == "__main__":
    main()
