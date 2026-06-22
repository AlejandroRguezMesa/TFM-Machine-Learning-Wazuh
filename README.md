# TFM — Sistema de correlación multi-capa de alertas Wazuh

Trabajo Fin de Máster (Máster en Inteligencia Artificial, UAX).

Sistema que correlaciona alertas de **Wazuh 4.14** en tres capas:

- **Capa 1** — Motor de reglas de Wazuh (decoders + reglas custom).
- **Capa 2** — Clustering no supervisado **HDBSCAN** sobre features
  (UMAP-8; la dimensión temporal va dentro de las features).
- **Capa 3** — Grafo de filas + comunidades **Louvain**, con resolución
  de activos (IP/host/usuario) y decaimiento temporal opcional.

Sobre las comunidades resultantes hay un prototipo opcional de **triaje
con LLM** (`llm_triage.py`).

---

## 1. Estructura del repositorio

```
repositorio/
├── run_seguimiento2.sh          Orquestador del pipeline (10 fases)
├── requirements.txt             Dependencias Python
├── .env.example                 Plantilla de credenciales del Indexer
│
├── Pipeline de datos
│   ├── indexer_client.py        Cliente OpenSearch (lee .env)
│   ├── inject_real_alerts.py    Muestreo estratificado del alerts.json real
│   ├── extract_indexer.py       Extracción del Indexer + dedup + normalización
│   ├── extract_real.py          Variante offline: lee un alerts.json local
│   ├── normalize.py             Normalización canónica de entidades
│   ├── entity_normalization.py  Mapeo columna → tipo de entidad
│   ├── anonymization.py         Anonimización biyectiva de usuarios
│   └── real_eda.py              Análisis exploratorio en streaming
│
├── Capas analíticas
│   ├── cluster_real.py          Capa 2 — HDBSCAN sobre alertas deduplicadas
│   ├── graph_layer_real.py      Capa 3 — grafo de filas + Louvain
│   ├── asset_map.py             Mapa de activos: dualidad IP/host + identidad
│   └── bridge_filter.py         Filtro de entidades de infraestructura
│
├── Generación de datos sintéticos
│   ├── generators/              Generadores por fuente (paquete)
│   │   ├── sink.py
│   │   ├── palo_alto.py
│   │   ├── vcenter.py
│   │   ├── office365.py
│   │   └── sentinelone.py
│   ├── scenarios/               Escenarios S01–S10 en YAML
│   ├── scenario_runner.py       Orquestador de escenarios + ground truth
│   ├── noise_runner.py          Generador de ruido benigno (Poisson)
│   └── smoke_test.py            Validación rápida log → decoder → regla
│
├── Persistencia y evaluación
│   ├── push_to_indexer.py       Sube resultados a wazuh-correlation-*
│   ├── verify_scenarios.py      Verificación cross-source contra ground truth
│   ├── inspect_community.py     Inspección fina de una comunidad
│   └── generar_graficas.py      Figuras del resumen del pipeline
│
├── Estudio del decaimiento temporal
│   ├── barrido_tau.py           Barrido de τ en el grafo de filas
│   ├── demo_decay_temporal.py   Demo paso a paso del decaimiento
│   ├── graficas_temporal.py     Figuras del estudio temporal
│   ├── graficas_decay_s10.py    Figuras de contraste sobre s10
│   ├── comparar_decay_AB.py     A/B sin/con decaimiento sobre el mismo run
│   └── run_decay.sh             Orquestador del estudio
│
├── Herramientas auxiliares
│   ├── comparar_clustering.py   HDBSCAN vs k-means vs DBSCAN, n repeticiones
│   ├── graficas_comparativa.py  Figura 2×2 de la comparativa (CSV → PNG)
│   └── llm_triage.py            Triaje de comunidades con LLM (Gemini/Groq/…)
│
├── configs/
│   ├── ossec_localfile_snippet.xml          Bloques <localfile> para ossec.conf
│   ├── tfm_correlation_dashboard.ndjson     Dashboard importable
│   └── tfm_correlation_dashboard_alt793.ndjson
│
├── capturas/                    Figuras de salida del pipeline principal
├── capturas_nuevas/             Figuras complementarias (arquitectura, comparativa, etc.)
├── capturas_temporal/           Figuras del estudio τ + tablas
└── outputs_memoria/             Material visual y tabular para la memoria
    ├── figuras/
    ├── tablas/
    ├── eda/
    ├── casos/                   Inspección de comunidades por escenario
    └── llm/                     Triaje LLM de comunidades y comparativa
```

---

## 2. Requisitos previos

El pipeline depende de un entorno **Wazuh 4.14** operativo (manager +
indexer + dashboard). El paquete contiene el código y los recursos;
la ejecución se realiza sobre la máquina del laboratorio.

- Wazuh 4.14 con manager, indexer y dashboard corriendo en local.
- Decoders y reglas custom de los productos del lab (Palo Alto, vCenter,
  Office 365, SentinelOne) instalados en `/var/ossec/etc/` (ver § 3.2).
- Usuario y rol con permisos de lectura/escritura sobre los índices
  `wazuh-alerts-*` y `wazuh-correlation-*` (ver memoria, Anexo C).
- Directorios de log del laboratorio creados con permisos correctos
  (ver § 3.3).

---

## 3. Puesta a punto

### 3.1 Entorno Python

```bash
cd repositorio
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Decoders y reglas de Wazuh

Los decoders y reglas custom **no se incluyen en este paquete** porque
contienen identificadores específicos del entorno (hostnames, dominios y
cuentas internas). El pipeline depende de las cuatro fuentes siguientes,
y para reproducirlo hay que instalar los decoders y reglas equivalentes
en `/var/ossec/etc/`:

| Fuente | Familia de regla |
|--------|------------------|
| Palo Alto firewall | `64500–64999` (rangos PaloAlto) |
| vCenter (vpxd, hostd) | `140000–140999` |
| Office 365 (Management API) | `91500–91999`, `108000+` |
| SentinelOne (API) | `300600+` |

Existen packs comunitarios para todas ellas en el catálogo público de
reglas de Wazuh y en repositorios de terceros. Una vez instalados,
reiniciar el manager:

```bash
sudo systemctl restart wazuh-manager
```

Las únicas adiciones específicas del TFM son los rangos `300601+`
(SentinelOne adaptado) y reglas `91500+` de correlación, definidas
sobre los packs anteriores. Los IDs concretos que produce cada
escenario sintético quedan documentados en la memoria del TFM.

### 3.3 Directorios de log del laboratorio

```bash
sudo mkdir -p /var/log/lab
sudo touch /var/log/lab/{paloalto,vcenter,office365}.log
sudo touch /var/log/sentinelone.json /var/log/sentinelone_activities.json \
           /var/log/sentinelone-device-control.json
sudo chown -R root:wazuh /var/log/lab /var/log/sentinelone*.json
sudo chmod 664 /var/log/lab/* /var/log/sentinelone*.json
sudo chmod 775 /var/log/lab
```

Una sola vez, pegar el contenido de `configs/ossec_localfile_snippet.xml`
dentro de `<ossec_config>...</ossec_config>` en `/var/ossec/etc/ossec.conf`
y reiniciar el manager.

### 3.4 Credenciales del Indexer

```bash
cp .env.example .env
$EDITOR .env            # rellenar WAZUH_INDEXER_PASS
chmod 600 .env
```

### 3.5 Dashboard de Wazuh (opcional)

En Wazuh → Stack Management → Saved Objects → Import, importar
`configs/tfm_correlation_dashboard.ndjson` (o
`tfm_correlation_dashboard_alt793.ndjson` para la variante con un
data-view alternativo). Aparecerá como "TFM — Métricas de
correlación" y consume los índices `wazuh-correlation-*` que rellena
`push_to_indexer.py`.

---

## 4. Ejecución del pipeline completo

### 4.1 Indicar el alerts.json de fondo

```bash
REAL_SRC=$HOME/Descargas/alerts.json sudo -E bash run_seguimiento2.sh
```

El flag `-E` de `sudo` conserva la variable `REAL_SRC`. Por defecto, el
orquestador busca `$HOME/Descargas/alerts_filtrado.json`.

### 4.2 Qué hace el orquestador

`run_seguimiento2.sh` ejecuta diez fases:

1. Verificación del entorno (.venv, .env, fichero real).
2. Limpieza del estado anterior (logs, ground truth, índices).
3. Inyección del fondo real al Indexer (muestreo estratificado).
4. Lanzamiento de los escenarios sintéticos S06–S09 cross-source.
5. Ruido benigno de fondo en paralelo (Poisson).
6. Espera de indexación.
7. Extracción + dedup + normalización (`extract_indexer.py`).
8. Capa 2 — HDBSCAN (`cluster_real.py`).
9. Capa 3 — grafo de filas + Louvain (`graph_layer_real.py`).
10. Persistencia en el Indexer + figuras + verificación.

Flags útiles del orquestador:

```bash
--skip-real           # solo escenarios sintéticos
--no-push             # no subir al Indexer
--real-n 10000        # tamaño del fondo real
--no-anonymize        # desactivar la anonimización de usuarios
```

### 4.3 Anonimización de usuarios

La extracción anonimiza por defecto los nombres de usuario mediante un
mapa biyectivo persistente (`lab_state/user_alias_map.json`, perm 600):

```
lab.user1                       →  user_0001_anonymized
tfm.s06.victim1            →  user_0042_anonymized
VSPHERE.LOCAL\svc-horizon  →  user_0070_anonymized
```

IPs y hostnames **no** se anonimizan: identifican activos de red, no
personas. Los aliases son estables entre runs, por lo que la
correlación a lo largo del tiempo se preserva. La evaluación
(`verify_scenarios.py`) resuelve el ground truth contra el parquet
anonimizado usando el mismo mapa.

Para reproducir el comportamiento con nombres en claro:
`bash run_seguimiento2.sh --no-anonymize`.

### 4.4 Análisis exploratorio del nuevo volcado (opcional)

```bash
source .venv/bin/activate
python real_eda.py $HOME/Descargas/alerts.json \
       --out lab_state/eda_report.txt
```

---

## 5. Verificación de resultados

El orquestador imprime al final un resumen y la verificación cross-source:

```
Escenario    Recall   Pureza  ComPrin   Cross Veredicto
------------------------------------------------------------------------
INC-S06         58%     100%     #124      si OK
INC-S07        100%      69%     #133      si OK
INC-S08        100%     100%     #131      si OK
INC-S09         73%     100%     #132      si OK

Escenarios consolidados correctamente: 4/4
```

Comandos útiles para revisión posterior:

```bash
source .venv/bin/activate

# Verificación cross-source contra el ground truth
python verify_scenarios.py

# Inspección fina de una comunidad concreta (p. ej. la #131)
python inspect_community.py 131

# Comparativa de algoritmos de clustering (alineada con producción)
python comparar_clustering.py --min-cluster-size 3 --time-weight 1.0 \
       --repeticiones 5

# Figura 2×2 de la comparativa (lee comparar_clustering.csv)
python graficas_comparativa.py
# → capturas_nuevas/fig_comparativa_clustering.png
```

Los datos finales quedan en `lab_state/real_alerts_incidents.parquet`.
El dashboard se consulta en Wazuh → Dashboards → "TFM — Métricas de
correlación".

---

## 6. Ejecución del pipeline a mano (sin orquestador)

```bash
source .venv/bin/activate

# 1. Fondo real (excluye la regla ruidosa 64508)
python inject_real_alerts.py $HOME/Descargas/alerts.json \
       --n 5000 --duration-min 30 --exclude-rule 64508

# 2. Escenarios sintéticos
for sc in scenarios/s06_*.yaml scenarios/s07_*.yaml \
          scenarios/s08_*.yaml scenarios/s09_*.yaml; do
    python scenario_runner.py "$sc" --time-scale 0.2
done

# 3. Esperar ~45 s a que Wazuh indexe, luego extraer
python extract_indexer.py --since now-90m

# 4. Capa 2 — clustering (hiperparámetros del run de referencia)
python cluster_real.py --min-cluster 3 --time-weight 1.0 --umap-dims 8

# 5. Capa 3 — grafo + Louvain
python graph_layer_real.py --min-shared 1 --min-weight 1.0

# 6. Persistencia y verificación
python push_to_indexer.py --recreate
python verify_scenarios.py
```

---

## 7. Estudio del decaimiento temporal (opcional)

El `graph_layer_real.py` admite decaimiento temporal en el peso de las
aristas (`--decay-kind` ∈ {`exponential`, `gaussian`, `linear`, `power`,
`none`}, parámetro `--decay-tau`).

El subdirectorio del estudio incluye:

- `barrido_tau.py`: barrido de τ y export a CSV de recall/pureza.
- `demo_decay_temporal.py`: comparativa paso a paso sin/con decaimiento.
- `comparar_decay_AB.py`: contraste A/B sobre un mismo parquet.
- `graficas_temporal.py`, `graficas_decay_s10.py`: figuras del estudio.
- `run_decay.sh`: orquesta el estudio completo de extremo a extremo.

Figuras y tablas resultantes: `capturas_temporal/`.

---

## 8. Triaje LLM (prototipo, opcional)

`llm_triage.py` toma una comunidad de la Capa 3 y genera un triaje
estructurado con un LLM externo (Gemini, Groq, etc.). El contexto
enviado son **resúmenes correlacionados**, nunca las alertas crudas, y
los nombres de usuario llegan ya anonimizados.

```bash
# Modo simulado (no llama a ningún modelo, útil para ver el formato):
python llm_triage.py --top 3 --dry-run

# Con clave de API (Google AI Studio, gratuita):
export LLM_API_KEY="..."
python llm_triage.py --top 3
```

El triaje generado para las comunidades del run de referencia, junto
con el informe comparativo, está en `outputs_memoria/llm/`.

---

## 9. Material complementario

- `capturas/` — Figuras de salida del pipeline.
- `capturas_nuevas/` — Figuras complementarias (arquitectura, comparativa).
- `capturas_temporal/` — Figuras y CSVs del barrido τ.
- `outputs_memoria/` — Material visual y tabular usado en la memoria,
  incluyendo `casos/` (inspección de comunidades), `eda/` (informe
  exploratorio), `tablas/` (comparativa de clustering) y `llm/`
  (triaje LLM + informe comparativo).
