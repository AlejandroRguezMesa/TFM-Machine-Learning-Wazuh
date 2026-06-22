#!/usr/bin/env bash
#
# run_seguimiento2.sh — Orquestador completo del experimento del seguimiento 2
#
# Lanza el flujo end-to-end del sistema y lo presenta de forma que sirva
# para capturas de pantalla en la memoria del TFM:
#
#   1. Limpieza de estado previo
#   2. Inyección de alertas REALES (5k) como fondo realista
#   3. Lanzamiento de escenarios SINTÉTICOS cross-source (S06, S07, S08)
#   4. Lanzamiento de ruido benigno (noise_runner)
#   5. Espera a indexación
#   6. Extracción del Indexer + dedup + normalización
#   7. Capa 2 (HDBSCAN)
#   8. Capa 3 (grafo + Louvain)
#   9. Push a Indexer (índices wazuh-correlation-*)
#  10. Resumen de resultados
#
# Uso:
#   sudo bash run_seguimiento2.sh                 # ejecución completa
#   sudo bash run_seguimiento2.sh --skip-real    # solo sintéticos (rápido)
#   sudo bash run_seguimiento2.sh --no-push      # no subir al Indexer
#   sudo bash run_seguimiento2.sh --real-n 10000 # más volumen de fondo
#
# REQUISITOS:
#   - .venv configurado con dependencias
#   - .env con credenciales del Indexer
#   - alerts_filtrado.json en $HOME/Descargas/
#   - Wazuh manager corriendo en local

set -euo pipefail

# ============ Configuración ============
REAL_SRC="${REAL_SRC:-$HOME/Descargas/alerts_filtrado.json}"
REAL_N="${REAL_N:-5000}"
REAL_DURATION_MIN="${REAL_DURATION_MIN:-30}"
# 64508 = drops masivos del firewall; 40704 = systemd service failures
# (ruido de la propia VM, detectado en el EDA del nuevo volcado)
EXCLUDE_RULES="${EXCLUDE_RULES:-64508,40704}"
# decoders de ruido operativo a excluir en la extracción:
# web-accesslog trae el campo srcip corrupto (timestamps), no aporta
EXCLUDE_DECODERS="${EXCLUDE_DECODERS:-web-accesslog}"
SCENARIOS=("scenarios/s06_o365_to_paloalto_c2.yaml"
           "scenarios/s07_edr_to_pa_to_vcenter.yaml"
           "scenarios/s08_o365_to_vcenter_lateral.yaml"
           "scenarios/s09_o365_account_compromise_ip_pivot.yaml")
NOISE_DURATION="${NOISE_DURATION:-300}"
WAIT_INDEX_SEC="${WAIT_INDEX_SEC:-45}"
EXTRACT_WINDOW="${EXTRACT_WINDOW:-90m}"
VENV="${VENV:-.venv/bin/python}"

# ============ Flags CLI ============
SKIP_REAL=false
SKIP_SYNTH=false
SKIP_NOISE=false
NO_PUSH=false
SKIP_PIPELINE=false
# Anonimizacion de usuarios: on por defecto. Pasar --no-anonymize para
# reproducir exactamente el run canonico documentado en run_final.log
# (con nombres de usuario crudos).
ANONYMIZE_USERS=true
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-real)     SKIP_REAL=true ;;
        --skip-synth)    SKIP_SYNTH=true ;;
        --skip-noise)    SKIP_NOISE=true ;;
        --skip-pipeline) SKIP_PIPELINE=true ;;
        --no-push)       NO_PUSH=true ;;
        --no-anonymize|--no-anonymize-users) ANONYMIZE_USERS=false ;;
        --real-n)        REAL_N="$2"; shift ;;
        --duration)      REAL_DURATION_MIN="$2"; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Flag desconocida: $1"; exit 1 ;;
    esac
    shift
done

# ============ Colores ============
if [[ -t 1 ]]; then
    BOLD="\033[1m"; DIM="\033[2m"; UNDERLINE="\033[4m"
    RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
    BLUE="\033[34m"; MAGENTA="\033[35m"; CYAN="\033[36m"; WHITE="\033[37m"
    RESET="\033[0m"
else
    BOLD=""; DIM=""; UNDERLINE=""; RED=""; GREEN=""; YELLOW=""
    BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; RESET=""
fi

# ============ UI helpers ============
hr()      { printf "${DIM}%s${RESET}\n" "────────────────────────────────────────────────────────────────────────"; }
banner()  {
    echo
    printf "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${BOLD}${CYAN}║${RESET}  ${BOLD}${WHITE}%-66s${RESET}  ${BOLD}${CYAN}║${RESET}\n" "$1"
    printf "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════╝${RESET}\n"
}
step()    { printf "\n${BOLD}${BLUE}▶${RESET} ${BOLD}%s${RESET}\n" "$1"; }
sub()     { printf "  ${DIM}·${RESET} %s\n" "$1"; }
ok()      { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
warn()    { printf "  ${YELLOW}⚠${RESET} %s\n" "$1"; }
err()     { printf "  ${RED}✗${RESET} %s\n" "$1" >&2; }
note()    { printf "  ${DIM}%s${RESET}\n" "$1"; }
kv()      { printf "  ${DIM}%-22s${RESET} ${BOLD}%s${RESET}\n" "$1:" "$2"; }
timer_start() { TIMER_START=$(date +%s); }
timer_end()   {
    local elapsed=$(( $(date +%s) - TIMER_START ))
    local m=$((elapsed / 60)); local s=$((elapsed % 60))
    printf "  ${GREEN}⏱${RESET}  Completado en ${BOLD}%02d:%02d${RESET}\n" "$m" "$s"
}

# ============ Sanity checks ============
banner "TFM – Pipeline de correlación multi-capa (seguimiento 2)"

step "[0/10] Verificando entorno"
[[ -f "$VENV" ]]      || { err "Falta $VENV — activa el venv"; exit 1; }
[[ -f ".env" ]]       || { err "Falta .env con credenciales del Indexer"; exit 1; }
ok ".venv encontrado"
ok ".env encontrado"

if ! $SKIP_REAL; then
    [[ -f "$REAL_SRC" ]] || { err "No existe $REAL_SRC"; exit 1; }
    REAL_SIZE_GB=$(du -h "$REAL_SRC" | cut -f1)
    ok "Fichero real: $REAL_SRC ($REAL_SIZE_GB)"
fi

kv "Venv"             "$VENV"
kv "REAL_SRC"         "$REAL_SRC"
kv "REAL_N"           "$REAL_N alertas"
kv "DURATION_MIN"     "$REAL_DURATION_MIN min"
kv "Escenarios"       "${SCENARIOS[*]##*/}"
kv "Noise duration"   "${NOISE_DURATION}s"
kv "Ventana extracción" "$EXTRACT_WINDOW"
if $ANONYMIZE_USERS; then
    kv "Anonimizacion users" "ACTIVA (mapa: lab_state/user_alias_map.json)"
else
    kv "Anonimizacion users" "DESACTIVADA (--no-anonymize)"
fi

_INDEXER_LOG="$(mktemp)"
if ! $VENV indexer_client.py >"$_INDEXER_LOG" 2>&1; then
    err "Conexión al Indexer falla. Revisa .env y permisos del usuario."
    echo
    err "Salida del cliente:"
    sed 's/^/      /' "$_INDEXER_LOG" >&2
    rm -f "$_INDEXER_LOG"
    exit 1
fi
rm -f "$_INDEXER_LOG"
ok "Conexión al Indexer OK"

# ============ 1. Limpieza ============
step "[1/10] Limpiando estado anterior"
sub "Truncando logs del lab"
truncate -s 0 /var/log/lab/*.log 2>/dev/null || true
truncate -s 0 /var/log/sentinelone.json /var/log/sentinelone_activities.json \
              /var/log/sentinelone-device-control.json 2>/dev/null || true
sub "Limpiando ground_truth previo"
rm -f lab_state/ground_truth.jsonl
ok "Estado limpio"

# ============ 2. Inyección de alertas reales ============
if ! $SKIP_REAL; then
    banner "FASE 1: INYECCIÓN DE FONDO REAL"
    timer_start
    step "[2/10] Inyectando $REAL_N alertas reales como fondo"
    sub "Excluyendo rule.id: $EXCLUDE_RULES (ruido masivo silenciado)"
    sub "Ventana temporal: últimos $REAL_DURATION_MIN min"

    # construimos los args como array para soportar tokens con espacios
    # y, sobre todo, para descartar tokens vacios si EXCLUDE_RULES tiene
    # comas consecutivas o esta vacia (evita pasar "--exclude-rule" sin
    # valor a Python).
    EXCLUDE_ARGS=()
    IFS=',' read -ra _RULES <<< "$EXCLUDE_RULES"
    for r in "${_RULES[@]}"; do
        r="${r//[[:space:]]/}"
        [[ -z "$r" ]] && continue
        EXCLUDE_ARGS+=(--exclude-rule "$r")
    done

    $VENV inject_real_alerts.py "$REAL_SRC" \
        --n "$REAL_N" \
        --duration-min "$REAL_DURATION_MIN" \
        "${EXCLUDE_ARGS[@]}" \
        2>&1 | sed 's/^/      /'
    ok "Alertas reales inyectadas"
    timer_end
else
    warn "Saltando inyección de fondo real (--skip-real)"
fi

# ============ 3. Escenarios sintéticos ============
if ! $SKIP_SYNTH; then
    banner "FASE 2: ESCENARIOS SINTÉTICOS CROSS-SOURCE"
    timer_start
    step "[3/10] Lanzando ${#SCENARIOS[@]} escenarios cross-source"

    # Ruido en paralelo durante los escenarios
    if ! $SKIP_NOISE; then
        sub "Iniciando ruido benigno paralelo (Poisson) durante ${NOISE_DURATION}s"
        $VENV noise_runner.py --duration "$NOISE_DURATION" \
            > /tmp/noise_runner.log 2>&1 &
        NOISE_PID=$!
        ok "noise_runner iniciado (PID=$NOISE_PID)"
        sleep 2
    fi

    for sc in "${SCENARIOS[@]}"; do
        echo
        hr
        sub "Lanzando $(basename "$sc")"
        # time-scale 0.2 = 5x más rápido pero con margen para que el
        # clustering vea densidad temporal correcta
        $VENV scenario_runner.py "$sc" --time-scale 0.2 2>&1 | sed 's/^/      /'
        ok "Escenario $(basename "$sc" .yaml) completado"
        # Espaciar escenarios para que la Capa 2 los vea como bloques distintos
        if [[ "$sc" != "${SCENARIOS[-1]}" ]]; then
            sub "Pausa 45s antes del siguiente escenario..."
            sleep 45
        fi
    done

    if ! $SKIP_NOISE && [[ -n "${NOISE_PID:-}" ]]; then
        sub "Parando noise_runner..."
        kill "$NOISE_PID" 2>/dev/null || true
        wait "$NOISE_PID" 2>/dev/null || true
        ok "Ruido benigno terminado"
    fi
    timer_end
else
    warn "Saltando escenarios sintéticos (--skip-synth)"
fi

# ============ 4. Espera a indexación ============
banner "FASE 3: PROCESAMIENTO Y CORRELACIÓN"
step "[4/10] Esperando ${WAIT_INDEX_SEC}s para que Wazuh indexe todas las alertas"
sub "El manager procesa los logs, las reglas evalúan, Filebeat las envía al Indexer"
for i in $(seq "$WAIT_INDEX_SEC" -1 1); do
    printf "\r  ${DIM}esperando... %02d s${RESET}  " "$i"
    sleep 1
done
printf "\r${GREEN}  ✓${RESET} Wazuh ha tenido tiempo de indexar          \n"

# ============ 5. Pipeline ML ============
if ! $SKIP_PIPELINE; then
    timer_start
    step "[5/10] Extrayendo alertas del Indexer (ventana: $EXTRACT_WINDOW)"
    if $ANONYMIZE_USERS; then
        sub "Anonimizacion de usuarios ACTIVA: cada usuario canonico se "
        sub "  sustituye por un alias estable 'user_NNNN_anonymized'."
        sub "  El mapa se persiste en lab_state/user_alias_map.json (modo 600)."
        sub "  IPs y hostnames NO se anonimizan."
    fi
    # mismo patron defensivo que con EXCLUDE_RULES: array + skip vacios.
    EXTRACT_EXCL=()
    IFS=',' read -ra _DECS <<< "$EXCLUDE_DECODERS"
    for d in "${_DECS[@]}"; do
        d="${d//[[:space:]]/}"
        [[ -z "$d" ]] && continue
        EXTRACT_EXCL+=(--exclude-decoder "$d")
    done
    EXTRACT_ANON_FLAG=()
    if ! $ANONYMIZE_USERS; then
        EXTRACT_ANON_FLAG=(--no-anonymize-users)
    fi
    $VENV extract_indexer.py --since "now-$EXTRACT_WINDOW" \
        "${EXTRACT_EXCL[@]}" "${EXTRACT_ANON_FLAG[@]}" 2>&1 | sed 's/^/      /'
    ok "Extracción completada"
    timer_end

    timer_start
    step "[6/10] Capa 2: clustering HDBSCAN sobre features (UMAP-8)"
    $VENV cluster_real.py \
        --min-cluster 3 \
        --time-weight 1.0 \
        --umap-dims 8 2>&1 | sed 's/^/      /'
    ok "Clustering Capa 2 completado"
    timer_end

    timer_start
    step "[7/10] Capa 3: grafo de FILAS + Louvain"
    # Capa 3 sin decaimiento temporal. La campana de 5 runs documentada
    # en CAMPANA_DECAY.md descarto config B (decay exponencial tau=60):
    # B se desploma a 0/4-2/4 en la mayoria de runs. A mantiene 4/4
    # estable. El decay queda implementado como mecanismo (validado en
    # escenario S10) pero desactivado por defecto.
    $VENV graph_layer_real.py --min-shared 1 --min-weight 1.0 \
        --decay-kind none \
        --max-rows-frac 0.10 --max-decoders 4 \
        --min-comm-size 3 2>&1 | sed 's/^/      /'
    ok "Detección de comunidades completada"
    timer_end

    # ============ 6. Push al Indexer ============
    if ! $NO_PUSH; then
        timer_start
        step "[8/10] Subiendo resultados a wazuh-correlation-*"
        $VENV push_to_indexer.py --recreate 2>&1 | sed 's/^/      /'
        ok "Push al Indexer completado"
        timer_end
    else
        warn "Saltando push al Indexer (--no-push)"
    fi
else
    warn "Saltando pipeline ML (--skip-pipeline)"
fi

# ============ Resumen ============
banner "RESUMEN DEL RUN"

if [[ -f lab_state/real_alerts_incidents.parquet ]]; then
    step "[9/10] Métricas finales"
    $VENV - <<'PYEOF' 2>&1 | sed 's/^/      /'
import pandas as pd
from pathlib import Path

p = Path("lab_state/real_alerts_incidents.parquet")
df = pd.read_parquet(p)
n_alertas = int(df["count"].sum())
n_filas = len(df)
n_clusters = df.loc[df["cluster_id"] != -1, "cluster_id"].nunique()
n_comms = df.loc[df["community_id"] >= 0, "community_id"].nunique()

print(f"\nALERTAS WAZUH ORIGINALES:    {n_alertas:>10,}")
print(f"  → tras dedup temporal:     {n_filas:>10,}  ({100*(1-n_filas/n_alertas):.1f}% reducción)")
print(f"  → micro-clusters Capa 2:   {n_clusters:>10,}")
print(f"  → comunidades Capa 3:      {n_comms:>10,}")
if n_comms:
    factor = n_alertas / n_comms
    print(f"\n  FACTOR DE REDUCCIÓN GLOBAL: {factor:.1f}:1  "
          f"({100*(1-n_comms/n_alertas):.3f}%)")

# Cross-source: comunidades con MÁS DE UN decoder distinto
print()
multi_dec = []
valid = df[df["community_id"] >= 0]
for cid, sub in valid.groupby("community_id"):
    decoders = set(sub["decoder.name"].dropna().unique())
    if len(decoders) > 1:
        multi_dec.append((cid, decoders, int(sub["count"].sum()),
                          len(sub)))
multi_dec.sort(key=lambda x: -x[2])
print(f"COMUNIDADES CROSS-SOURCE (>1 decoder): {len(multi_dec)}/{n_comms}")
for cid, decs, alertas, filas in multi_dec[:10]:
    decs_str = ", ".join(sorted(decs))
    print(f"  comunidad {cid:>3}:  {alertas:>5,} alertas  {filas:>4} filas  "
          f"  decoders=[{decs_str}]")
PYEOF

    # Verificación específica de los escenarios sintéticos
    echo
    step "[9.5/10] Verificación de escenarios sintéticos (cross-source)"
    $VENV verify_scenarios.py 2>&1 | sed 's/^/      /'

    # Generación de las figuras para la memoria
    echo
    step "[9.6/10] Generando figuras de resultados en capturas/"
    $VENV generar_graficas.py 2>&1 | sed 's/^/      /'
fi

# ============ Cierre ============
step "[10/10] Próximos pasos"
sub "Dashboard:    Wazuh → Dashboards → 'TFM — Métricas de correlación'"
sub "              Time picker: 'Last 2 hours' o 'Last 4 hours'"
sub "Drill-down:   Discover → wazuh-correlation-alerts-* → filtra community_id"
sub "Datos:        lab_state/real_alerts_incidents.parquet"
echo

printf "${BOLD}${GREEN}✓ Pipeline completo finalizado correctamente${RESET}\n"
echo
