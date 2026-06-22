#!/usr/bin/env bash
#
# run_decay.sh — Ejecuta una run de N vueltas para validar la
# configuracion B (decaimiento temporal) del pipeline frente a la A
# (baseline), de forma automatica y desatendida.
#
# Cada vuelta:
#   1. Lanza el pipeline completo (run_seguimiento2.sh) con sudo, lo que
#      genera un dataset nuevo (real_alerts_clustered.parquet).
#   2. Ejecuta comparar_decay_AB.py (como usuario normal, SIN sudo) sobre
#      ese dataset, que compara A vs B y anexa la fila al CSV.
#
# El CSV (comparar_decay_AB.csv) acumula una pareja de filas (A y B) por
# vuelta, cada una con su etiqueta runN, para leerlas juntas al final.
#
# USO:
#   ./run_decay.sh [N_VUELTAS]      (por defecto 5)
#
# Ejemplo:
#   ./run_decay.sh 5
#
# NOTAS:
#   - Pide la contrasena de sudo al principio y la mantiene viva durante
#     toda la run (sudo -v en bucle), para no tener que reintroducirla
#     en cada vuelta.
#   - Si una vuelta del pipeline falla, lo avisa y SIGUE con la siguiente
#     (no aborta la run entera por un fallo puntual).
#   - Renombra cualquier CSV previo a *_previo_TIMESTAMP.csv para que la
#     run arranque limpia, sin borrar datos.
#   - NO modifica el pipeline ni ninguna configuracion. Solo orquesta
#     llamadas a scripts existentes.

set -u  # error si se usa variable no definida (pero NO -e: no queremos
        # que un fallo puntual aborte toda la run)

# ---- Configuracion ----
N_VUELTAS="${1:-5}"
REAL_SRC="${REAL_SRC:-$HOME/Descargas/alerts.json}"
VENV_PY=".venv/bin/python"
CSV="comparar_decay_AB.csv"
LOG_DIR="run_logs"

# ---- Comprobaciones previas ----
if [[ ! -x "$VENV_PY" ]]; then
    echo "ERROR: no encuentro $VENV_PY. Ejecuta desde la raiz del proyecto."
    exit 1
fi
if [[ ! -f "run_seguimiento2.sh" ]]; then
    echo "ERROR: no encuentro run_seguimiento2.sh. Ejecuta desde la raiz."
    exit 1
fi
if [[ ! -f "comparar_decay_AB.py" ]]; then
    echo "ERROR: no encuentro comparar_decay_AB.py."
    exit 1
fi
if [[ ! -f "$REAL_SRC" ]]; then
    echo "ERROR: no encuentro el fichero de alertas reales: $REAL_SRC"
    echo "       Define REAL_SRC=/ruta/a/alerts.json antes de ejecutar."
    exit 1
fi

mkdir -p "$LOG_DIR"

# ---- Apartar CSV previo (sin borrar) ----
if [[ -f "$CSV" ]]; then
    TS=$(date +%Y%m%d_%H%M%S)
    mv "$CSV" "${CSV%.csv}_previo_${TS}.csv"
    echo "CSV previo apartado como ${CSV%.csv}_previo_${TS}.csv"
fi

# ---- Pedir sudo una vez y mantenerlo vivo en segundo plano ----
echo "Se necesita sudo para lanzar el pipeline. Introduce la contrasena:"
sudo -v || { echo "ERROR: sudo no autorizado."; exit 1; }
# refrescar el timestamp de sudo cada 60s mientras dure el script
( while true; do sudo -n -v 2>/dev/null; sleep 60; done ) &
SUDO_KEEPALIVE_PID=$!
# asegurar que matamos el keepalive al salir, pase lo que pase
trap 'kill "$SUDO_KEEPALIVE_PID" 2>/dev/null' EXIT

echo
echo "========================================================"
echo "  CAMPANA DE VALIDACION DEL DECAY — $N_VUELTAS vueltas"
echo "  REAL_SRC = $REAL_SRC"
echo "========================================================"
echo

# ---- Bucle de vueltas ----
INICIO_GLOBAL=$(date +%s)
for (( i=1; i<=N_VUELTAS; i++ )); do
    ETIQUETA="run${i}"
    LOG_PIPELINE="${LOG_DIR}/pipeline_${ETIQUETA}.log"
    LOG_COMPARA="${LOG_DIR}/compara_${ETIQUETA}.log"

    echo "--------------------------------------------------------"
    echo "  VUELTA $i/$N_VUELTAS  (etiqueta: $ETIQUETA)  $(date '+%H:%M:%S')"
    echo "--------------------------------------------------------"

    # 1. Pipeline completo (con sudo). Guardamos log y mostramos solo el
    #    veredicto final por pantalla para no saturar.
    echo "  [1/2] Lanzando run_seguimiento2.sh ... (log: $LOG_PIPELINE)"
    t0=$(date +%s)
    REAL_SRC="$REAL_SRC" sudo -E bash run_seguimiento2.sh > "$LOG_PIPELINE" 2>&1
    rc_pipe=$?
    t1=$(date +%s)
    if [[ $rc_pipe -ne 0 ]]; then
        echo "  [!] El pipeline devolvio codigo $rc_pipe en la vuelta $i."
        echo "      Revisa $LOG_PIPELINE. Sigo con la siguiente vuelta."
        # corregir propietario del lab_state por si sudo dejo ficheros root
        sudo chown -R "$(id -un):$(id -gn)" lab_state 2>/dev/null
        continue
    fi
    echo "      pipeline OK ($(( t1 - t0 ))s). Veredicto del run:"
    grep -E "consolidados correctamente" "$LOG_PIPELINE" | tail -1 | sed 's/^/        /'

    # corregir propietario por si run_seguimiento2.sh (sudo) dejo ficheros
    # de lab_state como root; si no, comparar_decay_AB.py no podria escribir
    sudo chown -R "$(id -un):$(id -gn)" lab_state 2>/dev/null

    # 2. Comparacion pareada A/B (SIN sudo, como usuario normal)
    echo "  [2/2] Comparacion A/B (log: $LOG_COMPARA)"
    "$VENV_PY" comparar_decay_AB.py --run-label "$ETIQUETA" \
        > "$LOG_COMPARA" 2>&1
    rc_cmp=$?
    if [[ $rc_cmp -ne 0 ]]; then
        echo "  [!] comparar_decay_AB.py fallo (codigo $rc_cmp) en vuelta $i."
        echo "      Revisa $LOG_COMPARA."
    else
        # mostrar la comparacion directa A vs B de esta vuelta
        sed -n '/A consolida/,/=====/p' "$LOG_COMPARA" | sed 's/^/      /'
    fi
    echo
done

FIN_GLOBAL=$(date +%s)
echo "========================================================"
echo "  CAMPANA COMPLETADA en $(( (FIN_GLOBAL - INICIO_GLOBAL) / 60 )) min"
echo "========================================================"
echo
echo "  Resultados acumulados en: $CSV"
echo "  Logs por vuelta en:       $LOG_DIR/"
echo
if [[ -f "$CSV" ]]; then
    echo "  Tabla resumen (config / consolidados / recall S06 / pureza S07):"
    echo
    "$VENV_PY" - "$CSV" <<'PYEOF'
import csv, sys
path = sys.argv[1]
with open(path) as f:
    filas = list(csv.DictReader(f))
if not filas:
    print("    (CSV vacio)")
    sys.exit()
cols = filas[0].keys()
# localizar columnas de interes de forma tolerante
def col(sub):
    for c in cols:
        if sub.lower() in c.lower():
            return c
    return None
c_s06r = col("S06_recall")
c_s07p = col("S07_pureza")
hdr = f"    {'run':<12}{'config':<14}{'consolid':<10}"
hdr += f"{'S06_recall':<12}{'S07_pureza':<12}"
print(hdr)
print("    " + "-" * 58)
for r in filas:
    run = r.get("run", "?")
    cfg = r.get("config", "?")
    cons = r.get("consolidados", "?")
    s06 = r.get(c_s06r, "?") if c_s06r else "?"
    s07 = r.get(c_s07p, "?") if c_s07p else "?"
    print(f"    {run:<12}{cfg:<14}{cons:<10}{s06:<12}{s07:<12}")
print()
print("    Lee asi: para cada vuelta hay 2 filas (A_baseline y B_sweetspot).")
print("    VIGILA la fila B: S06_recall debe quedarse >30% de forma estable,")
print("    y S07_pureza deberia subir respecto a su fila A.")
PYEOF
fi
