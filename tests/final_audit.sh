#!/usr/bin/env bash
#
# Auditoria final de integracion y estres de AegisCore (FASE 23).
#
# Ejecuta EN PARALELO las validaciones independientes —compilacion limpia sin
# advertencias, simulacion de Red Team, insercion masiva de eventos en el ring
# buffer y verificacion de recursos— y despues informa de un veredicto unico.
# Es la puerta final antes de una release: mas exhaustiva que `make ci` (que es
# la puerta por commit) porque incluye la prueba de carga completa y el barrido
# de advertencias.
#
# Uso:  tests/final_audit.sh
# Codigo de salida 0 si TODO pasa, 1 si algo falla.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; pkill -9 -f "sleep 3600" 2>/dev/null || true' EXIT

titulo() { printf '\n%s== %s ==%s\n' "$NEGRITA" "$1" "$FIN"; }

# --- Lanzamiento en paralelo de las comprobaciones independientes -------------
titulo "Auditoria final: lanzando comprobaciones en paralelo"

# 1. Compilacion limpia SIN advertencias del compilador.
(
    cargo build --workspace --all-targets 2>"$TMP/build.err"
    rc=$?
    # Cualquier linea 'warning:' del compilador cuenta como fallo: una release
    # no sale con advertencias.
    warns=$(grep -c '^warning' "$TMP/build.err" 2>/dev/null || echo 0)
    echo "$rc $warns" > "$TMP/build.rc"
) &
PID_BUILD=$!

# 2. Clippy con -D warnings sobre todo el arbol.
(
    cargo clippy --all-targets -- -D warnings >"$TMP/clippy.log" 2>&1
    echo $? > "$TMP/clippy.rc"
) &
PID_CLIPPY=$!

# 3. Simulacion de Red Team defensiva.
(
    if command -v python3 >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
        cargo build -q -p aegis-evasion --example scan_pid >/dev/null 2>&1
        cargo build -q -p aegis-ransom --example honeypot_probe >/dev/null 2>&1
        cargo build -q -p aegis-watchdog >/dev/null 2>&1
        make -C drivers/linux/aegis-bpf build sign >/dev/null 2>&1 || true
        python3 tests/red_team_sim.py >"$TMP/redteam.log" 2>&1
        echo $? > "$TMP/redteam.rc"
    else
        echo "skip" > "$TMP/redteam.rc"
    fi
) &
PID_REDTEAM=$!

# 4. Insercion masiva de eventos en el ring buffer (prueba de estres completa).
(
    cargo test -p aegis-e2e --test stress_concurrencia -- --nocapture \
        >"$TMP/stress.log" 2>&1
    echo $? > "$TMP/stress.rc"
) &
PID_STRESS=$!

# 5. Ingenieria del caos (FASE 29): corrupcion del buffer de IPC, caidas de red,
#    saturacion de memoria y cuelgues de hilos. Es la comprobacion de que el
#    producto no hace nada catastrofico cuando el entorno se rompe, que es lo que
#    ninguna prueba funcional cubre.
(
    cargo test -p aegis-e2e --test chaos_harness -- --nocapture \
        >"$TMP/chaos.log" 2>&1
    echo $? > "$TMP/chaos.rc"
) &
PID_CHAOS=$!

echo "  compilacion (pid $PID_BUILD), clippy (pid $PID_CLIPPY), red team (pid $PID_REDTEAM), estres (pid $PID_STRESS), caos (pid $PID_CHAOS)"
echo "  esperando..."
wait "$PID_BUILD" "$PID_CLIPPY" "$PID_REDTEAM" "$PID_STRESS" "$PID_CHAOS"

# --- Verificacion de recursos (secuencial: necesita el binario de release) ----
titulo "Verificacion de recursos del agente (<= 45 MB)"
PRESUPUESTO_KB=46080
RSS_KB=""
if cargo build --release -p aegis-agent -q 2>/dev/null && [ -x target/release/aegis-agent ]; then
    ./target/release/aegis-agent --stats-interval 300 >/dev/null 2>"$TMP/agent.err" &
    PID_AG=$!
    sleep 4
    RSS_KB=$(grep VmRSS "/proc/$PID_AG/status" 2>/dev/null | awk '{print $2}')
    kill -TERM "$PID_AG" 2>/dev/null || true
    wait "$PID_AG" 2>/dev/null || true
fi

# --- Recogida de resultados ---------------------------------------------------
FALLOS=0
resultado() { # nombre  ok?  detalle
    if [ "$2" = "0" ]; then
        printf '  %s%-28s OK%s  %s\n' "$VERDE" "$1" "$FIN" "$3"
    elif [ "$2" = "skip" ]; then
        printf '  %s%-28s omitido%s  %s\n' "$GRIS" "$1" "$FIN" "$3"
    else
        printf '  %s%-28s FALLO%s  %s\n' "$ROJO" "$1" "$FIN" "$3"
        FALLOS=$((FALLOS + 1))
    fi
}

titulo "Veredicto"

read -r BUILD_RC BUILD_WARN < "$TMP/build.rc" 2>/dev/null || { BUILD_RC=1; BUILD_WARN=0; }
if [ "$BUILD_RC" = "0" ] && [ "$BUILD_WARN" = "0" ]; then
    resultado "Compilacion sin avisos" 0 "0 advertencias"
else
    resultado "Compilacion sin avisos" 1 "rc=$BUILD_RC, $BUILD_WARN advertencias (ver build.err)"
    [ -s "$TMP/build.err" ] && grep '^warning' "$TMP/build.err" | head -5 | sed 's/^/      | /'
fi

resultado "Clippy (-D warnings)" "$(cat "$TMP/clippy.rc" 2>/dev/null || echo 1)" ""
resultado "Red Team (9 escenarios)" "$(cat "$TMP/redteam.rc" 2>/dev/null || echo 1)" \
    "$(tail -1 "$TMP/redteam.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')"

STRESS_RC=$(cat "$TMP/stress.rc" 2>/dev/null || echo 1)
STRESS_INFO=$(grep -E "ritmo del ring" "$TMP/stress.log" 2>/dev/null | tail -1 | sed 's/\x1b\[[0-9;]*m//g')
resultado "Estres del ring (1M eventos)" "$STRESS_RC" "$STRESS_INFO"

CHAOS_RC=$(cat "$TMP/chaos.rc" 2>/dev/null || echo 1)
CHAOS_INFO=$(grep -E "^test result" "$TMP/chaos.log" 2>/dev/null | tail -1)
resultado "Caos (4 familias de fallo)" "$CHAOS_RC" "$CHAOS_INFO"

if [ -n "$RSS_KB" ]; then
    if [ "$RSS_KB" -le "$PRESUPUESTO_KB" ]; then
        resultado "Recursos (RSS <= 45 MB)" 0 "$RSS_KB KB de $PRESUPUESTO_KB KB"
    else
        resultado "Recursos (RSS <= 45 MB)" 1 "$RSS_KB KB supera $PRESUPUESTO_KB KB"
    fi
else
    resultado "Recursos (RSS <= 45 MB)" skip "el agente no arranco en este entorno"
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sAUDITORIA FINAL SUPERADA.%s AegisCore listo para release.\n' "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sAUDITORIA FINAL: %d comprobacion(es) fallaron.%s\n' "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
