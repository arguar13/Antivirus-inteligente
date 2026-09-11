#!/usr/bin/env bash
#
# Verificacion de AegisHPC (telemetria de la PMU, FASE 61). Informa SIEMPRE de
# que se pudo ejercer y que no, como el resto de fases con muro de hardware.
#
# El NUCLEO —lo que puede estar MAL de forma peligrosa— se prueba de verdad en
# "Rust · tests" (cargo test), con series de datos reales y cero mocks: el
# analizador aprende la linea base por EWMA y decide si un pico de fallos de cache
# es un canal lateral (Flush+Reload/Spectre) o un pico de fallos de prediccion de
# saltos es una cadena ROP/JOP, sin falsos positivos con el trafico normal y sin
# dejarse envenenar la base por un ataque.
#
# Aqui se re-ejercita ese nucleo y se DECLARA el muro: LEER la PMU en vivo necesita
# que el hardware la exponga, y muchas maquinas virtuales (este runner, entre
# ellas) no lo hacen (`perf_event_open` -> ENOENT). No se finge.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisHPC: el nucleo (deteccion de canal lateral y ROP/JOP) se prueba con series reales"
if cargo test -p aegis-hardsense --quiet heuristica:: >/tmp/aegis-hardsense.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (pico de fallos de cache -> canal lateral; pico de fallos de prediccion -> ROP/JOP; normal -> nada)"
else
    echo "    ${ROJO}FALLO${FIN}: el nucleo de AegisHPC no pasa"
    sed 's/^/    | /' /tmp/aegis-hardsense.log | tail -30
    exit 1
fi

echo "==> AegisHPC: soporte de PMU (lectura en vivo por perf_event_open) en esta maquina"
# El propio test de sondeo dice, con honestidad, si hay PMU o no (y por que).
if cargo test -p aegis-hardsense --quiet contadores:: -- --nocapture >/tmp/aegis-hardsense-pmu.log 2>&1; then
    linea="$(grep -m1 'PMU:' /tmp/aegis-hardsense-pmu.log || true)"
    if echo "$linea" | grep -q 'NO disponible'; then
        echo "    ${GRIS}${linea}${FIN}"
        echo "    ${GRIS}La captura en vivo NO se ejercio aqui; la DECISION (heuristica) SI, arriba.${FIN}"
    else
        echo "    ${VERDE}${linea:-PMU disponible}${FIN}"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: el sondeo de PMU entro en panico (no debe)"
    sed 's/^/    | /' /tmp/aegis-hardsense-pmu.log | tail -20
    exit 1
fi
exit 0
