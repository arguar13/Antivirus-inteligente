#!/usr/bin/env bash
#
# Verificacion de PTGuard (Intel PT, FASE 51). Informa SIEMPRE de que se pudo
# ejercer y que no, como el resto de fases con muro fisico.
#
# El NUCLEO —decodificar la traza, reconstruir el flujo, decidir ROP/JOP— se
# prueba de verdad en el grupo "Rust · tests" (cargo test --all lo incluye) con
# trazas binarias reales y codigo x86-64 real. Aqui se comprueba, ademas, que la
# FONTANERIA gated (perf_event_open + area AUX) COMPILA, y se declara si esta
# maquina podria capturar de verdad —que aqui NO, por no tener intel_pt—.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> PTGuard: la fontaneria de captura en vivo COMPILA (feature pt-live)"
if cargo check -p aegis-ptguard --features pt-live >/dev/null 2>&1; then
    echo "    ${VERDE}OK${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la fontaneria gated no compila"
    exit 1
fi

echo "==> PTGuard: soporte de Intel PT en esta maquina"
if grep -qw intel_pt /proc/cpuinfo 2>/dev/null; then
    par="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo '?')"
    echo "    ${VERDE}intel_pt PRESENTE${FIN} (perf_event_paranoid=$par): la captura en vivo se puede ejercer aqui."
else
    echo "    ${GRIS}intel_pt AUSENTE${FIN}: captura en vivo NO ejercida aqui (VM sin Intel PT)."
    echo "    ${GRIS}El nucleo (decodificar/reconstruir/decidir) SI se prueba en 'Rust · tests'.${FIN}"
fi
exit 0
