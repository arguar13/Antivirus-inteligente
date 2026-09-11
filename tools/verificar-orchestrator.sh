#!/usr/bin/env bash
#
# Verificacion de AegisOrchestrator (AI-RO, FASE 64). Informa SIEMPRE de que se
# pudo ejercer y que no, como el resto de fases con muro.
#
# El NUCLEO —lo que puede estar MAL de forma peligrosa— se prueba de verdad en
# "Servidor · tests" (cargo test): la maquina de estados de remediacion elige el
# playbook segun la amenaza, lanza las acciones EN PARALELO, sobrevive a fallos
# parciales (un fallo no aborta las demas), es idempotente en el reintento (solo
# repite lo fallido) y no toca la flota por una sospecha debil. Aqui se re-ejercita
# y se DECLARA el muro.
#
# El muro es la EJECUCION REAL de cada accion contra un sistema real: programar el
# XDP en el kernel del endpoint, matar un proceso, revocar un ticket en la KDC,
# volcar la RAM. Eso ocurre en el agente, por el canal gRPC/mTLS, y NO se ejercita
# aqui: en las pruebas, un doble controlable ocupa el lugar de la flota (registra
# que se le pidio y devuelve exito o fallo a voluntad), que es justo el muro.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

if [ ! -d server ]; then
    echo "    ${GRIS}servidor no presente en este arbol: omitido${FIN}"
    exit 0
fi

echo "==> AegisOrchestrator: la maquina de estados de remediacion se prueba entera"
if cargo test --manifest-path server/Cargo.toml -p aegis-orchestrator --quiet \
    >/tmp/aegis-orchestrator.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Golden Ticket -> 4 acciones en paralelo; fallo parcial resiliente; reintento idempotente; no-critico no actua)"
else
    echo "    ${ROJO}FALLO${FIN}: la maquina de estados de remediacion no pasa"
    sed 's/^/    | /' /tmp/aegis-orchestrator.log | tail -30
    exit 1
fi

echo "==> AegisOrchestrator: ejecucion REAL de las acciones contra la flota (muro)"
echo "    ${GRIS}NO ejercida aqui: programar el XDP en el kernel del endpoint, matar un proceso,${FIN}"
echo "    ${GRIS}revocar un ticket en la KDC o volcar la RAM ocurre en el AGENTE, contra un sistema${FIN}"
echo "    ${GRIS}real, por gRPC/mTLS. En las pruebas, un doble de la frontera ocupa el lugar de la${FIN}"
echo "    ${GRIS}flota; la MAQUINA DE ESTADOS (playbook, paralelismo, fallos, idempotencia) SI se prueba.${FIN}"
exit 0
