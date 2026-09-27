#!/usr/bin/env bash
#
# Verificacion de AegisEmulate (emulacion, ejecucion simbolica acotada y
# desempaquetado generico, FASE 102).
#
# CONTRA QUIEN COMPITE: Qiling, Unicorn, unipacker y angr. Se gana en cuatro cosas:
#  - LA AUSENCIA ES LA FRONTERA: el emulador no tiene salida al sistema real. Se
#    verifica AQUI por lo que FALTA en el codigo de produccion —ni fichero, ni
#    socket, ni proceso, ni reloj del anfitrion—, no por una comprobacion que
#    podria estar mal.
#  - EJECUCION SIMBOLICA ACOTADA sobre la IR de la FASE 100: presupuesto de estados
#    parte del tipo; angr no acota y explota.
#  - DESEMPAQUETADO GENERICO por observacion, no por firma: un empaquetador nuevo
#    se desempaqueta sin regla nueva.
#  - DETERMINISMO: el estado inicial es explicito; dos emulaciones son iguales.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisEmulate: MMU, interprete, entorno, simbolico y desempaquetado"
if cargo test -p aegis-emular >/tmp/aegis-emular.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (MMU con permisos reales W^X; interprete x86-64 sobre ella; entorno"
    echo "    ${VERDE}  ${FIN} sintetico; ejecucion simbolica acotada sobre la IR de la FASE 100 que"
    echo "    ${VERDE}  ${FIN} resuelve saltos calculados y se rinde por presupuesto; y un stub real"
    echo "    ${VERDE}  ${FIN} auto-descomprimido se desempaqueta por observacion —OEP con sus tres"
    echo "    ${VERDE}  ${FIN} heuristicas—, deterministico y acotado)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-emular.log | tail -30; exit 1
fi

echo "==> AegisEmulate: la ausencia es la frontera (no hay salida al sistema real)"
# Se busca en el codigo de PRODUCCION (src/, no las pruebas) cualquier via de
# escape al anfitrion. Debe dar cero: el emulador solo toca su MMU y su entorno
# sintetico.
PATRON='std::fs|File::(open|create)|TcpStream|UdpSocket|TcpListener|process::Command|SystemTime::now|Instant::now|std::net|std::process'
FUGAS=$(grep -rnE "$PATRON" crates/aegis-emular/src/ 2>/dev/null | grep -v '^\s*//' | wc -l)
if [ "$FUGAS" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (cero vias de salida al sistema real en el codigo del emulador:"
    echo "    ${VERDE}  ${FIN} ni fichero, ni socket, ni proceso, ni reloj del anfitrion. Qiling"
    echo "    ${VERDE}  ${FIN} puede montar el FS del host; aqui el tipo no lo ofrece)"
else
    echo "    ${ROJO}FALLO${FIN}: hay $FUGAS via(s) de salida al sistema real en el emulador:"
    grep -rnE "$PATRON" crates/aegis-emular/src/ | grep -v '^\s*//' | sed 's/^/    | /'
    exit 1
fi
exit 0
