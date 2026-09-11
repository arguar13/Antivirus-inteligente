#!/usr/bin/env bash
#
# Verificacion del motor ITDR (FASE 58). Informa SIEMPRE de que se pudo ejercer
# y que no, como el resto de fases con muro.
#
# El NUCLEO —parsear tickets Kerberos byte a byte, decidir Kerberoasting /
# Golden / Silver Ticket y correlacionar el grafo de identidad con la centralidad
# de Brandes— se prueba de verdad en "Servidor · tests" (cargo test incluye el
# crate aegis-itdr y el modulo itdr del plano de control), con tickets DER reales
# y un lote de flota con varios ataques a la vez. Aqui se comprueba, ademas, que
# ese nucleo pasa sus pruebas y se DECLARA el muro: la captura EN VIVO de la capa
# de identidad necesita un dominio Active Directory real.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> ITDR: el nucleo de deteccion pasa sus pruebas"
if (cd server && cargo test -p aegis-itdr --quiet) >/tmp/aegis-itdr.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Kerberoasting, Golden/Silver Ticket, grafo de identidad + Brandes, parser DER)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-itdr.log | tail -20
    exit 1
fi

echo "==> ITDR: captura en vivo de la capa de identidad en esta maquina"
# La ingesta real normaliza los eventos 4768/4769/4770 del Registro de Seguridad
# de un Controlador de Dominio (Windows / ETW-Ti) o los tickets de la red
# (RPC/SMB) a la telemetria del motor. Nada de eso existe en un runner Linux sin
# dominio.
if command -v klist >/dev/null 2>&1 && klist >/dev/null 2>&1; then
    echo "    ${VERDE}credenciales Kerberos presentes${FIN}: hay una fuente de identidad local que ejercer."
else
    echo "    ${GRIS}sin dominio Active Directory / KDC aqui${FIN}: captura en vivo NO ejercida."
    echo "    ${GRIS}El motor que DECIDE (parseo DER, detectores, grafo) SI se prueba arriba y en 'Servidor · tests'.${FIN}"
fi
exit 0
