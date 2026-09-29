#!/usr/bin/env bash
#
# Verificacion de AegisPattern (motor de patrones propio, FASE 101).
#
# CONTRA QUIEN COMPITE: YARA / yara-x y el motor de ClamAV. Se gana en cinco cosas
# que YARA no tiene, cada una por construccion: coste acotado por tipo (una regla
# cuya cota no se puede demostrar NO COMPILA), tri-estado (un escaneo parcial lo
# dice), determinismo y orden, SIN RETROCESO (Pike VM: sin ReDoS por construccion),
# y seguridad de memoria (forbid unsafe en el motor que come entrada hostil).
#
# LA PRUEBA DE QUE LA FASE TERMINO (invariante 8 del MEGAPROMPT 11): la fila de
# yara-x DESAPARECE del arbol del agente. Se comprueba aqui.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisPattern: el motor propio (nucleo, cota, tri-estado, sin retroceso)"
if cargo test -p aegis-patron --lib >/tmp/aegis-patron.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (regex sin retroceso —el patologico (a+)+ corre en tiempo lineal—;"
    echo "    ${VERDE}  ${FIN} Aho-Corasick multi-literal; una regla con salto sin cota NO COMPILA;"
    echo "    ${VERDE}  ${FIN} escaneo parcial declarado; y el mismo motor para fichero y memoria)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-patron.log | tail -30; exit 1
fi

echo "==> AegisPattern: paridad con yara-x sobre el conjunto base del agente"
if cargo test -p aegis-patron --test paridad >/tmp/aegis-patron-par.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (base.yar compila con sus 14 reglas y da LAS MISMAS coincidencias"
    echo "    ${VERDE}  ${FIN} que yara-x sobre entradas dirigidas y un barrido generativo de 200"
    echo "    ${VERDE}  ${FIN} pasadas, cero divergencias. yara-x es aqui dependencia de PRUEBA)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-patron-par.log | tail -30; exit 1
fi

echo "==> AegisPattern: autoataque (compilador y motor como superficie)"
if cargo test -p aegis-patron --test autoataque >/tmp/aegis-patron-ata.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (reglas hostiles rechazadas en compilacion; entradas hostiles —enormes,"
    echo "    ${VERDE}  ${FIN} repetitivas, casi-coincidentes— sin panico ni cuelgue ni reserva sin cota)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-patron-ata.log | tail -30; exit 1
fi

echo "==> AegisPattern: yara-x DESAPARECIO del arbol del agente (invariante 8)"
EN_BASE=$(grep -c "^yara-x" tools/lineabase-agente.txt)
EN_ARBOL=$(cargo tree -p aegis-scan -e no-dev 2>/dev/null | grep -c "yara-x")
if [ "$EN_BASE" = "0" ] && [ "$EN_ARBOL" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (yara-x no esta en tools/lineabase-agente.txt ni en el arbol de"
    echo "    ${VERDE}  ${FIN} produccion de aegis-scan. Un producto no puede superar a su propia"
    echo "    ${VERDE}  ${FIN} dependencia: ahora el motor del camino de decision es propio)"
else
    echo "    ${ROJO}FALLO${FIN}: yara-x sigue en el arbol del agente (lineabase=$EN_BASE, arbol=$EN_ARBOL)"
    exit 1
fi
exit 0
