#!/usr/bin/env bash
#
# Verificacion de AegisRange (emulacion de adversario y medida de cobertura, FASE 99).
#
# CONTRA QUIEN COMPITE: MITRE Caldera y Atomic Red Team. Esos ejecutan tecnicas y
# dejan que TU mires si detectaste; el ciclo lo cierra una persona. Aqui el ciclo
# se cierra automatico: se ejecuta una emulacion BENIGNA y REVERSIBLE de la tecnica
# en un rango declarado, se pregunta al arbitro por la entidad afectada, y si no
# hubo veredicto se DICE como hueco de cobertura con el nombre de la tecnica. La
# cobertura deja de ser una opinion y pasa a ser una cifra reproducible.
#
# LAS TRES GARANTIAS, comprobadas por tipo y por prueba:
#   - SOLO EN EL RANGO: una tecnica no se ejecuta sin la PruebaDeRango, que solo
#     acuna un rango declarado. La prueba no se puede fabricar (compile_fail).
#   - REVERSION OBLIGATORIA: el rasgo exige `revertir` sin cuerpo por defecto —una
#     tecnica sin reversion NO COMPILA (compile_fail)— y la medida revierte siempre
#     y comprueba que no queda residuo.
#   - EMULACION BENIGNA: el gesto es un marcador dentro de la jaula; no hay payload.
#
# HONESTIDAD: tres estados por tecnica —detectada, no detectada, no aplicable— y
# jamas se cuenta una «no aplicable» como detectada.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisRange: el catalogo, el rango y la medida de cobertura"
if (cd server && cargo test -q -p aegis-rango) >/tmp/aegis-rango.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (al menos una tecnica por cada una de las 14 tacticas de ATT&CK"
    echo "    ${VERDE}  ${FIN} Enterprise, incluidas las 14 del motor conductual; se ejecutan, se"
    echo "    ${VERDE}  ${FIN} miden contra el arbitro REAL, se revierten y no dejan residuo; los"
    echo "    ${VERDE}  ${FIN} huecos —el conductual y el forense de memoria, que hoy no entregan"
    echo "    ${VERDE}  ${FIN} señal— salen nombrados; y la cifra es reproducible entre ejecuciones)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-rango.log | tail -30
    exit 1
fi

echo "==> AegisRange: solo en el rango y reversion, por tipo (compile_fail)"
if (cd server && cargo test -q -p aegis-rango --doc) >/tmp/aegis-rango-doc.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (una tecnica sin reversion NO COMPILA; y la PruebaDeRango no se"
    echo "    ${VERDE}  ${FIN} puede fabricar fuera de un rango declarado: no hay via de ejecucion"
    echo "    ${VERDE}  ${FIN} contra produccion, y eso se verifica por lo que el tipo NO ofrece)"
else
    echo "    ${ROJO}FALLO${FIN}: los compile_fail del rango no se sostienen"
    sed 's/^/    | /' /tmp/aegis-rango-doc.log | tail -30
    exit 1
fi
exit 0
