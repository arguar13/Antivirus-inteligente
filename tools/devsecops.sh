#!/usr/bin/env bash
#
# Pipeline DevSecOps de AegisCore (FASE 35).
#
# Es la puerta CONTINUA, mas pesada que `make ci` (la puerta por commit): reune
# las tres patas de la seguridad de la construccion —fuzzing continuo,
# sanitizacion de memoria y auditoria de dependencias— y emite un veredicto
# unico. Pensada para correr en un pipeline nocturno o programado, no en cada
# push.
#
# Uso:  tools/devsecops.sh [SEGUNDOS_FUZZ_POR_OBJETIVO]
#   Por defecto 30 s/objetivo de fuzzing.
#
# Codigo de salida 0 si las tres patas pasan; 1 si alguna falla.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'
SEG_FUZZ="${1:-30}"

titulo() { printf '\n%s########## %s ##########%s\n' "$NEGRITA" "$1" "$FIN"; }

FALLOS=0

titulo "1/3 · Auditoria de dependencias"
./tools/audit.sh || FALLOS=$((FALLOS + 1))

titulo "2/3 · Sanitizacion de memoria"
./tools/sanitize.sh || FALLOS=$((FALLOS + 1))

titulo "3/3 · Fuzzing continuo"
./tools/fuzz.sh "$SEG_FUZZ" || FALLOS=$((FALLOS + 1))

titulo "Veredicto DevSecOps"
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sPIPELINE DEVSECOPS SUPERADO.%s Las tres patas en verde.\n' "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sPIPELINE DEVSECOPS: %d pata(s) fallaron.%s\n' "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
