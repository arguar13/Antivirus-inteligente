#!/usr/bin/env bash
#
# Verificacion de AegisDecompile (decompilador determinista a pseudo-C, FASE 100).
#
# CONTRA QUIEN COMPITE: el decompilador de Ghidra, rizin/Cutter y angr. Se gana en
# cuatro cosas que Ghidra no da: DETERMINISMO (la misma entrada da byte a byte la
# misma salida, por nombres derivados del contenido y no del orden), la
# DECOMPILACION ES EVIDENCIA (cada sentencia cita las direcciones que la originan),
# COTA DURA Y CALIDAD DECLARADA (parte de la salida), y NO EJECUTA NADA (por tipo).
#
# LA CIFRA DE LA FASE es el REDONDEO SEMANTICO: se compila un corpus desde C
# conocido, se decompila, se recompila el pseudo-C y se comprueba equivalencia de
# comportamiento sobre entradas generadas. La tasa se publica tal cual sale.
#
# ALCANCE HONESTO de este incremento: se verifica equivalencia sobre el subconjunto
# que hoy se emite como C recompilable —funciones de registros, aritmetica entera
# sobre argumentos, a -O2—. La recuperacion de variables de pila de -O0, la
# destruccion de phi sin errores de arista critica, y ARM64, son incrementos
# siguientes; se decompilan y se leen, pero no cuentan como verificados. La cifra
# mide lo que de verdad se comprobo.
#
# MURO DECLARADO: no se persigue la ergonomia interactiva de Ghidra (renombrado
# colaborativo, scripting, navegacion). Ghidra es un IDE de ingenieria inversa;
# AegisCore es un EDR.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisDecompile: la IR, los tipos, la calidad y la emision determinista"
if (cd . && cargo test -p aegis-decompile --lib) >/tmp/aegis-decompile.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (IR SSA de tres direcciones con memoria explicita; reconstruccion de"
    echo "    ${VERDE}  ${FIN} tipos por unificacion con Desconocido como tope —nunca se inventa un"
    echo "    ${VERDE}  ${FIN} tipo—; nombres estables por hash de contenido —no por orden—; calidad"
    echo "    ${VERDE}  ${FIN} como parte de la salida; y el analisis no ejecuta ni entra en panico"
    echo "    ${VERDE}  ${FIN} con bytes hostiles)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-decompile.log | tail -30
    exit 1
fi

echo "==> AegisDecompile: el redondeo semantico (la cifra de la fase)"
if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
    if (cd . && cargo test -p aegis-decompile --test roundtrip -- --nocapture) \
        >/tmp/aegis-decompile-rt.log 2>&1; then
        echo "    ${VERDE}OK${FIN}: $(grep -m1 'REDONDEO SEMANTICO' /tmp/aegis-decompile-rt.log | sed 's/^ *//')"
    else
        echo "    ${ROJO}FALLO${FIN}: el pseudo-C no recompilo equivalente"
        sed 's/^/    | /' /tmp/aegis-decompile-rt.log | tail -30
        exit 1
    fi
else
    echo "    ${GRIS}sin compilador de C aqui: el redondeo semantico NO se ejercio.${FIN}"
    echo "    ${GRIS}La IR, los tipos, el determinismo y la robustez SI se prueban arriba.${FIN}"
fi
exit 0
