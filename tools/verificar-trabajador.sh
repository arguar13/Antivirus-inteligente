#!/usr/bin/env bash
#
# Verificacion del trabajador confinado (FASE 1 del MP-16).
#
# LA CAUSA RAIZ que cierra: los parsers de bytes hostiles —ELF, PE, Mach-O, el
# modelo, el desensamblador, el emulador— vivian en el mismo proceso que decide,
# y el agente compila con `panic = "abort"`. Un fichero que hiciera entrar en
# panico a cualquiera de ellos apagaba el EDR entero en esa maquina.
#
# Lo que esta puerta sostiene:
#   1. el protocolo, los analizadores y el confinamiento, en sus pruebas;
#   2. el confinamiento REAL, contra el kernel y como root: el trabajador no lee
#      ficheros ni abre sockets (comprobado desde dentro), un panico lo mata y el
#      siguiente analisis lo relanza, la bomba de memoria la para el cgroup, el
#      bucle infinito lo corta el plazo y morir en bucle lo deja enfriando;
#   3. la invariante: ningun parser del trabajador sin objetivo de fuzzing y
#      semillas, y las semillas (donde van los casos encontrados) como
#      regresiones;
#   4. que el instalable NO lleva los analizadores de prueba;
#   5. fuzzing de todos los objetivos del trabajador, con el toolchain fijado.
#      Sin ese toolchain FALLA: un fuzzing que se omite en silencio es un verde
#      falso, que es lo que el MP-15 manda eliminar.
#
# Necesita root para el punto 2 (espacio de nombres de red, cambio de uid,
# cgroup). make ci corre como root en el runner y en WSL.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fallo() { echo "    ${ROJO}FALLO${FIN}: $1"; FALLOS=$((FALLOS + 1)); }
SEGUNDOS_FUZZ="${AEGIS_FUZZ_SEGUNDOS:-15}"

echo "==> Trabajador: protocolo, analizadores, confinamiento y la invariante de fuzzing"
if cargo test -q -p aegis-trabajador > "$TMP/unit.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/unit.log" | awk '{s+=$4} END {print s}') pruebas)"
else
    fallo "cargo test -p aegis-trabajador"; sed 's/^/    | /' "$TMP/unit.log" | tail -30
fi

echo "==> Trabajador: confinamiento real contra el kernel (root)"
if AEGIS_EXIGIR="${AEGIS_EXIGIR:+$AEGIS_EXIGIR,}root" cargo test -q -p aegis-trabajador \
    --features prueba-fallos \
    --test confinamiento_real -- --test-threads=1 > "$TMP/real.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/real.log" | tail -1))"
    echo "    ${GRIS}Sin ficheros ni red desde dentro; panico, bomba de memoria y bucle${FIN}"
    echo "    ${GRIS}infinito terminan en SinDatos con su causa, y el trabajador se relanza.${FIN}"
else
    fallo "confinamiento real"; sed 's/^/    | /' "$TMP/real.log" | tail -40
fi

echo "==> Trabajador: el instalable no lleva los analizadores de prueba"
if cargo build -q --release -p aegis-agent > "$TMP/build.log" 2>&1; then
    BIN="${CARGO_TARGET_DIR:-target}/release/aegis-agent"
    if grep -aq "prueba-panico\|panico provocado por la prueba" "$BIN"; then
        fallo "el binario publicado contiene los analizadores de prueba (feature prueba-fallos)"
    else
        echo "    ${VERDE}OK${FIN} (ninguna cadena de los analizadores de prueba en $BIN)"
    fi
else
    fallo "no compila el agente en release"; sed 's/^/    | /' "$TMP/build.log" | tail -20
fi

echo "==> Trabajador: fuzzing de sus parsers (${SEGUNDOS_FUZZ} s por objetivo)"
if AEGIS_EXIGIR_FUZZ=1 FUZZ_OBJETIVOS="trabajador_*" ./tools/fuzz.sh "$SEGUNDOS_FUZZ" > "$TMP/fuzz.log" 2>&1; then
    grep -E "==>|OK" "$TMP/fuzz.log" | sed 's/^/    | /'
    echo "    ${VERDE}OK${FIN}"
else
    fallo "fuzzing del trabajador"; sed 's/^/    | /' "$TMP/fuzz.log" | tail -40
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> Trabajador verificado${FIN}"
else
    echo "${ROJO}==> Trabajador: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
