#!/usr/bin/env bash
#
# Construccion reproducible bit a bit (FASE 108).
#
# in-toto atestigua lo que PASO; esto demuestra que se puede REPETIR: dos
# construcciones del mismo fuente, con los mismos flags, dan el MISMO binario byte
# a byte. Es una afirmacion mucho mas fuerte, y casi nadie la sostiene.
#
# Las fuentes de no-determinismo de rustc son conocidas y se cierran con flags:
#  - rutas absolutas incrustadas   -> --remap-path-prefix
#  - orden de codegen en paralelo   -> -C codegen-units=1
#  - marca de tiempo / build-id     -> rustc no la incrusta por defecto
#
# Lo que este script demuestra en UNA maquina es la reproducibilidad TEMPORAL (dos
# builds seguidos, mismo hash). La reproducibilidad CROSS-MAQUINA de la flota entera
# necesita dos runners distintos; se DECLARA como el paso que la cierra, en vez de
# fingir que este contenedor son dos maquinas.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'

RUSTC="$(command -v rustc || true)"
if [ -z "$RUSTC" ]; then
    echo "${GRIS}rustc no esta en el PATH: demostracion de reproducibilidad OMITIDA.${FIN}"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Un fuente fijo y representativo (aritmetica + formato, como un artefacto real).
cat > "$TMP/repro.rs" <<'RS'
fn fib(n: u64) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n { let t = a.wrapping_add(b); a = b; b = t; }
    a
}
fn main() {
    let mut acc = 0u64;
    for i in 0..90 { acc = acc.wrapping_add(fib(i)); }
    println!("{acc}");
}
RS

# Flags que cierran las fuentes conocidas de no-determinismo.
FLAGS="-C codegen-units=1 -C debuginfo=0 --remap-path-prefix=$TMP=/build"
export SOURCE_DATE_EPOCH=0

echo "==> construir-reproducible: dos construcciones del mismo fuente"
"$RUSTC" $FLAGS -O -o "$TMP/a.bin" "$TMP/repro.rs" 2>/tmp/repro-a.log || {
    echo "    ${ROJO}FALLO${FIN}: la primera construccion no compila"; sed 's/^/    | /' /tmp/repro-a.log | tail; exit 1; }
"$RUSTC" $FLAGS -O -o "$TMP/b.bin" "$TMP/repro.rs" 2>/tmp/repro-b.log || {
    echo "    ${ROJO}FALLO${FIN}: la segunda construccion no compila"; sed 's/^/    | /' /tmp/repro-b.log | tail; exit 1; }

HA="$(sha256sum "$TMP/a.bin" | cut -d' ' -f1)"
HB="$(sha256sum "$TMP/b.bin" | cut -d' ' -f1)"

if [ "$HA" = "$HB" ]; then
    echo "    ${VERDE}OK${FIN}: dos construcciones -> el MISMO binario (sha256 $HA)"
    echo "    ${GRIS}Reproducibilidad temporal demostrada. La cross-maquina de la flota${FIN}"
    echo "    ${GRIS}se cierra con dos runners distintos, y se declara.${FIN}"
    exit 0
else
    # No se maquilla: se declara la diferencia y su causa probable, para arreglarla.
    echo "    ${ROJO}NO REPRODUCIBLE${FIN}: las dos construcciones difieren"
    echo "    | a: $HA"
    echo "    | b: $HB"
    echo "    ${GRIS}Hay una fuente de no-determinismo (marca de tiempo, orden, ruta) que${FIN}"
    echo "    ${GRIS}arreglar en la causa. Ver docs/100-procedencia.md.${FIN}"
    exit 1
fi
