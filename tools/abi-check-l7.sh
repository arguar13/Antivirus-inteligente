#!/usr/bin/env bash
#
# Verifica que el compilador de C —el que compila el programa eBPF de uprobes— y
# rustc —el que compila el analizador— calculan EXACTAMENTE el mismo layout para
# el evento L7 que viaja por el ring buffer.
#
# POR QUE HACE FALTA, si los dos lados ya tienen aserciones
# --------------------------------------------------------
# Porque cada lado solo puede afirmar lo que el mismo calcula. Las
# `_Static_assert` de aegis_sslsniff.h fijan lo que ve C; las `const` de abi.rs
# fijan lo que ve Rust. Ninguna de las dos puede ver a la otra, asi que si
# alguien cambia la cabecera y "arregla" su asercion, los dos lados quedan
# internamente consistentes y mutuamente incompatibles.
#
# El sintoma de esa divergencia no es un fallo de compilacion: el analizador
# leeria el pid donde hay una longitud y la carga util donde hay una marca de
# tiempo. Es decir, un EDR que procesa basura y por tanto no detecta nada,
# pareciendo que funciona. Aqui se convierte en un fallo del build.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

CC="${CC:-cc}"
echo "==> Sonda C   ($CC)"
"$CC" -std=c11 -Wall -Wextra -Werror \
      -Idrivers/linux/aegis-bpf/include \
      -o "$OUT/abi_probe_l7_c" tools/abi_probe_l7.c
"$OUT/abi_probe_l7_c" > "$OUT/c.txt"

echo "==> Sonda Rust (cargo)"
cargo run --quiet -p aegis-l7hunter --example abi_probe_l7 > "$OUT/rust.txt"

echo "==> Comparando layouts"
if diff -u "$OUT/c.txt" "$OUT/rust.txt" > "$OUT/diff.txt"; then
    echo "OK: $(wc -l < "$OUT/c.txt") entradas de layout coinciden entre C y Rust."
else
    echo "FALLO: el ABI del evento L7 ha divergido entre C y Rust." >&2
    echo "  '-' = lo que dice drivers/linux/aegis-bpf/include/aegis_sslsniff.h" >&2
    echo "  '+' = lo que dice crates/aegis-l7hunter/src/abi.rs" >&2
    cat "$OUT/diff.txt" >&2
    exit 1
fi
