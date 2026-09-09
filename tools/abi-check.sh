#!/usr/bin/env bash
#
# Verifica que el compilador de C (el del driver) y rustc (el del agente)
# calculan EXACTAMENTE el mismo layout para el ABI compartido.
#
# Las aserciones const de abi.rs ya fijan los valores esperados en Rust, pero
# no pueden ver el header de C. Sin esta comprobacion, un cambio en
# shared/include/aegis_abi.h que rustc no conoce se manifestaria como campos
# desplazados en produccion: el agente leeria un PID donde hay una direccion.
# Aqui se convierte en un fallo de build.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

CC="${CC:-cc}"
echo "==> Sonda C   ($CC)"
"$CC" -std=c11 -Wall -Wextra -Werror -Ishared/include \
      -o "$OUT/abi_probe_c" tools/abi_probe.c
"$OUT/abi_probe_c" > "$OUT/c.txt"

echo "==> Sonda Rust (cargo)"
cargo run --quiet -p aegis-ipc --example abi_probe > "$OUT/rust.txt"

echo "==> Comparando layouts"
if diff -u "$OUT/c.txt" "$OUT/rust.txt" > "$OUT/diff.txt"; then
    echo "OK: $(wc -l < "$OUT/c.txt") entradas de layout coinciden entre C y Rust."
else
    echo "FALLO: el ABI de C y el de Rust han divergido." >&2
    echo "  '-' = lo que dice shared/include/aegis_abi.h" >&2
    echo "  '+' = lo que dice crates/aegis-ipc/src/abi.rs" >&2
    cat "$OUT/diff.txt" >&2
    exit 1
fi
