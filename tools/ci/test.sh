#!/usr/bin/env bash
#
# Job de CI: pruebas del workspace.
#
# Las pruebas que necesitan kernel (eBPF, ptrace privilegiado) se saltan solas
# si el entorno no las permite; el resto corre siempre. `--locked` garantiza que
# el Cargo.lock versionado es el que se usa: una dependencia que cambia sola
# entre CI y produccion es una via de compromiso de la cadena de suministro.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: test (workspace)"
FALLOS=0

correr "cargo test --workspace --locked" cargo test --workspace --locked || FALLOS=$((FALLOS+1))

# Cotejo del ABI entre C y Rust con los dos compiladores: el driver se compila
# con clang en Linux y con MSVC en Windows; si el layout dependiera del
# compilador, el ABI no seria un contrato.
for cc in gcc clang; do
    if hay "$cc"; then
        correr "ABI C<->Rust ($cc)" env CC="$cc" ./tools/abi-check.sh || FALLOS=$((FALLOS+1))
    else
        paso "ABI C<->Rust ($cc)"; omitido "no hay $cc en esta maquina"
    fi
done

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
