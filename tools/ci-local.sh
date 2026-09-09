#!/usr/bin/env bash
#
# Ejecuta localmente EXACTAMENTE las mismas comprobaciones que .github/workflows/ci.yml.
#
# Existe por una razon concreta: GitHub Actions esta bloqueado a nivel de
# repositorio o cuenta en este proyecto (ver docs/07-estado-ci.md), asi que el
# pipeline remoto no corre. Las comprobaciones no dejan de ser obligatorias por
# eso: se ejecutan aqui, y este script es la referencia normativa mientras el
# CI remoto no arranque.
#
# Uso:  ./tools/ci-local.sh          (todo)
#       ./tools/ci-local.sh rust     (solo un grupo)
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0
SOLO="${1:-}"

paso() {
    local grupo="$1"; shift
    local titulo="$1"; shift
    if [ -n "$SOLO" ] && [ "$SOLO" != "$grupo" ]; then return 0; fi
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$titulo"
    if "$@" > /tmp/ci-local.log 2>&1; then
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/ci-local.log | tail -40
        FALLOS=$((FALLOS + 1))
    fi
}

paso rust  "Rust · formato"            cargo fmt --all --check
paso rust  "Rust · clippy (-D warnings)" cargo clippy --all-targets -- -D warnings
paso rust  "Rust · tests"               cargo test --all
paso abi   "ABI · layout C vs Rust (gcc)"   env CC=gcc   ./tools/abi-check.sh
paso abi   "ABI · layout C vs Rust (clang)" env CC=clang ./tools/abi-check.sh
# Los pasos de eBPF solo aplican en Linux y solo si el subproyecto existe ya.
# Un grupo que no aplica se omite explicitamente en vez de fallar: un CI que
# falla por algo que no es un defecto ensena a la gente a ignorar el CI.
if [ -f drivers/linux/aegis-bpf/Makefile ]; then
    paso bpf   "eBPF · compilacion"            make -C drivers/linux/aegis-bpf build
    paso bpf   "eBPF · verificador del kernel" make -C drivers/linux/aegis-bpf verify
else
    printf '%s==>%s eBPF · %somitido (subproyecto aun no creado)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi
paso docs  "Docs · enlaces relativos"   ./tools/check-links.sh

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%sTodas las comprobaciones pasan.%s\n' "$VERDE" "$FIN"
    exit 0
fi
printf '%s%d grupo(s) de comprobaciones han fallado.%s\n' "$ROJO" "$FALLOS" "$FIN"
exit 1
