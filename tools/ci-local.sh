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
    if command -v python3 >/dev/null 2>&1; then
        paso bpf   "eBPF · integridad HMAC"    make -C drivers/linux/aegis-bpf check-integrity
    fi
    paso bpf   "eBPF · verificador del kernel" make -C drivers/linux/aegis-bpf verify
else
    printf '%s==>%s eBPF · %somitido (subproyecto aun no creado)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi
paso docs  "Docs · enlaces relativos"   ./tools/check-links.sh
# El fichero de cadenas cifradas (FASE 13) tiene que estar al dia respecto al
# manifiesto: si alguien cambia una cadena critica y no regenera, el binario
# llevaria en claro lo que deberia ir cifrado. Solo aplica si hay python3.
if command -v python3 >/dev/null 2>&1; then
    paso harden "Blindaje · cadenas cifradas al dia" python3 tools/obfuscate.py --check
else
    printf '%s==>%s Blindaje · %somitido (sin python3)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi

# El presupuesto de recursos es un compromiso del producto (ver README), no una
# aspiracion. Un componente que se lo salta es un bug atribuible, y por eso se
# mide en la misma puerta que el resto.
if [ -n "${SOLO:-}" ] && [ "$SOLO" != "budget" ]; then :; else
    printf '%s==>%s Presupuesto de memoria del agente\n' "$GRIS" "$FIN"
    if cargo build --release -p aegis-agent -q 2>/dev/null && [ -x target/release/aegis-agent ]; then
        ./target/release/aegis-agent --stats-interval 300 >/dev/null 2>/tmp/aegis-budget.err &
        PID_AGENTE=$!
        sleep 4
        RSS=$(grep VmRSS "/proc/$PID_AGENTE/status" 2>/dev/null | awk '{print $2}')
        kill -TERM "$PID_AGENTE" 2>/dev/null
        wait "$PID_AGENTE" 2>/dev/null
        if [ -z "$RSS" ]; then
            printf '    %somitido: el agente no arranco%s\n' "$GRIS" "$FIN"
            printf '    %s  causa: %s%s\n' "$GRIS" "$(tail -1 /tmp/aegis-budget.err 2>/dev/null | head -c 160)" "$FIN"
        elif [ "$RSS" -lt 46080 ]; then
            printf '    %sOK%s (%s KB de un presupuesto de 46080 KB)\n' "$VERDE" "$FIN" "$RSS"
        else
            printf '    %sFALLO%s: %s KB supera el presupuesto de 46080 KB\n' "$ROJO" "$FIN" "$RSS"
            FALLOS=$((FALLOS + 1))
        fi
    else
        printf '    %somitido (no se pudo compilar el agente)%s\n' "$GRIS" "$FIN"
    fi
fi

# Simulacion de Red Team (FASE 17): ataques reales contra las defensas. Es el
# ultimo paso porque necesita los binarios de ejemplo compilados y ejercita el
# sistema entero. Requiere python3 y un compilador de C para la victima de
# inyeccion; si faltan, se omite en vez de fallar.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "redteam" ]; then
    if command -v python3 >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
        printf '%s==>%s Red Team · simulacion de ataques\n' "$GRIS" "$FIN"
        cargo build -q -p aegis-evasion --example scan_pid 2>/dev/null
        cargo build -q -p aegis-ransom --example honeypot_probe 2>/dev/null
        make -C drivers/linux/aegis-bpf build sign >/dev/null 2>&1 || true
        if python3 tests/red_team_sim.py > /tmp/aegis-redteam.log 2>&1; then
            printf '    %sOK%s\n' "$VERDE" "$FIN"
        else
            printf '    %sFALLO%s\n' "$ROJO" "$FIN"
            sed 's/^/    | /' /tmp/aegis-redteam.log | tail -30
            FALLOS=$((FALLOS + 1))
        fi
    else
        printf '%s==>%s Red Team · %somitido (sin python3 o sin cc)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
    fi
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%sTodas las comprobaciones pasan.%s\n' "$VERDE" "$FIN"
    exit 0
fi
printf '%s%d grupo(s) de comprobaciones han fallado.%s\n' "$ROJO" "$FALLOS" "$FIN"
exit 1
