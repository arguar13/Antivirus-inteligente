#!/usr/bin/env bash
#
# Auditoria de vulnerabilidades de dependencias (FASE 35).
#
# Cada crate de terceros es superficie de ataque en un EDR: si se compromete un
# crate que acaba dentro del agente, se compromete el propio producto. Este
# script cruza el arbol de dependencias contra la base de avisos de RustSec.
# La politica y los avisos aceptados —con justificacion y via de remediacion—
# viven en .cargo/audit.toml.
#
# Uso:  tools/audit.sh
#
# Codigo de salida 0 si no hay vulnerabilidades sin triar; 1 si aparece una
# nueva; se OMITE (0) si falta cargo-audit.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'

if ! cargo audit --version >/dev/null 2>&1; then
    printf '%s== Auditoria OMITIDA: falta cargo-audit (cargo install cargo-audit) ==%s\n' "$GRIS" "$FIN"
    exit 0
fi

printf '%s== Auditoria de dependencias contra RustSec ==%s\n' "$NEGRITA" "$FIN"

# --no-yanked: la comprobacion de crates "retirados" consulta el registro, que
# el proxy del entorno de integracion bloquea (503). La cadena de suministro por
# version retirada ya la cubre deny.toml (yanked = "deny"); aqui interesa la
# base de vulnerabilidades.
if cargo audit --no-yanked > /tmp/aegis-audit.log 2>&1; then
    grep -E "Scanning|crate dependencies" /tmp/aegis-audit.log | sed 's/^/    | /'
    printf '    %sOK%s  sin vulnerabilidades sin triar\n' "$VERDE" "$FIN"
    # Dejar constancia de cuantos avisos hay aceptados y documentados.
    aceptados=$(grep -cE '"RUSTSEC-' .cargo/audit.toml 2>/dev/null || echo 0)
    printf '    %s(%s aviso(s) transitivos aceptados y documentados en .cargo/audit.toml)%s\n' \
        "$GRIS" "$aceptados" "$FIN"
    exit 0
else
    printf '    %sFALLO%s  hay una vulnerabilidad sin triar\n' "$ROJO" "$FIN"
    grep -E "Crate:|Title:|ID:|Severity:|vulnerabilities found" /tmp/aegis-audit.log \
        | grep -vi yanked | head -30 | sed 's/^/      | /'
    printf '    %sTriala: corrige actualizando la dependencia, o documenta la\n' "$GRIS"
    printf '    aceptacion en .cargo/audit.toml con su justificacion.%s\n' "$FIN"
    exit 1
fi
