#!/usr/bin/env bash
#
# Job de CI: cadena de suministro.
#
# Dos comprobaciones complementarias sobre las dependencias de terceros, que en
# un EDR son superficie de ataque directa:
#   - cargo-deny : licencias permitidas, fuentes conocidas, versiones duplicadas.
#   - cargo-audit: avisos de vulnerabilidad de RustSec (politica en
#                  .cargo/audit.toml).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: supply-chain (dependencias de terceros)"
FALLOS=0

if hay cargo-deny; then
    correr "cargo deny check" cargo deny check || FALLOS=$((FALLOS+1))
else
    paso "cargo deny check"; omitido "falta cargo-deny (cargo install cargo-deny)"
fi

# La auditoria tiene su propio script porque tambien la usa el pipeline
# DevSecOps nocturno.
if hay cargo-audit; then
    ./tools/audit.sh || FALLOS=$((FALLOS+1))
else
    paso "cargo audit"; omitido "falta cargo-audit (cargo install cargo-audit)"
fi

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
