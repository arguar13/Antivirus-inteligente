#!/usr/bin/env bash
#
# Job de CI: el plano de control (workspace `server/`).
#
# Es un workspace SEPARADO del agente —asincrono, con tokio, axum, tonic y
# pools de conexiones— asi que necesita su propia pasada de formato, lints,
# compilacion y pruebas.
#
# Las pruebas de integracion hablan con PostgreSQL y Redis REALES. Donde no los
# haya, cada prueba se OMITE diciendolo (no finge exito); en CI los aporta el
# propio workflow con servicios de contenedor.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ/server"

titulo "Job: servidor (plano de control)"
FALLOS=0

correr "cargo fmt --all --check"           cargo fmt --all -- --check || FALLOS=$((FALLOS+1))
correr "clippy (depuracion, -D warnings)"  cargo clippy --all-targets -- -D warnings || FALLOS=$((FALLOS+1))
correr "clippy (release, -D warnings)"     cargo clippy --release --workspace --all-targets -- -D warnings || FALLOS=$((FALLOS+1))

# Aviso honesto: sin bases de datos, las pruebas de integracion se saltan solas
# y lo que queda es mucho menos garantia.
if command -v pg_isready >/dev/null 2>&1 && pg_isready -q 2>/dev/null; then
    paso "PostgreSQL"; ok "disponible"
else
    paso "PostgreSQL"; omitido "sin base de datos, las pruebas de integracion se saltan"
fi
if command -v redis-cli >/dev/null 2>&1 && [ "$(redis-cli ping 2>/dev/null)" = "PONG" ]; then
    paso "Redis"; ok "disponible"
else
    paso "Redis"; omitido "sin cache, las pruebas de esa parte se saltan"
fi

correr "cargo test --locked" cargo test --locked || FALLOS=$((FALLOS+1))

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
