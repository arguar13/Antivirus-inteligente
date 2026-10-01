#!/usr/bin/env bash
#
# Job de CI: el plano de control (workspace `server/`).
#
# Es un workspace SEPARADO del agente —asincrono, con tokio, axum, tonic y
# pools de conexiones— asi que necesita su propia pasada de formato, lints,
# compilacion y pruebas.
#
# Las pruebas de integracion hablan con PostgreSQL y Redis REALES, y aqui se
# EXIGEN (AEGIS_EXIGIR=servicios; hallazgos H-10/H-20): una prueba a la que le
# falten FALLA diciendo como obtenerlos. En CI los aporta el propio workflow con
# servicios de contenedor.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ/server"

titulo "Job: servidor (plano de control)"
FALLOS=0

correr "cargo fmt --all --check"           cargo fmt --all -- --check || FALLOS=$((FALLOS+1))
correr "clippy (depuracion, -D warnings)"  cargo clippy --all-targets -- -D warnings || FALLOS=$((FALLOS+1))
correr "clippy (release, -D warnings)"     cargo clippy --release --workspace --all-targets -- -D warnings || FALLOS=$((FALLOS+1))

# Antes, sin bases de datos, las pruebas de integracion se saltaban solas con un
# aviso que cargo capturaba: el job salia verde sin haberlas ejecutado. Ahora
# los servicios se EXIGEN, y las omisiones que si se admiten (datos o medidas
# bajo demanda) se anotan en AEGIS_OMISIONES y se cuentan al final.
export AEGIS_EXIGIR="${AEGIS_EXIGIR-servicios}"
AEGIS_OMISIONES="$(mktemp)"
export AEGIS_OMISIONES
trap 'rm -f "$AEGIS_OMISIONES" "$AEGIS_OMISIONES.log"' EXIT

correr "PostgreSQL y Redis de las pruebas" "$RAIZ/tools/ci/servicios.sh" --comprobar \
    || FALLOS=$((FALLOS+1))

correr "cargo test --locked" cargo test --locked || FALLOS=$((FALLOS+1))

# El recuento, siempre a la vista: una omision no declarada en
# tools/config/omisiones.toml hace fallar el job.
paso "Omisiones de las pruebas"
if python3 "$RAIZ/tools/ci/omisiones.py" "$AEGIS_OMISIONES" --exigir-declaradas \
        > "$AEGIS_OMISIONES.log" 2>&1; then
    sed 's/^/      | /' "$AEGIS_OMISIONES.log"
    ok
else
    sed 's/^/      | /' "$AEGIS_OMISIONES.log"
    fallo "omisiones sin declarar o configuracion incoherente"
    FALLOS=$((FALLOS+1))
fi

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
