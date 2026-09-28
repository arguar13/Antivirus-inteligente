#!/usr/bin/env bash
#
# Verificacion de AegisReal (la escala, MEDIDA de verdad, FASE 111).
#
# CONTRA QUIEN COMPITE: Wazuh y Elastic en produccion. No se gana declarando: se
# gana MIDIENDO lo mismo que ellos, con la MISMA base de datos real, y publicando
# el numero.
#
# QUE SE MIDE AQUI, CONTRA POSTGRESQL REAL (no simulado en memoria):
#  - PERDIDA CERO, contada en los DOS extremos: lo que el simulador envio, lo que
#    la base guarda (count de alertas) y el contador propio del servidor (sum de
#    eventos). Los tres cuadran, o hay perdida y se ve.
#  - LATENCIA de ingesta p50/p95/p99, publicada.
#  - AISLAMIENTO por inquilino: el conteo de una flota no incluye a la otra.
#  - PURGA como la FASE 75: DETACH+DROP de una particion frente a un DELETE, para
#    demostrar que la purga es metadato y no un barrido que bloquee la ingesta.
#
# EL MURO: cien mil conexiones mTLS vivas y discos de produccion no caben en esta
# maquina; el benchmark en memoria de `fleet-simulator/src/bin/escala.rs` cubre el
# reparto y la manada a esa escala, y aqui se mide lo que SI se puede medir de
# verdad contra la base. Sin PostgreSQL, se OMITE con honestidad, no se finge.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

: "${AEGIS_TEST_PG_URL:=postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test}"
export AEGIS_TEST_PG_URL

echo "==> AegisReal: medida de escala contra PostgreSQL REAL (perdida, latencia, purga)"
LOG=/tmp/aegis-escala-real.log
if (cd server && cargo test -p aegis-server --test escala_real -- --nocapture) >"$LOG" 2>&1; then
    if grep -q "OMITIDA: no hay PostgreSQL" "$LOG"; then
        echo "    ${GRIS}OMITIDA${FIN}: no hay PostgreSQL en esta maquina."
        echo "    ${GRIS}  ${FIN} La medida real se declara; arranca PostgreSQL (pg_ctlcluster) para ejercerla."
    else
        echo "    ${VERDE}OK${FIN} (perdida CERO contada en los dos extremos contra la base real;"
        echo "    ${VERDE}  ${FIN} aislamiento por inquilino comprobado; y la purga de la FASE 75 es"
        echo "    ${VERDE}  ${FIN} metadato —DETACH+DROP—, no un barrido que bloquee la ingesta)"
        grep -E "ingesta real|purga FASE 75" "$LOG" | sed 's/^/    | /'
    fi
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' "$LOG" | tail -30; exit 1
fi
exit 0
