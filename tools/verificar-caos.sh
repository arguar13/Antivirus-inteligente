#!/usr/bin/env bash
#
# Caos del plano de control con procesos reales (E6.17, FASE 6.4 del MP-16).
# Invariante 7 extendida: ninguna caida de una dependencia del plano de control
# produce perdida silenciosa.
#
# Lanza, EN SERIE, los escenarios de server/crates/aegis-server/tests/caos.rs:
#   1. PostgreSQL cae (pg_ctl stop -m immediate) y vuelve: contrapresion, el
#      servidor se recupera solo (y su LISTEN), cero perdidos.
#   2. Redis cae y vuelve: la ingesta sigue, las sesiones caducan de forma
#      controlada (401) y una sesion nueva funciona.
#   3. El certificado de un agente caduca: rechazo en el handshake, nada se
#      pierde, y tras renovar llega todo.
#   4. El certificado del servidor vence en mitad: lo renueva solo (H-39).
#   5. Reloj del agente a +-10 min (libfaketime en otro proceso).
#   6. El SIEM muere (kill -9) y se ahoga (SIGSTOP): la salida se reconcilia.
#
# Cada escenario levanta su PostgreSQL (initdb en un temporal) y su Redis: el
# PostgreSQL del CI no se toca. Como root, los binarios de PostgreSQL corren
# como el usuario `postgres` (runuser).
#
# Variables:
#   AEGIS_CAOS_CORTE_SEG   segundos de PostgreSQL caido (20; el PLAN pide 60)
#   AEGIS_CAOS_SIEM_SEG    segundos de colector muerto (15; el PLAN pide 300)
#   AEGIS_PG_BIN           directorio de initdb/pg_ctl (si no, el mas nuevo de
#                          /usr/lib/postgresql/*/bin)
#   AEGIS_LIBFAKETIME      ruta de libfaketime.so.1
#
# Sin PostgreSQL, Redis o libfaketime el escenario FALLA: el grupo exige
# `servicios,programa` (aegis_prueba). Para omitir en local:
#   AEGIS_EXIGIR= tools/verificar-caos.sh
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

export AEGIS_EXIGIR="${AEGIS_EXIGIR-servicios,programa}"

# Disco: cada escenario crea un cluster de PostgreSQL de ~40 MiB en el temporal
# y lo borra al terminar. Se exige un margen holgado (regla «cuidar el disco»).
LIBRE_MB=$(df -Pm "${TMPDIR:-/tmp}" | awk 'NR==2 {print $4}')
if [ "${LIBRE_MB:-0}" -lt 2048 ]; then
    printf '%sFALLO%s: menos de 2 GiB libres en %s\n' "$ROJO" "$FIN" "${TMPDIR:-/tmp}"
    exit 1
fi

cd server
if cargo test --locked -p aegis-server --test caos -- --ignored --test-threads=1 --nocapture \
    caos_; then
    printf '%sCaos del plano de control: ninguna caida produjo perdida silenciosa.%s\n' "$VERDE" "$FIN"
    exit 0
fi
printf '%sCaos del plano de control: FALLO (ver arriba el escenario y su cuenta).%s\n' "$ROJO" "$FIN"
exit 1
