#!/usr/bin/env bash
#
# Flota viva (H-23, E6.5 del MP-16): el agente PUBLICADO se enrola y reporta al
# plano de control REAL.
#
# QUE SE EJERCE, SIN DOBLES
#  - el binario aegis-server contra PostgreSQL y Redis reales, con la CA de flota
#    provisionada en disco;
#  - el enlace del agente (crates/aegis-agent/src/plano.rs): configuracion por
#    fichero, certificado y clave en disco, y el cliente mTLS de aegis-fleet;
#  - un veredicto sintetico que tiene que quedar en `alertas` con el CN del
#    certificado; un SIGKILL al servidor durante el que la cola guarda lo que
#    llega; y la reconciliacion al volver, con la cuenta del enlace cuadrada y el
#    estado de los motores en el inventario.
#
# Sin servidor, PostgreSQL, Redis o psql, la prueba se OMITE y lo dice por
# aegis_prueba; make ci exige los servicios (AEGIS_EXIGIR=servicios) y ahi la
# omision es un FALLO: una puerta de servicio que no se ejercio no es un verde.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

: "${AEGIS_TEST_PG_URL:=postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test}"
: "${AEGIS_TEST_REDIS_URL:=redis://127.0.0.1:6379}"
export AEGIS_TEST_PG_URL AEGIS_TEST_REDIS_URL

# Salida privada de esta ejecucion: nada de rutas fijas en /tmp (ver el porque
# en tools/ci-local.sh).
LOG="$(mktemp -t aegis-flota-viva-XXXXXXXX)" || exit 1
trap 'rm -f "$LOG"' EXIT

echo "==> Flota viva: se compila aegis-server (workspace server/)"
if ! (cd server && cargo build --locked -q -p aegis-server) >"$LOG" 2>&1; then
    echo "    ${ROJO}FALLO${FIN}: aegis-server no compila"
    sed 's/^/    | /' "$LOG" | tail -30
    exit 1
fi
# El binario recien compilado, y no uno que hubiera por ahi: probar contra un
# servidor viejo seria dar por bueno un arbol que no es este.
DESTINO=$(cd server && cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
AEGIS_SERVER_BIN="$DESTINO/debug/aegis-server"
if [ ! -x "$AEGIS_SERVER_BIN" ]; then
    echo "    ${ROJO}FALLO${FIN}: no esta $AEGIS_SERVER_BIN despues de compilarlo"
    exit 1
fi
export AEGIS_SERVER_BIN

echo "==> Flota viva: agente -> plano de control real (mTLS nativo, PostgreSQL)"
if ! cargo test -q -p aegis-agent --test plano_control_vivo -- --ignored --nocapture \
        >"$LOG" 2>&1; then
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' "$LOG" | tail -40
    exit 1
fi
if grep -q "OMITIDA:" "$LOG"; then
    echo "    ${GRIS}OMITIDA${FIN}: $(grep -m1 'OMITIDA:' "$LOG" | sed 's/.*OMITIDA: //')"
    echo "    ${GRIS}  ${FIN} Arranca PostgreSQL y Redis para ejercerla; make ci los exige"
    echo "    ${GRIS}  ${FIN} (AEGIS_EXIGIR=servicios) y ahi omitir es fallar."
else
    echo "    ${VERDE}OK${FIN} (veredicto en PostgreSQL con el CN del certificado; SIGKILL al"
    echo "    ${VERDE}  ${FIN} servidor y reconciliacion sin perdida; estado de motores en el"
    echo "    ${VERDE}  ${FIN} inventario; cuenta del enlace cuadrada)"
    grep -E "^AEGIS-MEDIDA" "$LOG" | sed 's/^/    | /'
fi
exit 0
