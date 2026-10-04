#!/usr/bin/env bash
#
# Los servicios de las pruebas de integracion del plano de control: PostgreSQL
# y Redis, mirados con las MISMAS URL que usan las pruebas (AEGIS_TEST_PG_URL y
# AEGIS_TEST_REDIS_URL, con los mismos valores por defecto).
#
# POR QUE (hallazgos H-10 y H-20)
#
# Sin ellos, las pruebas se omitian solas con un aviso que cargo se tragaba, y
# el workflow los arrancaba con `|| true`: si no arrancaban, nadie se enteraba y
# la tanda salia verde con cuarenta pruebas sin ejecutar. Ahora `make ci` los
# EXIGE (AEGIS_EXIGIR=servicios) y este script es el que dice, en una linea y
# antes que las pruebas, cual falta y que hacer.
#
# Uso:
#   tools/ci/servicios.sh --comprobar
#       Responden? Si no, dice cual falta y como arrancarlo, y sale 1. Si
#       AEGIS_EXIGIR no exige alguno, lo dice y no lo cuenta como fallo: sus
#       pruebas se omitiran, y la tanda las contara.
#   tools/ci/servicios.sh --arrancar
#       (runner de CI o WSL, como root) Arranca el primer cluster de PostgreSQL
#       y un redis-server si no responden, crea la base de pruebas si falta,
#       espera a que respondan y comprueba. Nada de `|| true`: si algo no
#       arranca, sale 1 diciendolo.
set -uo pipefail

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'

PG_URL="${AEGIS_TEST_PG_URL:-postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test}"
REDIS_URL="${AEGIS_TEST_REDIS_URL:-redis://127.0.0.1:6379}"
# Ni psql ni redis-cli pueden quedarse esperando: un servicio que no contesta
# es un fallo con nombre, no un cuelgue.
export PGCONNECT_TIMEOUT=5

pg_responde() {
    psql -X -w -t -A -c 'SELECT 1' "$PG_URL" 2>/dev/null | grep >/dev/null -x 1
}

redis_responde() {
    [ "$(timeout 5 redis-cli -u "$REDIS_URL" ping 2>/dev/null)" = "PONG" ]
}

# Si AEGIS_EXIGIR exige el servicio $1 (por su clave, por la clase o por `todo`).
exige() {
    local t
    for t in $(printf '%s' "${AEGIS_EXIGIR:-}" | tr ',' ' '); do
        case "$t" in
            todo|servicios|"$1") return 0 ;;
        esac
    done
    return 1
}

comprobar() {
    local malos=0
    if ! exige postgresql; then
        printf '%sno se exige%s PostgreSQL (AEGIS_EXIGIR=%s): sus pruebas se omitiran y se contaran\n' \
            "$GRIS" "$FIN" "${AEGIS_EXIGIR:-}"
    elif ! command -v psql >/dev/null 2>&1; then
        printf '%sFALTA%s psql, el cliente de PostgreSQL, para comprobar %s\n' "$ROJO" "$FIN" "$PG_URL"
        malos=$((malos + 1))
    elif pg_responde; then
        printf '%sOK%s PostgreSQL responde en %s\n' "$VERDE" "$FIN" "$PG_URL"
    else
        printf '%sFALTA%s PostgreSQL no responde en %s\n' "$ROJO" "$FIN" "$PG_URL"
        psql -X -w -t -A -c 'SELECT 1' "$PG_URL" 2>&1 | head -5 | sed 's/^/    | /'
        printf '    Arrancalo y crea la base (como root): tools/ci/servicios.sh --arrancar\n'
        printf '    o apunta AEGIS_TEST_PG_URL a uno que responda. Si arranca y aun asi no\n'
        printf '    conecta, mira pg_hba.conf: el usuario de la URL tiene que poder entrar.\n'
        malos=$((malos + 1))
    fi

    if ! exige redis; then
        printf '%sno se exige%s Redis (AEGIS_EXIGIR=%s): sus pruebas se omitiran y se contaran\n' \
            "$GRIS" "$FIN" "${AEGIS_EXIGIR:-}"
    elif ! command -v redis-cli >/dev/null 2>&1; then
        printf '%sFALTA%s redis-cli para comprobar %s\n' "$ROJO" "$FIN" "$REDIS_URL"
        malos=$((malos + 1))
    elif redis_responde; then
        printf '%sOK%s Redis responde en %s\n' "$VERDE" "$FIN" "$REDIS_URL"
    else
        printf '%sFALTA%s Redis no responde en %s\n' "$ROJO" "$FIN" "$REDIS_URL"
        printf '    Arrancalo (como root): tools/ci/servicios.sh --arrancar\n'
        printf '    o apunta AEGIS_TEST_REDIS_URL a uno que responda.\n'
        malos=$((malos + 1))
    fi
    [ "$malos" -eq 0 ]
}

arrancar_postgresql() {
    pg_responde && return 0
    if ! command -v pg_lsclusters >/dev/null 2>&1; then
        printf '%sFALTA%s PostgreSQL (no hay pg_lsclusters): deploy/ci/instalar-runner.sh lo instala\n' \
            "$ROJO" "$FIN"
        return 1
    fi
    local version nombre puerto estado
    read -r version nombre puerto estado _ < <(pg_lsclusters -h | head -1)
    if [ -z "${version:-}" ]; then
        printf '%sFALTA%s ningun cluster de PostgreSQL (pg_lsclusters no lista ninguno):\n' "$ROJO" "$FIN"
        printf '    crealo con pg_createcluster <version> main\n'
        return 1
    fi
    if [ "$estado" != "online" ]; then
        printf '==> arrancando PostgreSQL %s/%s (puerto %s)\n' "$version" "$nombre" "$puerto"
        if ! pg_ctlcluster --skip-systemctl-redirect "$version" "$nombre" start; then
            printf '%sFALLO%s PostgreSQL %s/%s no arranca; su registro:\n' "$ROJO" "$FIN" "$version" "$nombre"
            tail -20 "/var/log/postgresql/postgresql-$version-$nombre.log" 2>/dev/null | sed 's/^/    | /'
            return 1
        fi
    fi
    # La base de las pruebas, si falta. El nombre sale de la propia URL.
    local base="${PG_URL##*/}"
    base="${base%%\?*}"
    if [ -n "$base" ]; then
        if ! runuser -u postgres -- psql -X -p "$puerto" -t -A \
                -c "SELECT 1 FROM pg_database WHERE datname = '$base'" | grep >/dev/null -x 1; then
            printf '==> creando la base de pruebas %s\n' "$base"
            if ! runuser -u postgres -- createdb -p "$puerto" "$base"; then
                printf '%sFALLO%s no se pudo crear la base %s\n' "$ROJO" "$FIN" "$base"
                return 1
            fi
        fi
    fi
}

arrancar_redis() {
    redis_responde && return 0
    if ! command -v redis-server >/dev/null 2>&1; then
        printf '%sFALTA%s redis-server: deploy/ci/instalar-runner.sh lo instala\n' "$ROJO" "$FIN"
        return 1
    fi
    printf '==> arrancando redis-server\n'
    if ! redis-server --daemonize yes; then
        printf '%sFALLO%s redis-server no arranca\n' "$ROJO" "$FIN"
        return 1
    fi
}

arrancar() {
    if ! { pg_responde && redis_responde; } && [ "$(id -u)" -ne 0 ]; then
        printf '%sFALLO%s --arrancar necesita root (arranca el cluster y crea la base como postgres)\n' \
            "$ROJO" "$FIN"
        return 1
    fi
    arrancar_postgresql || return 1
    arrancar_redis || return 1
    # Arrancados no es lo mismo que respondiendo: se espera, con plazo.
    local i
    for i in $(seq 1 30); do
        pg_responde && redis_responde && break
        sleep 1
    done
    AEGIS_EXIGIR=servicios comprobar
}

case "${1:-}" in
    --comprobar) comprobar ;;
    --arrancar) arrancar ;;
    *)
        printf 'uso: %s --comprobar | --arrancar\n' "$0" >&2
        exit 2
        ;;
esac
