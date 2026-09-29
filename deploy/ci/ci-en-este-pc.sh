#!/usr/bin/env bash
#
# El CI remoto cuando la forja y el runner viven en el PC de desarrollo (WSL).
#
#   deploy/ci/ci-en-este-pc.sh            empuja HEAD a la forja y espera el veredicto
#   deploy/ci/ci-en-este-pc.sh --estado   solo dice como va la ultima ejecucion
#
# POR QUE HACE FALTA Y NO BASTA CON DEJAR LOS SERVICIOS ARRANCADOS
#
# WSL apaga la distribucion cuando no queda ninguna terminal conectada: a los
# pocos segundos detiene systemd y con el la forja y el runner, aunque la maquina
# virtual siga en pie. Una ejecucion del CI de dos horas moria a mitad (visto dos
# veces en la FASE 0 del MP-15). Mantener la distribucion encendida para siempre
# resolveria eso a costa de tener la memoria ocupada todo el dia.
#
# Este script es el termino medio correcto: levanta la forja y el runner, empuja,
# se QUEDA conectado mientras corre la tarea —eso mantiene viva la distribucion—,
# dice el veredicto y apaga los dos servicios al terminar. En una maquina dedicada
# (docs/ci-remoto.md) no hace falta: alli los servicios corren siempre.
#
# Necesita root (se lanza como `wsl -d Ubuntu -u root -- deploy/ci/ci-en-este-pc.sh`)
# y la forja y el runner instalados (deploy/ci/forja-local.sh, instalar-runner.sh).
set -uo pipefail
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
URL="http://localhost:${AEGIS_FORJA_PUERTO:-3000}"
SECRETOS=/root/.aegis-forja
API="$URL/api/v1/repos/aegis/aegiscore"

[ "$(id -u)" -eq 0 ] || { echo "hace falta root" >&2; exit 1; }
[ -r "$SECRETOS" ] || { echo "no hay forja: deploy/ci/forja-local.sh" >&2; exit 1; }
TOKEN="$(grep '^token=' "$SECRETOS" | cut -d= -f2)"

api() { curl -fsS -H "Authorization: token $TOKEN" "$API/$1"; }

ultima_ejecucion() {
    # id estado sha de la ejecucion mas reciente, o de la de un sha concreto.
    api "actions/tasks?limit=20" | python3 -c '
import json, sys
sha = sys.argv[1] if len(sys.argv) > 1 else ""
for t in json.load(sys.stdin)["workflow_runs"]:
    if not sha or t["head_sha"].startswith(sha):
        print(t["id"], t["status"], t["head_sha"][:7]); break' "$@"
}

levantar() {
    systemctl start forgejo
    for _ in $(seq 1 30); do curl -fs "$URL/api/healthz" > /dev/null 2>&1 && break; sleep 1; done
    systemctl start forgejo-runner
}

apagar() {
    # La preferencia del proyecto: lo que no se usa, no ocupa memoria.
    systemctl stop forgejo-runner forgejo
}

if [ "${1:-}" = "--estado" ]; then
    levantar
    ultima_ejecucion
    apagar
    exit 0
fi

trap apagar EXIT
levantar

sha="$(git -C "$RAIZ" rev-parse HEAD)"
echo "==> empujando ${sha:0:7} a la forja"
git -C "$RAIZ" -c http.extraHeader="Authorization: token $TOKEN" \
    push -q "$URL/aegis/aegiscore.git" HEAD:main || exit 1

echo "==> esperando a que el runner la recoja"
for _ in $(seq 1 60); do
    linea="$(ultima_ejecucion "${sha:0:7}")"
    [ -n "$linea" ] && break
    sleep 5
done
[ -n "${linea:-}" ] || { echo "la forja no creo ninguna ejecucion para ${sha:0:7}" >&2; exit 1; }
id="${linea%% *}"
echo "    ejecucion $id"

inicio=$(date +%s)
while :; do
    estado="$(ultima_ejecucion "${sha:0:7}" | awk '{print $2}')"
    case "$estado" in
        success) echo "==> VERDE: make ci pasa en el runner ($(( ($(date +%s) - inicio) / 60 )) min)"; exit 0 ;;
        failure|cancelled|skipped)
            echo "==> $estado tras $(( ($(date +%s) - inicio) / 60 )) min. Ultimas lineas del registro:"
            log="$(ls /var/lib/forgejo/data/actions_log/aegis/aegiscore/*/"$id".log.zst 2>/dev/null | head -1)"
            [ -n "$log" ] && zstd -dc "$log" 2>/dev/null | tail -40
            exit 1 ;;
    esac
    # Que se esta ejecutando, para que una espera larga no parezca un cuelgue.
    grupo="$(ps -eo args | grep -oE 'verificar-[a-z0-9-]+\.sh|cargo (test|clippy|build) [^ ]* ?-p [a-z0-9-]+|qemu-system-[a-z0-9_]+' | head -1)"
    printf '    %s  %s min  %s\n' "$(date +%H:%M)" "$(( ($(date +%s) - inicio) / 60 ))" "${grupo:-...}"
    sleep 120
done
