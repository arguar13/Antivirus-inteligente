#!/usr/bin/env bash
#
# Levanta una forja Forgejo con Actions activado, lista para el CI de AegisCore.
#
#   sudo deploy/ci/forja-local.sh            instala y arranca en 127.0.0.1:3000
#   sudo deploy/ci/forja-local.sh --token    imprime un token de registro de runner
#
# Sirve para dos cosas: evaluar el CI en una sola maquina (forja + runner juntos)
# y como receta de la forja de produccion, que en ese caso va en su propia
# maquina detras de TLS. Deja las credenciales del administrador en
# /root/.aegis-forja (0600): nunca en el repositorio ni en la salida.
set -euo pipefail

VERSION="16.0.5"
PUERTO="${AEGIS_FORJA_PUERTO:-3000}"
URL="http://localhost:$PUERTO"
DATOS="/var/lib/forgejo"
CONF="/etc/forgejo/app.ini"
SECRETOS="/root/.aegis-forja"

[ "$(id -u)" -eq 0 ] || { echo "hace falta root" >&2; exit 1; }

forgejo_cli() { runuser -u forgejo -- forgejo --config "$CONF" --work-path "$DATOS" "$@"; }

if [ "${1:-}" = "--token" ]; then
    forgejo_cli actions generate-runner-token
    exit 0
fi

echo "==> forgejo $VERSION (verificado por suma)"
# `forgejo --version` dice «Forgejo version 16.0.5+gitea-...»: se busca la
# version exacta seguida de «+» o de fin, no el tercer campo tal cual.
if ! forgejo --version 2>/dev/null | grep -qE "version $VERSION(\+| |$)"; then
    tmp="$(mktemp -d)"
    base="https://codeberg.org/forgejo/forgejo/releases/download/v$VERSION"
    bin="forgejo-$VERSION-linux-amd64"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$bin" "$base/$bin"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$bin.sha256" "$base/$bin.sha256"
    (cd "$tmp" && sha256sum -c "$bin.sha256")
    install -m 0755 "$tmp/$bin" /usr/local/bin/forgejo
    rm -rf "$tmp"
fi

echo "==> usuario y directorios"
id forgejo >/dev/null 2>&1 || useradd --system --home-dir "$DATOS" --shell /bin/bash forgejo
install -d -o forgejo -g forgejo "$DATOS" "$DATOS/custom" "$DATOS/data" "$DATOS/log"
install -d -m 0750 -o root -g forgejo /etc/forgejo

if [ ! -f "$CONF" ]; then
    echo "==> configuracion"
    # TODOS los secretos se generan aqui, con el generador de Forgejo. Si falta
    # uno, Forgejo intenta escribirlo el mismo en app.ini, y app.ini es de solo
    # lectura para el servicio A PROPOSITO: un servicio que puede reescribir su
    # propia configuracion puede, comprometido, desactivar su autenticacion.
    secreto="$(forgejo generate secret SECRET_KEY)"
    interno="$(forgejo generate secret INTERNAL_TOKEN)"
    jwt="$(forgejo generate secret JWT_SECRET)"
    lfs="$(forgejo generate secret LFS_JWT_SECRET)"
    cat > "$CONF" <<CONF
APP_NAME = AegisCore
RUN_USER = forgejo
RUN_MODE = prod

[server]
HTTP_ADDR = 127.0.0.1
HTTP_PORT = $PUERTO
ROOT_URL  = $URL/
DISABLE_SSH = true
LFS_JWT_SECRET = $lfs

[database]
DB_TYPE = sqlite3
PATH    = $DATOS/data/forgejo.db

[security]
INSTALL_LOCK   = true
SECRET_KEY     = $secreto
INTERNAL_TOKEN = $interno

[oauth2]
JWT_SECRET = $jwt

[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW  = true

[actions]
ENABLED = true
DEFAULT_ACTIONS_URL = https://code.forgejo.org

[log]
MODE = file
ROOT_PATH = $DATOS/log
CONF
    chown root:forgejo "$CONF"
    chmod 0640 "$CONF"
fi

echo "==> base de datos"
# La salida se guarda y se ensena si falla: callarla escondia justo el error.
if ! forgejo_cli migrate > /tmp/forgejo-migrate.log 2>&1 || grep -q "\[F\]" /tmp/forgejo-migrate.log; then
    cat /tmp/forgejo-migrate.log >&2
    exit 1
fi

echo "==> servicio"
cat > /etc/systemd/system/forgejo.service <<UNIDAD
[Unit]
Description=Forgejo (forja del CI de AegisCore)
After=network.target

[Service]
User=forgejo
Group=forgejo
WorkingDirectory=$DATOS
ExecStart=/usr/local/bin/forgejo web --config $CONF --work-path $DATOS
Restart=always

[Install]
WantedBy=multi-user.target
UNIDAD
systemctl daemon-reload
systemctl enable --now forgejo
for _ in $(seq 1 30); do curl -fs "$URL/api/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "$URL/api/healthz" >/dev/null || { echo "forgejo no responde en $URL" >&2; exit 1; }

if [ ! -f "$SECRETOS" ]; then
    echo "==> administrador y repositorio"
    clave="$(openssl rand -base64 24)"
    forgejo_cli admin user create --admin --username aegis --email aegis@localhost \
        --password "$clave" --must-change-password=false >/dev/null
    token="$(forgejo_cli admin user generate-access-token --username aegis \
        --token-name ci --scopes write:repository,write:user --raw)"
    curl -fsS -H "Authorization: token $token" -H 'Content-Type: application/json' \
        -d '{"name":"aegiscore","private":true,"default_branch":"main"}' \
        "$URL/api/v1/user/repos" >/dev/null
    umask 077
    printf 'usuario=aegis\nclave=%s\ntoken=%s\nremoto=%s/aegis/aegiscore.git\n' \
        "$clave" "$token" "$URL" > "$SECRETOS"
fi

echo
echo "Forja lista en $URL (credenciales en $SECRETOS, solo root)."
echo "Siguiente paso: registrar el runner con KVM:"
echo "    sudo deploy/ci/instalar-runner.sh --instancia $URL --token \$(sudo $0 --token)"
