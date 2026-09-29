#!/usr/bin/env bash
#
# Abre la consola de AegisCore en el navegador, YA.
#
# Sirve la consola estatica (server/panel/) con un servidor local minimo y abre
# el navegador. No necesita PostgreSQL, ni Redis, ni la CA de flota: es la propia
# pagina que va embebida en el binario firmado, servida tal cual para verla.
#
# Para recorrerla entera sin backend, pulsa «Ver demostracion» en el acceso: carga
# datos sinteticos (flota, alertas, linaje, reglas, inteligencia, caza, campanas)
# con la misma forma que devuelve el plano de control real. Para datos REALES,
# arranca el servidor completo (aegis-server) y entra con tu operador.
set -uo pipefail
cd "$(dirname "$0")/.."

PUERTO="${1:-8899}"
RAIZ="server"   # se sirve desde aqui para que /panel/estilo.css y /panel/app.js resuelvan
URL="http://localhost:${PUERTO}/panel/"

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ACENTO=$'\033[36m'; FIN=$'\033[0m'

if ! command -v python3 >/dev/null 2>&1; then
    echo "Necesito python3 para servir la consola. Instalalo o abre server/panel/ con tu servidor estatico preferido." >&2
    exit 1
fi

echo "${VERDE}==>${FIN} Consola de AegisCore"
echo "    Sirviendo ${GRIS}${RAIZ}/panel/${FIN} en el puerto ${PUERTO}"
echo
echo "    Abre:  ${ACENTO}${URL}${FIN}"
echo "    ${GRIS}En el acceso, pulsa «Ver demostracion» para recorrerla con datos sinteticos.${FIN}"
echo "    ${GRIS}Ctrl+C para parar el servidor.${FIN}"
echo

# Intentar abrir el navegador (Windows via WSL, macOS, Linux). Si no se puede, no
# pasa nada: la URL esta impresa arriba.
(
  sleep 1
  if command -v explorer.exe >/dev/null 2>&1; then explorer.exe "$URL" >/dev/null 2>&1
  elif command -v cmd.exe >/dev/null 2>&1; then cmd.exe /c start "" "$URL" >/dev/null 2>&1
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1
  fi
) &

# Servir. --bind 127.0.0.1: no se expone a la red, solo a esta maquina.
exec python3 -m http.server "$PUERTO" --bind 127.0.0.1 --directory "$RAIZ"
