#!/usr/bin/env bash
#
# Verificacion del forense de memoria a escala (RAM YARA, FASE 57). Informa
# SIEMPRE de que se pudo ejercer y que no, como el resto de fases con muro.
#
# El NUCLEO —partir la memoria en chunks, ARRASTRAR el solapamiento para no perder
# una firma partida en la frontera, escanear con YARA, deduplicar y contabilizar
# para el estrangulador, y el filtro existencial `yara_match` de AegisQL— se
# prueba de verdad en "Rust · tests" (cargo test): AegisMemScanner con reglas YARA
# reales sobre buffers reales, y la tabla `memory` del parser con la query exacta
# de la fase. Aqui se re-ejercita ese nucleo y se DECLARA el muro.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> RAM YARA: el nucleo del escaner y del filtro pasa sus pruebas"
if cargo test -p aegis-scan memscanner --quiet >/tmp/aegis-memscanner.log 2>&1 \
   && cargo test -p aegis-hunt pruebas_yara --quiet >>/tmp/aegis-memscanner.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (chunks + solapamiento + YARA real; filtro existencial yara_match)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-memscanner.log | tail -20
    exit 1
fi

echo "==> RAM YARA: lectura de memoria FISICA/ajena y estrangulado por el SO"
# El escaner lee la memoria de OTROS procesos (o la fisica cruda con el driver de
# las FASES de kernel), y el estrangulado real de E/S/CPU lo aplica el SO por
# fuera (cgroups en Linux, Job Objects en Windows). Ninguna de las dos cosas se
# puede ejercer en un runner sin privilegios ni procesos victima.
if [ "$(id -u)" -eq 0 ] && [ -r /proc/1/maps ]; then
    echo "    ${GRIS}con privilegios: la lectura de memoria ajena PODRIA ejercerse en un despliegue real.${FIN}"
else
    echo "    ${GRIS}sin privilegios de lectura de memoria ajena aqui${FIN}: lectura fisica NO ejercida."
fi
echo "    ${GRIS}El nucleo que DECIDE (partir, solapar, escanear, filtrar) SI se prueba arriba.${FIN}"
exit 0
