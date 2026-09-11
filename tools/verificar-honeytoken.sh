#!/usr/bin/env bash
#
# Verificacion de decepcion activa / honey-tokens (FASE 52). Informa SIEMPRE de
# que se pudo ejercer y que no.
#
# El NUCLEO —acunar el marcador atribuible, renderizar credenciales creibles
# (validadas por parsers reales), planificar sobre /proc/maps real y decidir el
# disparo— se prueba en "Rust · tests" (cargo test --all lo incluye). Aqui se
# comprueba que la FONTANERIA gated (process_vm_writev sobre memoria ajena)
# COMPILA, y se declara que su EJECUCION necesita un proceso victima real y
# privilegios que el CI no da.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> Honeytoken: la fontaneria de inyeccion en memoria ajena COMPILA (feature inyeccion)"
if cargo check -p aegis-honeytoken --features inyeccion >/dev/null 2>&1; then
    echo "    ${VERDE}OK${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la fontaneria gated no compila"
    exit 1
fi
echo "    ${GRIS}Inyeccion en LSASS/ssh-agent via process_vm_writev: NO ejercida aqui${FIN}"
echo "    ${GRIS}(necesita un proceso victima real y privilegios). El nucleo SI se prueba.${FIN}"
exit 0
