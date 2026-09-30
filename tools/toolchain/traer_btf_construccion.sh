#!/usr/bin/env bash
#
# El BTF de CONSTRUCCION: el universo de tipos del kernel contra el que se
# genera vmlinux.h y se compilan las sondas eBPF.
#
#   tools/toolchain/traer_btf_construccion.sh            lo deja si falta
#   tools/toolchain/traer_btf_construccion.sh --forzar   lo vuelve a extraer
#
# Destino: /opt/aegis-btf/vmlinux-construccion (+ .procedencia), que es lo que
# `make ci` usa por defecto (AEGIS_BTF).
#
# POR QUE NO EL DEL KERNEL QUE COMPILA
#
# Porque depende de la maquina. Las sondas usan tipos que no todo kernel expone
# (los iteradores abiertos de tareas, 6.7+): con el BTF del kernel de WSL2 (6.6)
# `aegis_kintegrity` no compila. Hasta la FASE 0 del MP-15 eso lo tapaba un BTF
# extraido a mano en la maquina del desarrollador y pasado por variable de
# entorno; el primer runner limpio no lo tenia y quince grupos de make ci
# fallaron en cascada. Ahora el BTF se OBTIENE de forma reproducible: el del
# kernel de Ubuntu 24.04 de la matriz de kernels, extraido arrancando su imagen
# cloud oficial, verificada contra las sumas que publica Ubuntu.
#
# El bytecode sigue siendo universal: CO-RE reubica en el destino. Este BTF solo
# fija los TIPOS con los que se compila.
set -euo pipefail
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$RAIZ"

IMAGEN="ubuntu-24.04"
DESTINO="${AEGIS_BTF_CONSTRUCCION:-/opt/aegis-btf/vmlinux-construccion}"
CACHE="${AEGIS_MATRIZ_CACHE:-$HOME/.cache/aegis-matriz}"

if [ -s "$DESTINO" ] && [ "${1:-}" != "--forzar" ]; then
    echo "BTF de construccion presente: $DESTINO"
    exit 0
fi

echo "==> imagen $IMAGEN (verificada por sus sumas oficiales)"
cargo xtask kernels traer --solo "$IMAGEN"
echo "==> extraer su BTF arrancandola en una microVM"
cargo xtask kernels btf --solo "$IMAGEN"

origen="$CACHE/btf/$IMAGEN.btf"
[ -s "$origen" ] || { echo "no se obtuvo $origen" >&2; exit 1; }
mkdir -p "$(dirname "$DESTINO")"
install -m 0644 "$origen" "$DESTINO"
{
    echo "origen : kernel de la imagen cloud oficial de $IMAGEN (tools/config/kernels.toml)"
    sed -n 1p "$CACHE/imagenes/$IMAGEN.origen" | sed 's/^/imagen : /'
    echo "sha256 : $(sha256sum "$DESTINO" | cut -d' ' -f1)"
    echo "fecha  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$DESTINO.procedencia"
echo "BTF de construccion en $DESTINO"
cat "$DESTINO.procedencia"
