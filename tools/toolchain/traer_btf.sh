#!/usr/bin/env bash
#
# AegisCore - BTF de referencia para la prueba cruzada de CO-RE (FASE 42).
#
# POR QUE
# -------
# El bytecode eBPF de AegisCore se compila una vez y se ejecuta en cualquier
# kernel con BTF: eso es CO-RE. Pero "se ejecuta en cualquier kernel" es una
# AFIRMACION, y una afirmacion sin prueba en un producto de seguridad vale cero.
#
# Este script trae los BTF de kernels reales de distribuciones reales para que
# `make -C drivers/linux/aegis-bpf core-matrix` pueda reubicar los programas
# contra ellos y demostrar, aqui y ahora, que ningun campo que el codigo lee ha
# desaparecido o cambiado de nombre en esos kernels. Es el mismo mecanismo que
# usa libbpf en el endpoint del cliente, solo que apuntado a otro BTF.
#
# De donde salen: BTFHub, el archivo publico de BTF de kernels distribuidos que
# mantiene Aqua Security. Se descargan solo los ficheros pedidos —el archivo
# completo son decenas de gigabytes— usando un clon sin blobs con checkout
# disperso.
#
# Uso:  tools/toolchain/traer_btf.sh
#   AEGIS_BTF_DIR=<ruta>  destino (por defecto /opt/aegis/btf)
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$RAIZ/tools/ci/_comun.sh"

DESTINO="${AEGIS_BTF_DIR:-/opt/aegis/btf}"
CACHE="${AEGIS_BTF_CACHE:-/opt/aegis/cache/btfhub}"
REPO="https://github.com/aquasecurity/btfhub-archive"

# Kernels de referencia. Cada uno esta aqui por un motivo concreto, no por
# rellenar: si un dia hay que quitar uno, que se sepa que cobertura se pierde.
#
#   5.4  Ubuntu 20.04 GA y RHEL 8 de facto. Es ANTERIOR al renombrado de
#        `real_start_time` a `start_boottime` (5.5), asi que es quien prueba de
#        verdad el sabor de tipo `task_struct___pre55`.
#   5.8  El suelo declarado de soporte del filtro XDP y de la telemetria.
REFERENCIAS=(
  "ubuntu/20.04/x86_64/5.4.0-42-generic.btf.tar.xz"
  "ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz"
)

titulo "BTF de referencia para la prueba cruzada de CO-RE"

if ! hay git; then
    fallo "falta git"; exit 1
fi
if ! hay tar; then
    fallo "falta tar"; exit 1
fi

mkdir -p "$DESTINO"

paso "clon sin blobs de BTFHub"
if [ ! -d "$CACHE/.git" ]; then
    mkdir -p "$(dirname "$CACHE")"
    if ! git clone --quiet --depth 1 --filter=blob:none --sparse "$REPO" "$CACHE" 2>/dev/null; then
        fallo "no se pudo clonar $REPO"
        echo "      | sin red: coloca los .btf directamente en $DESTINO"
        exit 1
    fi
fi
ok "$(du -sh "$CACHE" | cut -f1) en $CACHE"

paso "checkout disperso de ${#REFERENCIAS[@]} kernel(es)"
rutas=()
for r in "${REFERENCIAS[@]}"; do rutas+=("/$r"); done
if ! git -C "$CACHE" sparse-checkout set --no-cone "${rutas[@]}" 2>/dev/null; then
    fallo "el checkout disperso fallo"
    exit 1
fi

traidos=0
for r in "${REFERENCIAS[@]}"; do
    archivo="$CACHE/$r"
    if [ ! -f "$archivo" ]; then
        fallo "no llego $r"
        echo "      | el nombre puede haber cambiado en el archivo de origen"
        exit 1
    fi
    if ! tar -xJf "$archivo" -C "$DESTINO"; then
        fallo "no se pudo extraer $r"
        exit 1
    fi
    traidos=$((traidos + 1))
done
# Los .tar.xz de BTFHub conservan permisos restrictivos del empaquetador; el CI
# corre como otro usuario y tiene que poder leerlos.
chmod 0644 "$DESTINO"/*.btf 2>/dev/null || true
ok "$traidos kernel(es) extraidos en $DESTINO"

paso "BTF disponibles"
for b in "$DESTINO"/*.btf; do
    [ -e "$b" ] || continue
    printf '      | %-34s %s\n' "$(basename "$b")" "$(du -h "$b" | cut -f1)"
done
ok "listo para: make -C drivers/linux/aegis-bpf core-matrix"
