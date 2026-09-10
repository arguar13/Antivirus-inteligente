#!/usr/bin/env bash
#
# Job de CI: programas eBPF ante el verificador del kernel.
#
# Compilar un programa eBPF no demuestra nada: el verificador del kernel rechaza
# codigo que compila sin un solo aviso. La prueba real es CARGARLO. Donde no hay
# privilegios o el kernel no lo permite, se OMITE con honestidad en vez de
# fingir que paso.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: ebpf (CO-RE, integridad y verificador)"
FALLOS=0

if ! hay clang; then
    omitido "sin clang no se pueden compilar los programas eBPF"
    exit 0
fi

if ! hay bpftool; then
    omitido "sin bpftool no se puede generar vmlinux.h (BPF CO-RE)"
    exit 0
fi

correr "compilar programas eBPF" make -C drivers/linux/aegis-bpf build || FALLOS=$((FALLOS+1))
correr "firmar e integridad HMAC"  make -C drivers/linux/aegis-bpf sign  || FALLOS=$((FALLOS+1))

# Que el bytecode sea REUBICABLE, no solo compilable. Sin esto, un objeto puede
# llevar dentro los desplazamientos del kernel de construccion y leer campos
# equivocados en cualquier otro kernel, sin un solo mensaje de error.
correr "conformidad CO-RE del bytecode" make -C drivers/linux/aegis-bpf core-check \
    || FALLOS=$((FALLOS+1))

# Y que esas reubicaciones RESUELVAN contra kernels reales distintos del de esta
# maquina. Es la prueba de "compile once, run everywhere" que se puede hacer sin
# arrancar esos kernels.
paso "reubicacion contra kernels de referencia"
if make -C drivers/linux/aegis-bpf core-matrix > /tmp/aegis-core-matrix.log 2>&1; then
    if grep -q "OMITIDO" /tmp/aegis-core-matrix.log; then
        omitido "no hay BTF de referencia (tools/toolchain/traer_btf.sh)"
    else
        ok
        grep -E "^---|CO-RE OK|pasan el verificador" /tmp/aegis-core-matrix.log \
            | sed 's/^/      | /'
    fi
else
    fallo "el bytecode no reubica contra algun kernel de referencia"
    tail -20 /tmp/aegis-core-matrix.log | sed 's/^/      | /'
    FALLOS=$((FALLOS+1))
fi

# El verificador exige privilegios y un kernel con BPF habilitado.
if [ "$(id -u)" -eq 0 ]; then
    # tracefs hace falta para los puntos de anclaje; si no monta, el propio
    # objetivo `verify` lo reporta.
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
    if make -C drivers/linux/aegis-bpf verify > /tmp/aegis-ebpf-verify.log 2>&1; then
        paso "verificador del kernel"; ok
    else
        paso "verificador del kernel"
        if grep -qiE "operation not permitted|not supported|no such file" /tmp/aegis-ebpf-verify.log; then
            omitido "este kernel no permite cargar los programas"
        else
            fallo "el verificador rechazo un programa"
            tail -30 /tmp/aegis-ebpf-verify.log | sed 's/^/      | /'
            FALLOS=$((FALLOS+1))
        fi
    fi
else
    paso "verificador del kernel"; omitido "hace falta root para cargar eBPF"
fi

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
