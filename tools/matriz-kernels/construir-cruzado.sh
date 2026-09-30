#!/usr/bin/env bash
#
# Artefactos de OTRA arquitectura para la matriz de kernels: las sondas eBPF, el
# verificador estatico y el agente estatico, para aarch64.
#
#   sudo tools/matriz-kernels/construir-cruzado.sh --preparar   (una vez)
#        tools/matriz-kernels/construir-cruzado.sh aarch64
#
# Deja:  drivers/linux/aegis-bpf/out-aarch64/*.bpf.o
#        drivers/linux/aegis-bpf/out-aarch64/aegis_bpf_verify_estatico
#        dist-hermetico-aarch64/aegis-agent
#        dist-hermetico-aarch64/aegis-watchdog
#
# POR QUE ESTATICO CON GLIBC Y NO CON MUSL
#
# En x86-64 el agente publicado es estatico con musl (tools/ci/hermetico.sh), y
# eso exige un sysroot musl completo con libbpf, libelf y zlib compilados desde
# fuente. Para aarch64 no hay toolchain musl cruzado empaquetado; si lo hay para
# glibc (gcc-aarch64-linux-gnu) y las bibliotecas arm64 de la distribucion por
# multiarquitectura. Un binario estatico con glibc es igual de independiente de
# la libc del destino para lo que hace el agente (no usa NSS ni dlopen). Lo que
# se prueba en la matriz es el KERNEL arm64, y eso es identico en los dos casos.
#
# EL BTF DE ARM
#
# Las sondas se compilan contra el vmlinux.h de la arquitectura destino: las
# uprobes leen argumentos de los registros y `struct pt_regs` es propia de cada
# CPU. El BTF de arm64 se extrae arrancando la imagen ARM de la matriz una vez
# (`cargo xtask kernels btf`), porque solo existe con el kernel en marcha.
set -euo pipefail
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$RAIZ"

PAQUETES_ARM64=(libbpf-dev:arm64 libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64)

preparar() {
    [ "$(id -u)" -eq 0 ] || { echo "--preparar necesita root" >&2; exit 1; }
    local codigo; codigo="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    # Las fuentes existentes se restringen a amd64: sin esto, al anadir arm64,
    # apt buscaria paquetes arm64 en archive.ubuntu.com, que no los tiene.
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ] \
        && ! grep -q '^Architectures:' /etc/apt/sources.list.d/ubuntu.sources; then
        sed -i '/^Types: deb/a Architectures: amd64' /etc/apt/sources.list.d/ubuntu.sources
    fi
    cat > /etc/apt/sources.list.d/ubuntu-ports-arm64.sources <<FUENTES
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: $codigo $codigo-updates $codigo-security
Components: main universe
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
FUENTES
    dpkg --add-architecture arm64
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross "${PAQUETES_ARM64[@]}"
    echo "multiarquitectura arm64 lista"
}

aarch64() {
    local btf="${AEGIS_MATRIZ_CACHE:-$HOME/.cache/aegis-matriz}/btf/ubuntu-24.04-arm64.btf"
    if [ ! -s "$btf" ]; then
        echo "==> BTF de arm64 (arranca la imagen ARM una vez, en emulacion)"
        cargo xtask kernels btf --solo ubuntu-24.04-arm64
    fi

    echo "==> sondas eBPF para arm64"
    make -C drivers/linux/aegis-bpf BUILD=out-aarch64 ARCH=arm64 AEGIS_BTF="$btf" build

    echo "==> verificador estatico para arm64"
    aarch64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static \
        -Idrivers/linux/aegis-bpf/include -Ishared/include \
        drivers/linux/aegis-bpf/tools/aegis_bpf_verify.c \
        -o drivers/linux/aegis-bpf/out-aarch64/aegis_bpf_verify_estatico \
        -L/usr/lib/aarch64-linux-gnu -l:libbpf.a -l:libelf.a -l:libz.a -l:libzstd.a

    echo "==> agente estatico para arm64"
    local lib=/usr/lib/aarch64-linux-gnu
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_PATH="$lib/pkgconfig" \
    PKG_CONFIG_LIBDIR="$lib/pkgconfig" \
    AEGIS_BTF="$btf" \
    RUSTFLAGS="-C target-feature=+crt-static -L native=$lib -C link-arg=-l:libzstd.a" \
        cargo build --release --locked --target aarch64-unknown-linux-gnu \
            -p aegis-agent --bin aegis-agent --features estatico-sistema
    # El watchdog: la prueba del trabajador confinado lo usa para demostrar que
    # matar al trabajador no hace que reinicie al agente.
    echo "==> watchdog estatico para arm64"
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    RUSTFLAGS="-C target-feature=+crt-static" \
        cargo build --release --locked --target aarch64-unknown-linux-gnu \
            -p aegis-watchdog --bin aegis-watchdog
    local dir_target="${CARGO_TARGET_DIR:-$RAIZ/target}"
    mkdir -p dist-hermetico-aarch64
    for b in aegis-agent aegis-watchdog; do
        cp "$dir_target/aarch64-unknown-linux-gnu/release/$b" "dist-hermetico-aarch64/$b"
        if readelf -l "dist-hermetico-aarch64/$b" | grep -q INTERP; then
            echo "FALLO: $b de arm64 no es estatico (tiene PT_INTERP)" >&2
            exit 1
        fi
        file "dist-hermetico-aarch64/$b" 2>/dev/null || true
    done
    echo "artefactos aarch64 listos"
}

case "${1:-}" in
    --preparar) preparar ;;
    aarch64) aarch64 ;;
    *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
