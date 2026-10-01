#!/usr/bin/env bash
#
# Aprovisiona un runner de CI de AegisCore para Forgejo Actions, o comprueba que
# el que hay sirve.
#
#   sudo deploy/ci/instalar-runner.sh --instancia https://forja.ejemplo --token XXXX
#   deploy/ci/instalar-runner.sh --comprobar
#
# El runner corre en modo HOST y como ROOT, con la etiqueta `kvm`, porque las
# pruebas cargan programas eBPF, leen memoria de otros procesos y arrancan
# microVM con KVM. Eso exige una maquina DEDICADA al CI —fisica, o una VM con
# virtualizacion anidada—, nunca el puesto de un desarrollador ni un servidor de
# produccion. Ver docs/ci-remoto.md.
#
# Distribuciones probadas: Ubuntu 24.04 y 26.04, Debian 12.
set -euo pipefail

VERSION_RUNNER="13.2.0"
VERSION_RUST="1.94.0"
DIR_RUNNER="/var/lib/forgejo-runner"
CACHE="/var/cache/aegis-ci"
RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
ok()    { printf '    %sOK%s    %s\n' "$VERDE" "$FIN" "$1"; }
falta() { printf '    %sFALTA%s %s\n' "$ROJO" "$FIN" "$1"; FALTAN=$((FALTAN + 1)); }

PAQUETES=(
    # compilacion
    build-essential clang llvm pkg-config git curl ca-certificates
    # eBPF y construccion hermetica (libbpf desde fuente necesita autotools)
    libbpf-dev libelf-dev zlib1g-dev libzstd-dev linux-libc-dev
    musl-dev musl-tools autoconf automake libtool autopoint gettext flex bison
    # matriz de kernels
    qemu-system-x86 qemu-system-arm qemu-utils qemu-efi-aarch64 ovmf
    cloud-image-utils e2fsprogs
    # pruebas de integracion del plano de control
    postgresql redis-server
    # testigos y material de las pruebas del agente: make ci no admite que se
    # omitan por su falta (aegis_prueba, tools/config/omisiones.toml)
    lld nftables python3 default-jre-headless
    # actions/checkout es JavaScript
    nodejs
)

comprobar() {
    FALTAN=0
    printf '%s==> runner de CI de AegisCore%s\n' "$GRIS" "$FIN"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ok "KVM"; else falta "KVM (/dev/kvm): la matriz de kernels no puede arrancar"; fi
    if [ -n "${HOME:-}" ]; then ok "HOME"; else falta "HOME sin definir (la unidad del runner necesita User=root)"; fi
    for b in clang qemu-system-x86_64 qemu-system-aarch64 cloud-localds mkfs.ext4 readelf nm \
             psql redis-server node lld-link nft python3 java; do
        if command -v "$b" >/dev/null 2>&1; then ok "$b"; else falta "$b"; fi
    done
    for b in cargo rustup cargo-deny cargo-audit cargo-vet cargo-fuzz; do
        if command -v "$b" >/dev/null 2>&1; then ok "$b"; else falta "$b"; fi
    done
    if command -v rustup >/dev/null 2>&1; then
        for t in x86_64-unknown-linux-musl aarch64-unknown-linux-gnu; do
            if rustup target list --installed 2>/dev/null | grep -qx "$t"; then ok "objetivo $t"; else falta "objetivo de Rust $t"; fi
        done
        nightly="$(tr -d '[:space:]' < "$RAIZ/tools/toolchain/nightly-fuzz.txt")"
        if rustup toolchain list 2>/dev/null | grep -q "^$nightly"; then ok "toolchain de fuzzing $nightly"; else falta "toolchain de fuzzing $nightly"; fi
    fi
    if [ -x /opt/aegis/musl-sysroot/bin/aegis-musl-gcc ]; then ok "sysroot musl"; else falta "sysroot musl (tools/toolchain/preparar_musl.sh)"; fi
    if [ -s /opt/aegis-btf/vmlinux-construccion ]; then ok "BTF de construccion"; else falta "BTF de construccion (tools/toolchain/traer_btf_construccion.sh)"; fi
    [ "$FALTAN" -eq 0 ] && { printf '%sEl runner sirve.%s\n' "$VERDE" "$FIN"; return 0; }
    printf '%s%d pieza(s) faltan: sudo %s --instancia URL --token TOKEN%s\n' "$ROJO" "$FALTAN" "$0" "$FIN"
    return 1
}

instalar() {
    local instancia="$1" token="$2" nombre="$3"
    [ "$(id -u)" -eq 0 ] || { echo "hace falta root" >&2; exit 1; }
    [ -r /dev/kvm ] || { echo "esta maquina no tiene KVM: no sirve de runner" >&2; exit 1; }

    echo "==> paquetes"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PAQUETES[@]}"

    echo "==> Rust $VERSION_RUST (el mismo toolchain que el desarrollo)"
    if ! command -v rustup >/dev/null 2>&1; then
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$VERSION_RUST"
    fi
    # Solo existe si rustup lo instalo este script; si ya habia otro, esta en PATH.
    # shellcheck disable=SC1091
    if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
    rustup toolchain install "$VERSION_RUST" --profile minimal -c clippy -c rustfmt
    rustup default "$VERSION_RUST"
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-unknown-linux-gnu

    echo "==> herramientas de cadena de suministro y de fuzzing"
    cargo install --locked cargo-deny cargo-audit cargo-vet cargo-fuzz
    # El nightly del fuzzing, FIJADO: libFuzzer y el sanitizador lo exigen, y uno
    # sin fecha seria otro compilador cada dia.
    rustup toolchain install "$(tr -d '[:space:]' < "$RAIZ/tools/toolchain/nightly-fuzz.txt")" --profile minimal

    echo "==> sysroot musl"
    "$RAIZ/tools/toolchain/preparar_musl.sh"

    echo "==> multiarquitectura arm64 (agente y sondas cruzados de la matriz)"
    "$RAIZ/tools/matriz-kernels/construir-cruzado.sh" --preparar

    echo "==> BTF de construccion de las sondas eBPF (reproducible, no el del anfitrion)"
    "$RAIZ/tools/toolchain/traer_btf_construccion.sh"

    echo "==> forgejo-runner $VERSION_RUNNER (verificado por suma)"
    local base="https://code.forgejo.org/forgejo/runner/releases/download/v$VERSION_RUNNER"
    local bin="forgejo-runner-$VERSION_RUNNER-linux-amd64"
    local tmp; tmp="$(mktemp -d)"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$bin" "$base/$bin"
    curl -fsSL --retry 5 --retry-all-errors -o "$tmp/$bin.sha256" "$base/$bin.sha256"
    (cd "$tmp" && sha256sum -c "$bin.sha256")
    install -m 0755 "$tmp/$bin" /usr/local/bin/forgejo-runner
    rm -rf "$tmp"

    echo "==> registro en $instancia"
    mkdir -p "$DIR_RUNNER" "$CACHE"
    cd "$DIR_RUNNER"
    forgejo-runner generate-config > config.yml
    forgejo-runner register --no-interactive --instance "$instancia" --token "$token" \
        --name "$nombre" --labels "kvm:host"

    echo "==> servicio"
    cat > /etc/systemd/system/forgejo-runner.service <<UNIDAD
[Unit]
Description=Runner de CI de AegisCore (Forgejo Actions, modo host, KVM)
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target

[Service]
# User= explicito aunque sea root: sin el, systemd no define HOME ni USER, y los
# verificadores que usan \$HOME (cache de Trivy, de Kafka) abortaban con
# «unbound variable» solo en el runner.
User=root
WorkingDirectory=$DIR_RUNNER
ExecStart=/usr/local/bin/forgejo-runner daemon --config $DIR_RUNNER/config.yml
Environment=PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIDAD
    systemctl daemon-reload
    systemctl enable --now forgejo-runner
    comprobar
}

case "${1:-}" in
    --comprobar) comprobar ;;
    --instancia)
        instancia="${2:?falta la URL de la instancia}"
        [ "${3:-}" = "--token" ] || { echo "uso: $0 --instancia URL --token TOKEN [--nombre N]" >&2; exit 2; }
        token="${4:?falta el token de registro}"
        nombre="aegis-kvm-$(hostname -s)"
        [ "${5:-}" = "--nombre" ] && nombre="${6:?falta el nombre}"
        instalar "$instancia" "$token" "$nombre"
        ;;
    *)
        sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
