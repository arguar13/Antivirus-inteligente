#!/usr/bin/env bash
#
# Prepara un contenedor EFIMERO recien creado para poder correr `make ci`.
#
# POR QUE EXISTE
# --------------
# El CI remoto (GitHub Actions) esta bloqueado en este proyecto (docs/07-estado-ci.md),
# asi que la puerta de calidad real es `make ci` local. Pero `make ci` necesita
# cosas que NO viven en git y que un contenedor nuevo no trae:
#
#   1. Herramientas de sistema que el workflow del CI instalaria (`protoc` para
#      tonic, `libelf`/`libbpf` y `bpftool` para los programas eBPF de CO-RE).
#   2. Los modelos ONNX embebidos (FASE 48/53), que estan GITIGNOREADOS (*.onnx)
#      porque son artefactos generados —no codigo— y se calibran con un script.
#
# Sin esto, `make ci` falla en un contenedor fresco por cosas que no son defectos
# del producto (falta `protoc`, falta un modelo). Este script cierra ese hueco de
# forma REPRODUCIBLE e IDEMPOTENTE: se puede correr las veces que haga falta.
#
# Uso:  ./tools/preparar-entorno.sh
# Se ejecuta ademas solo, al arrancar una sesion de Claude Code en la web, via el
# hook SessionStart de .claude/settings.json.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; AMAR=$'\033[33m'; FIN=$'\033[0m'
info()  { printf '%s==>%s %s\n' "$GRIS" "$FIN" "$1"; }
ok()    { printf '    %sOK%s %s\n' "$VERDE" "$FIN" "${1:-}"; }
aviso() { printf '    %sAVISO%s %s\n' "$AMAR" "$FIN" "$1"; }

# sudo solo si hace falta y existe.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi

APT_ACTUALIZADO=0
apt_update_una_vez() {
    [ "$APT_ACTUALIZADO" -eq 1 ] && return 0
    $SUDO apt-get update -qq >/dev/null 2>&1 || true
    APT_ACTUALIZADO=1
}

# Instala paquetes apt solo si alguno de sus binarios/ficheros clave falta.
# $1 = descripcion; $2 = fichero/binario testigo; $3.. = paquetes.
asegurar_apt() {
    local desc="$1" testigo="$2"; shift 2
    if [ -e "$testigo" ] || command -v "$(basename "$testigo")" >/dev/null 2>&1; then
        ok "$desc ya presente"
        return 0
    fi
    info "instalando $desc ($*)"
    apt_update_una_vez
    if $SUDO apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1; then
        ok "$desc instalado"
    else
        aviso "no se pudo instalar $desc; 'make ci' podria fallar en el grupo afectado"
    fi
}

echo "== Preparando el entorno para 'make ci' =="

# --- 1. Herramientas de compilacion / protobuf / eBPF -----------------------
asegurar_apt "protoc (tonic)"        /usr/bin/protoc            protobuf-compiler
asegurar_apt "clang"                 /usr/bin/clang             clang
asegurar_apt "lld (lld-link)"        /usr/bin/lld-link          lld
asegurar_apt "headers libelf"        /usr/include/libelf.h      libelf-dev
asegurar_apt "headers libbpf"        /usr/include/bpf/libbpf.h  libbpf-dev
asegurar_apt "headers zlib"          /usr/include/zlib.h        zlib1g-dev
asegurar_apt "pkg-config"            /usr/bin/pkg-config        pkg-config
asegurar_apt "pip de python3"        /usr/bin/pip3             python3-pip

# --- 2. bpftool (genera vmlinux.h del BTF para los eBPF CO-RE) ---------------
# El paquete `bpftool` suele no tener candidato directo; el binario real viene en
# los `linux-tools-*`. Como el kernel del contenedor es a medida, el wrapper por
# version no sirve, pero el BINARIO si (solo lee un fichero BTF). Se localiza y se
# enlaza a /usr/local/bin.
info "bpftool (para vmlinux.h de los eBPF)"
if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
    ok "bpftool ya funciona"
else
    apt_update_una_vez
    # Probar varias fuentes; la que exista se instala.
    for paq in linux-tools-generic "linux-tools-$(uname -r)" linux-tools-6.8.0-31-generic; do
        $SUDO apt-get install -y --no-install-recommends "$paq" >/dev/null 2>&1 && break
    done
    BIN="$(find /usr/lib/linux-tools* -name bpftool -type f 2>/dev/null | sort -V | tail -1)"
    if [ -n "$BIN" ] && "$BIN" version >/dev/null 2>&1; then
        $SUDO ln -sf "$BIN" /usr/local/bin/bpftool
        ok "bpftool enlazado ($BIN)"
    else
        aviso "no se encontro un bpftool utilizable; el grupo eBPF de 'make ci' fallara"
    fi
fi

# --- 2b. El BTF del kernel, ¿alcanza para los eBPF de este proyecto? ---------
#
# No basta con que HAYA BTF: tiene que traer los tipos que usan los programas.
# `aegis_kintegrity.bpf.c` recorre la lista de tareas con los iteradores abiertos
# (`bpf_iter_task_*`, kernel 6.7+), y hay kernels con BTF que NO los exponen
# porque se compilaron sin esa parte. El de WSL2 es uno: tiene BTF de 6 MB y seis
# mil tipos, pero ni `struct bpf_iter_task` ni las kfunc.
#
# Sin esta comprobacion, el sintoma es un error de clang a mitad de `cargo build`
# —"variable has incomplete type 'struct bpf_iter_task'"— que no dice nada de la
# causa real ni de como arreglarlo. Se detecta aqui y se dice que hacer.
info "BTF del kernel: ¿trae los tipos de los iteradores abiertos?"
BTF_K="${AEGIS_BTF:-/sys/kernel/btf/vmlinux}"
if [ ! -r "$BTF_K" ]; then
    aviso "no hay BTF legible en $BTF_K; el kernel necesita CONFIG_DEBUG_INFO_BTF"
elif ! command -v bpftool >/dev/null 2>&1; then
    aviso "sin bpftool no se puede comprobar el BTF"
elif bpftool btf dump file "$BTF_K" format raw 2>/dev/null \
        | grep >/dev/null "STRUCT 'bpf_iter_task'"; then
    ok "el BTF de $BTF_K trae struct bpf_iter_task"
else
    aviso "el BTF de $BTF_K NO trae struct bpf_iter_task."
    aviso "  aegis_kintegrity.bpf.c no compilara contra el. Pasa comun en WSL2 y"
    aviso "  en kernels recortados. Apunta AEGIS_BTF al vmlinux de un kernel que"
    aviso "  si los tenga (>= 6.4 con los iteradores compilados); el Makefile lo"
    aviso "  admite: CO-RE reubica en el destino, no en la compilacion. Por"
    aviso "  ejemplo, extraido del paquete linux-image-*-generic de la distro."
fi

# --- 3. Dependencias de Python para generar los modelos ---------------------
info "numpy + onnx (para generar los modelos)"
if python3 -c "import numpy, onnx" >/dev/null 2>&1; then
    ok "numpy y onnx ya presentes"
else
    if python3 -m pip install --quiet numpy onnx >/dev/null 2>&1 \
        || python3 -m pip install --quiet --break-system-packages numpy onnx >/dev/null 2>&1; then
        ok "numpy y onnx instalados"
    else
        aviso "no se pudieron instalar numpy/onnx; no se generaran los modelos"
    fi
fi

# --- 4. Modelos ONNX embebidos (gitignoreados) ------------------------------
# Se generan con sus scripts de calibracion (los pesos estan fijados a mano, no
# entrenados; ver crates/aegis-ml/tools/build_model.py).
generar_modelo() {
    local salida="$1" generador="$2" desc="$3"
    if [ -f "$salida" ]; then
        ok "$desc ya generado"
        return 0
    fi
    mkdir -p "$(dirname "$salida")"
    if python3 "$generador" "$salida" >/dev/null 2>&1; then
        ok "$desc generado ($(wc -c < "$salida") bytes)"
    else
        aviso "no se pudo generar $desc; 'make ci' fallara al compilar el crate que lo embebe"
    fi
}
info "modelos ONNX embebidos"
generar_modelo crates/aegis-ml/models/aegis-static-v1.onnx \
    crates/aegis-ml/tools/build_model.py "modelo estatico (aegis-ml)"
generar_modelo crates/aegis-edgeml/models/aegis-behavior-v1.onnx \
    crates/aegis-edgeml/tools/build_behavior_model.py "modelo de comportamiento (aegis-edgeml)"
generar_modelo crates/aegis-l7hunter/models/aegis-c2-l7-v1.onnx \
    crates/aegis-l7hunter/tools/build_c2_model.py "modelo de canales C2 (aegis-l7hunter)"

echo "== Entorno listo. Ya se puede correr 'make ci'. =="
