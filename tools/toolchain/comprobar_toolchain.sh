#!/usr/bin/env bash
#
# Puerta: la toolchain con la que se construye es la FIJADA.
#
# QUE COMPRUEBA
# -------------
# Rust (siempre):
#   1. `channel` de rust-toolchain.toml es el canal de tools/toolchain/fijado.toml
#   2. `rustc --version` y `cargo --version` son EXACTAMENTE los fijados (el hash
#      corto es el commit del compilador)
#   3. el manifiesto del canal instalado es el fijado y el rust-std de cada
#      objetivo esta instalado con el SHA-256 fijado
#   4. la imagen hermetica (tools/toolchain/imagen/Dockerfile) pide el mismo canal
#
# Sysroot musl (con --sysroot DIR, desde tools/ci/hermetico.sh):
#   5. el sysroot tiene SELLO y se construyo con la receta ACTUAL
#      (tools/toolchain/preparar_musl.sh, por su SHA-256), con el rustc fijado y
#      con los paquetes fijados
#   6. los paquetes del anfitrion siguen en la version fijada: el gcc y binutils
#      del anfitrion compilan el C vendorizado a traves del envoltorio
#   7. el arbol del sysroot no ha cambiado desde que se sello
#
# POR QUE
# -------
# Hasta ahora nada fijaba el compilador. Cada maquina usaba el `default` de su
# rustup; el runner instalaba 1.94.0, la imagen hermetica 1.94.1 y el workflow
# de GitHub `stable`. El sysroot se componia con la musl y las cabeceras que
# tuviera la distribucion en ese momento. Un `apt upgrade` o un `rustup update`
# cambiaban el binario que se entrega sin tocar una linea del repositorio.
#
# Uso:  tools/toolchain/comprobar_toolchain.sh [--sysroot DIR]
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../ci/_comun.sh"
source "$RAIZ/tools/toolchain/fijado.sh"
# Desde la raiz, para que rustup elija la toolchain por rust-toolchain.toml
# igual que cuando compila la tanda.
cd "$RAIZ" || exit 1

SYSROOT=""
case "${1:-}" in
    --sysroot) SYSROOT="${2:?falta el directorio del sysroot}" ;;
    "") ;;
    *) echo "uso: $0 [--sysroot DIR]" >&2; exit 2 ;;
esac

titulo "Toolchain fijada (tools/toolchain/fijado.toml)"
FALLOS=0

# igual <que> <esperado> <obtenido>: un paso por comprobacion, con los dos valores
# a la vista cuando no coinciden.
igual() {
    paso "$1"
    if [ "$2" = "$3" ]; then
        ok "$3"
    else
        fallo
        printf '      | fijado  : %s\n' "${2:-(vacio)}"
        printf '      | en uso  : %s\n' "${3:-(vacio)}"
        FALLOS=$((FALLOS + 1))
    fi
}

if ! CANAL="$(fijado_valor rust canal)"; then
    paso "fijado.toml"; fallo "no tiene [rust] canal"; exit 1
fi

# --- 1-2. El compilador -----------------------------------------------------
igual "rust-toolchain.toml elige el canal fijado" \
    "$CANAL" "$(fijado_valor toolchain channel "$RAIZ/rust-toolchain.toml" 2>/dev/null)"
igual "rustc" "$(fijado_valor rust rustc)" "$(rustc --version 2>/dev/null)"
igual "cargo" "$(fijado_valor rust cargo)" "$(cargo --version 2>/dev/null)"

# --- 3. El canal instalado y sus rust-std -----------------------------------
# rustup deja en cada toolchain el manifiesto del canal del que la instalo, con
# el SHA-256 de cada paquete que descargo y verifico.
SYSROOT_RUST="$(rustc --print sysroot 2>/dev/null)"
MANIFIESTO="$SYSROOT_RUST/lib/rustlib/multirust-channel-manifest.toml"
if [ ! -f "$MANIFIESTO" ]; then
    paso "manifiesto del canal"
    fallo "no hay $MANIFIESTO: esta toolchain no la instalo rustup"
    FALLOS=$((FALLOS + 1))
else
    igual "manifiesto del canal" "$(fijado_valor rust manifiesto)" \
        "$(awk -F'"' '/^date = /{print $2; exit}' "$MANIFIESTO")"
    for objetivo in $(fijado_claves rust-std); do
        if [ ! -d "$SYSROOT_RUST/lib/rustlib/$objetivo/lib" ]; then
            paso "rust-std $objetivo"
            fallo "no esta instalado: rustup target add $objetivo"
            FALLOS=$((FALLOS + 1))
            continue
        fi
        igual "rust-std $objetivo" "$(fijado_valor rust-std "$objetivo")" \
            "$(awk -v c="[pkg.rust-std.target.$objetivo]" '
                  $0 == c { en = 1; next }
                  en && /^\[/ { exit }
                  en && /^xz_hash = / { gsub(/^xz_hash = "|"$/, ""); print; exit }
              ' "$MANIFIESTO")"
    done
fi

# --- 4. La imagen hermetica pide el mismo canal ------------------------------
igual "tools/toolchain/imagen/Dockerfile (RUST_VERSION)" "$CANAL" \
    "$(awk -F= '/^ARG RUST_VERSION=/{print $2; exit}' "$RAIZ/tools/toolchain/imagen/Dockerfile")"

# --- 5-7. El sysroot musl ----------------------------------------------------
if [ -n "$SYSROOT" ]; then
    SELLO="$SYSROOT/SELLO"
    paso "sello del sysroot"
    if [ ! -f "$SELLO" ]; then
        fallo "$SYSROOT no tiene SELLO: no se sabe de que se construyo"
        echo "      | rehazlo con: tools/toolchain/preparar_musl.sh"
        FALLOS=$((FALLOS + 1))
    else
        ok "$SELLO"
        igual "sysroot: receta (preparar_musl.sh)" \
            "$(sha256sum < "$RAIZ/tools/toolchain/preparar_musl.sh" | cut -d' ' -f1)" \
            "$(fijado_sello_valor "$SELLO" receta)"
        igual "sysroot: rustc de la libunwind" "$(fijado_valor rust rustc)" \
            "$(fijado_sello_valor "$SELLO" rustc)"
        for p in $(fijado_claves sysroot-musl); do
            [ "$p" = "distribucion" ] && continue
            igual "sysroot: $p" "$(fijado_valor sysroot-musl "$p")" \
                "$(fijado_sello_valor "$SELLO" "paquete.$p")"
        done
        igual "sysroot: arbol intacto desde el sello" \
            "$(fijado_sello_valor "$SELLO" arbol)" "$(fijado_huella_arbol "$SYSROOT")"
    fi

    paso "paquetes del anfitrion en la version fijada"
    if desvios="$(fijado_desvios_paquetes)"; then
        ok
    else
        fallo
        printf '%s\n' "$desvios" | sed 's/^/      | /'
        FALLOS=$((FALLOS + 1))
    fi
fi

if [ "$FALLOS" -ne 0 ]; then
    echo
    echo "    La toolchain en uso no es la fijada. O se instala la fijada, o se sube"
    echo "    la version A PROPOSITO: rust-toolchain.toml y tools/toolchain/fijado.toml"
    echo "    en el mismo commit, y el sysroot rehecho con tools/toolchain/preparar_musl.sh."
    exit 1
fi
exit 0
