#!/usr/bin/env bash
#
# Lectura de tools/toolchain/fijado.toml y del SELLO de un sysroot musl.
#
# Se carga con `source`. Es la UNICA definicion de como se leen las versiones
# fijadas y de como se calcula la huella de un sysroot: la usan la receta que lo
# construye (preparar_musl.sh) y la puerta que lo comprueba
# (comprobar_toolchain.sh). Dos copias de la huella acabarian calculando cosas
# distintas y la puerta daria por bueno un sysroot que no es el sellado.
#
# fijado.toml se lee con awk y no con un analizador de TOML porque este fichero
# tiene que funcionar tambien dentro de la imagen hermetica mientras se construye
# el sysroot, antes de que haya nada mas instalado. Por eso su formato esta
# limitado a `[seccion]` y `clave = "valor"` (lo dice su cabecera).

FIJADO_TOML="${FIJADO_TOML:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fijado.toml}"

# fijado_valor <seccion> <clave> [fichero]: imprime el valor; falla si no esta.
fijado_valor() {
    awk -v s="$1" -v k="$2" '
        { l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+$/, "", l) }
        l ~ /^\[/ { sub(/[[:space:]]*#.*$/, "", l); en = (l == "[" s "]"); next }
        en && index(l, k) == 1 {
            r = substr(l, length(k) + 1)
            if (r ~ /^[[:space:]]*=[[:space:]]*"/) {
                sub(/^[[:space:]]*=[[:space:]]*"/, "", r); sub(/".*$/, "", r)
                print r; hallado = 1; exit
            }
        }
        END { exit hallado ? 0 : 1 }
    ' "${3:-$FIJADO_TOML}"
}

# fijado_claves <seccion> [fichero]: las claves de una seccion, en su orden.
fijado_claves() {
    awk -v s="$1" '
        { l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+$/, "", l) }
        l ~ /^\[/ { sub(/[[:space:]]*#.*$/, "", l); en = (l == "[" s "]"); next }
        en && l ~ /^[A-Za-z0-9_.-]+[[:space:]]*=/ { sub(/[[:space:]]*=.*$/, "", l); print l }
    ' "${2:-$FIJADO_TOML}"
}

# fijado_version_paquete <paquete>: version instalada, de la arquitectura nativa.
# Sin la arquitectura, un paquete multiarquitectura (linux-libc-dev esta para
# amd64 y para arm64, por la matriz de kernels) imprime las dos versiones pegadas.
fijado_version_paquete() {
    local arq
    arq="$(dpkg --print-architecture 2>/dev/null)" || return 1
    dpkg-query -W -f='${Version}\n' "$1:$arq" 2>/dev/null | head -n 1
}

# fijado_desvios_paquetes: imprime cada paquete de [sysroot-musl] cuya version
# instalada no es la fijada, y falla si hay alguno.
fijado_desvios_paquetes() {
    if ! command -v dpkg-query >/dev/null 2>&1; then
        echo "sin dpkg-query: las versiones fijadas son paquetes de $(fijado_valor sysroot-musl distribucion)"
        return 1
    fi
    local p esperado real malos=0
    for p in $(fijado_claves sysroot-musl); do
        [ "$p" = "distribucion" ] && continue
        esperado="$(fijado_valor sysroot-musl "$p")"
        real="$(fijado_version_paquete "$p")"
        if [ "$real" != "$esperado" ]; then
            printf '%-28s fijado %s, instalado %s\n' "$p" "$esperado" "${real:-(ninguno)}"
            malos=$((malos + 1))
        fi
    done
    [ "$malos" -eq 0 ]
}

# fijado_huella_arbol <dir>: SHA-256 del contenido de un arbol (sin su SELLO).
# Cuenta el contenido de cada fichero y el destino de cada enlace, en orden fijo.
fijado_huella_arbol() {
    [ -d "$1" ] || return 1
    (
        cd "$1" || exit 1
        {
            find . -path ./SELLO -prune -o -type f -print0 \
                | LC_ALL=C sort -z | xargs -0 -r sha256sum
            find . -type l -print0 | LC_ALL=C sort -z \
                | while IFS= read -r -d '' e; do
                      printf 'enlace %s -> %s\n' "$e" "$(readlink "$e")"
                  done
        } | sha256sum | cut -d' ' -f1
    )
}

# fijado_sello_valor <fichero-sello> <clave>: el SELLO es `clave=valor` por linea.
fijado_sello_valor() {
    awk -v k="$2" '
        index($0, k "=") == 1 { print substr($0, length(k) + 2); hallado = 1; exit }
        END { exit hallado ? 0 : 1 }
    ' "$1"
}

# fijado_escribir_sello <sysroot> <receta>: graba de que se construyo el sysroot
# (la receta por su SHA-256, el rustc del que sale la libunwind, las versiones de
# los paquetes) y la huella del arbol resultante. Se llama al final de la receta,
# con el sysroot ya verificado.
fijado_escribir_sello() {
    local dir="$1" receta="$2" arbol p
    arbol="$(fijado_huella_arbol "$dir")" || return 1
    {
        echo "formato=1"
        echo "receta=$(sha256sum < "$receta" | cut -d' ' -f1)"
        echo "rustc=$(rustc --version 2>/dev/null)"
        for p in $(fijado_claves sysroot-musl); do
            [ "$p" = "distribucion" ] && continue
            echo "paquete.$p=$(fijado_version_paquete "$p")"
        done
        echo "construido=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "arbol=$arbol"
    } > "$dir/SELLO"
}
