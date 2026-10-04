#!/usr/bin/env bash
#
# AegisCore - construccion del sysroot musl (FASE 42).
#
# EL PROBLEMA QUE RESUELVE
# -----------------------
# El `musl-gcc` que empaquetan las distribuciones no es un toolchain cruzado
# completo: es gcc con un fichero de `specs` que lo apunta a las cabeceras y
# las bibliotecas de musl. Ese sysroot contiene la libc... y NADA MAS. No trae
# las cabeceras UAPI del kernel (`linux/`, `asm/`, `asm-generic/`), asi que en
# cuanto una dependencia con codigo C incluye <asm/unistd.h> —libbpf lo hace en
# la primera linea— la compilacion muere con:
#
#     bpf.c:28:10: fatal error: asm/unistd.h: No such file or directory
#
# LA SOLUCION QUE **NO** SE APLICA
# --------------------------------
# Anadir `-I/usr/include/x86_64-linux-gnu` a CFLAGS "hace que compile". Es un
# parche y es peligroso: ese directorio es el multiarch de GLIBC, y ademas de
# `asm/` contiene `bits/`, `gnu/` y `sys/`. Con el en la ruta de busqueda, las
# cabeceras de glibc entran en una compilacion contra musl. El binario resultante
# mezcla dos ABIs de libc distintas: puede enlazar, puede incluso arrancar, y
# fallar mas tarde con corrupcion silenciosa en `struct stat`, en `errno` o en
# los tipos de tiempo. En un producto de seguridad eso es inaceptable.
#
# LA SOLUCION CORRECTA
# --------------------
# Componer un sysroot musl COMPLETO, que es exactamente lo que produce un
# toolchain cruzado de verdad:
#
#   sysroot/include/  =  cabeceras de musl          (la libc)
#                     +  cabeceras UAPI del kernel  (linux/ asm/ asm-generic/)
#   sysroot/lib/      =  crt*.o, libc.a de musl
#
# Las cabeceras UAPI son INDEPENDIENTES de la libc por definicion —son la salida
# de `make headers_install` del kernel, que el paquete `linux-libc-dev`
# empaqueta—, asi que combinarlas con musl es correcto y es lo que hace
# cualquier toolchain musl serio. Lo que no se combina jamas es la libc.
#
# El sysroot queda AUTOCONTENIDO (copias, no enlaces), de modo que se puede
# fijar, empaquetar y auditar como una unidad reproducible.
#
# Uso:  tools/toolchain/preparar_musl.sh [--verificar]
#   AEGIS_MUSL_SYSROOT=<ruta>  destino (por defecto /opt/aegis/musl-sysroot)
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$RAIZ/tools/ci/_comun.sh"
source "$RAIZ/tools/toolchain/fijado.sh"
# Desde la raiz: rustup elige el rustc por rust-toolchain.toml, y la libunwind
# que se copia al sysroot tiene que salir del rustc fijado.
cd "$RAIZ" || exit 1

SYSROOT="${AEGIS_MUSL_SYSROOT:-/opt/aegis/musl-sysroot}"

# `grep -q` cierra la tuberia en cuanto encuentra la primera coincidencia. El
# proceso de la izquierda recibe entonces SIGPIPE y termina con codigo distinto
# de cero, y con `pipefail` activo ESO hace fallar la tuberia entera aunque la
# coincidencia se haya encontrado. Es un error clasico y silencioso: la
# comprobacion informa de lo contrario de lo que observo.
#
# `contiene` hace la busqueda sobre una cadena YA capturada, asi que no queda
# ningun proceso a la izquierda al que SIGPIPE pueda tumbar.
contiene() {  # contiene <texto> <patron-extendido>
    printf '%s' "$1" | grep >/dev/null -E -- "$2" && return 0 || return 1
}
TRIPLE_MUSL="x86_64-linux-musl"
TRIPLE_RUST="x86_64-unknown-linux-musl"

# Origenes. Se declaran arriba para que una distribucion distinta se adapte
# cambiando solo estas rutas.
MUSL_INC="/usr/include/$TRIPLE_MUSL"
MUSL_LIB="/usr/lib/$TRIPLE_MUSL"
UAPI_LINUX="/usr/include/linux"
UAPI_GENERIC="/usr/include/asm-generic"
UAPI_ASM="/usr/include/x86_64-linux-gnu/asm"

titulo "Sysroot musl para $TRIPLE_RUST"

# --- Comprobacion de los ingredientes --------------------------------------
faltan=0
comprobar_dir() {
    if [ -d "$1" ]; then
        return 0
    fi
    fallo "falta $1"
    echo "      | instala: $2"
    faltan=$((faltan + 1))
}

paso "ingredientes del sysroot"
comprobar_dir "$MUSL_INC"    "apt-get install -y musl-dev musl-tools"
comprobar_dir "$MUSL_LIB"    "apt-get install -y musl-dev musl-tools"
comprobar_dir "$UAPI_LINUX"  "apt-get install -y linux-libc-dev"
comprobar_dir "$UAPI_GENERIC" "apt-get install -y linux-libc-dev"
comprobar_dir "$UAPI_ASM"    "apt-get install -y linux-libc-dev"
if ! hay musl-gcc; then
    fallo "falta musl-gcc"; echo "      | instala: apt-get install -y musl-tools"
    faltan=$((faltan + 1))
fi
[ "$faltan" -eq 0 ] || exit 1
ok "musl-dev, musl-tools y linux-libc-dev presentes"

# --- Versiones fijadas -------------------------------------------------------
# El sysroot se compone SOLO con las versiones de tools/toolchain/fijado.toml. Un
# `apt upgrade` que cambie musl, las cabeceras del kernel o el compilador cambia
# el binario que se entrega: si pasa, se ve aqui y se decide subiendo la version
# fijada, no en silencio.
paso "versiones fijadas (tools/toolchain/fijado.toml)"
if ! desvios="$(fijado_desvios_paquetes)"; then
    fallo "los paquetes de este sistema no son los fijados"
    printf '%s\n' "$desvios" | sed 's/^/      | /'
    exit 1
fi
ok "paquetes de $(fijado_valor sysroot-musl distribucion) en la version fijada"

# --- Composicion ------------------------------------------------------------
paso "componer $SYSROOT"
rm -rf "$SYSROOT"
mkdir -p "$SYSROOT/include" "$SYSROOT/lib"

# 1. La libc. Primero, para que si algo de lo demas colisionara se viera al
#    copiar y no en tiempo de compilacion.
cp -a "$MUSL_INC/." "$SYSROOT/include/"
cp -a "$MUSL_LIB/." "$SYSROOT/lib/"

# 2. Las cabeceras UAPI del kernel. NUNCA el multiarch de glibc entero: solo
#    los tres arboles que el kernel exporta.
for src in "$UAPI_LINUX" "$UAPI_GENERIC" "$UAPI_ASM"; do
    destino="$SYSROOT/include/$(basename "$src")"
    if [ -e "$destino" ]; then
        fallo "colision: $destino ya existe (musl no deberia traerlo)"
        exit 1
    fi
    cp -a "$src" "$destino"
done
ok "libc de musl + UAPI del kernel (linux/, asm/, asm-generic/)"

# --- Barrera contra contaminacion de glibc ---------------------------------
# Si una sola cabecera de glibc se hubiera colado, el sysroot no sirve. Se
# comprueba por marcadores que solo existen en glibc.
paso "barrera anti-glibc"
contaminacion=0
for marcador in gnu/stubs.h gnu/libc-version.h bits/libc-header-start.h; do
    if [ -e "$SYSROOT/include/$marcador" ]; then
        fallo "cabecera de glibc en el sysroot: $marcador"
        contaminacion=$((contaminacion + 1))
    fi
done
# El features.h que quede tiene que ser el de musl, no el de glibc.
if [ -e "$SYSROOT/include/features.h" ] && grep -Eq "__GLIBC__" "$SYSROOT/include/features.h" 2>/dev/null; then
    fallo "features.h del sysroot define __GLIBC__: es el de glibc"
    contaminacion=$((contaminacion + 1))
fi
[ "$contaminacion" -eq 0 ] || exit 1
ok "sin rastro de glibc"

# --- Envoltorio del compilador ---------------------------------------------
# Se genera un `specs` propio en vez de reutilizar el de la distribucion: asi el
# sysroot es la UNICA fuente de cabeceras y bibliotecas, y el resultado no
# depende de que /usr/include/x86_64-linux-musl siga existiendo ni de que la
# distribucion cambie su specs en una actualizacion.
paso "envoltorio del compilador"
SPECS="$SYSROOT/aegis-musl.specs"
# El `specs` se DERIVA del que instala la distribucion, sustituyendo sus rutas
# por las del sysroot. Derivarlo en vez de escribirlo a mano es deliberado: el
# formato de `specs` de gcc es posicional y fragil (un espacio de mas dentro de
# un `%{...}` y gcc aborta con "specs file malformed"), y ademas la distribucion
# es quien sabe que ficheros de arranque y que enlazador dinamico corresponden a
# SU musl. Aqui solo se cambia DONDE estan, no QUE son.
SPECS_ORIGEN="$MUSL_LIB/musl-gcc.specs"
if [ ! -f "$SPECS_ORIGEN" ]; then
    fallo "no aparece $SPECS_ORIGEN (paquete musl-tools)"
    exit 1
fi
sed -e "s#$MUSL_INC#$SYSROOT/include#g" \
    -e "s#$MUSL_LIB#$SYSROOT/lib#g" \
    "$SPECS_ORIGEN" > "$SPECS"

# Comprobacion de que la sustitucion fue completa: si quedara una ruta del
# sistema, el sysroot no seria autocontenido y la compilacion volveria a mezclar
# origenes sin avisar.
if grep -nE "/usr/(include|lib)/x86_64-linux-musl" "$SPECS"; then
    fallo "el specs derivado sigue apuntando fuera del sysroot"
    exit 1
fi

CCWRAP="$SYSROOT/bin/aegis-musl-gcc"
mkdir -p "$SYSROOT/bin"
cat > "$CCWRAP" <<WRAP
#!/bin/sh
# Compilador C del sysroot musl de AegisCore. Todas las cabeceras y todas las
# bibliotecas salen de $SYSROOT; nada del sistema anfitrion entra.
exec "\${REALGCC:-x86_64-linux-gnu-gcc}" "\$@" -specs "$SPECS"
WRAP
chmod 0755 "$CCWRAP"
ok "$CCWRAP"

# --- Complementos: las extensiones GNU que musl no implementa ---------------
#
# elfutils —del que depende libbpf para leer ELF— usa APIs que son extensiones
# de GNU: `argp_parse` y `obstack`. glibc las trae; musl NO. Su `configure`
# aborta con "failed to find argp_parse" / "failed to find _obstack_free" y ahi
# se acaba la construccion estatica.
#
# La solucion correcta —y la que usa Alpine Linux para empaquetar elfutils sobre
# musl— es aportar esas funciones como bibliotecas independientes, compiladas
# contra ESTE sysroot e instaladas DENTRO de el, de forma que los
# `AC_SEARCH_LIBS` de elfutils las encuentren igual que encontrarian las de
# glibc.
#
# Lo que NO se hace: parchear elfutils, desactivar comprobaciones de su
# configure, ni sustituir libelf por otra cosa. El agujero es la ausencia de
# unas funciones concretas; lo que corresponde es aportarlas.
#
# Cada complemento se fija por ETIQUETA y por COMMIT. La etiqueta se puede
# mover; el commit no. Si el repositorio de origen cambiara bajo nuestros pies,
# la construccion se detiene en vez de compilar codigo distinto en silencio.
CACHE="${AEGIS_MUSL_CACHE:-/opt/aegis/cache}"

# nombre | repositorio | etiqueta | commit | cabeceras a instalar
COMPLEMENTOS=(
  "argp-standalone|https://github.com/argp-standalone/argp-standalone|1.5.0|b931da3e7e9a999b0d9515c087488e96821845fb|argp.h"
  "musl-obstack|https://github.com/void-linux/musl-obstack|v1.2.3|f4385255be1615688c6a5f042277304d7ab288b1|obstack.h"
)

construir_complemento() {
    local nombre="$1" repo="$2" etiqueta="$3" commit="$4" cabeceras="$5"
    local src="$CACHE/$nombre-$etiqueta"

    paso "$nombre $etiqueta"
    if [ ! -d "$src/.git" ]; then
        mkdir -p "$CACHE"
        if ! git clone --quiet --depth 1 -b "$etiqueta" "$repo" "$src" 2>/dev/null; then
            fallo "no se pudo obtener $repo ($etiqueta)"
            echo "      | sin red: clona el repositorio en $src y repite"
            return 1
        fi
    fi
    local obtenido
    obtenido="$(git -C "$src" rev-parse HEAD 2>/dev/null)"
    if [ "$obtenido" != "$commit" ]; then
        fallo "$nombre no esta en el commit fijado"
        echo "      | esperado: $commit"
        echo "      | obtenido: $obtenido"
        return 1
    fi

    local log; log="$(mktemp)"
    if ! (
        cd "$src" &&
        autoreconf -i &&
        ./configure --host=x86_64-linux-musl --enable-static --disable-shared \
            CC="$CCWRAP" CFLAGS="-O2 -fPIC" &&
        make -j"$(nproc)"
    ) > "$log" 2>&1; then
        fallo "$nombre no compila contra el sysroot"
        tail -25 "$log" | sed 's/^/      | /'
        rm -f "$log"; return 1
    fi
    rm -f "$log"

    # El archivo estatico puede quedar en la raiz o bajo .libs/ segun use
    # libtool. Se busca en vez de suponerlo.
    local archivo
    archivo="$(find "$src" -name '*.a' -newer "$src/configure" 2>/dev/null | head -1)"
    if [ -z "$archivo" ]; then
        fallo "$nombre compilo pero no produjo ningun archivo estatico"
        return 1
    fi
    install -m 0644 "$archivo" "$SYSROOT/lib/$(basename "$archivo")"
    local h
    for h in $cabeceras; do
        if [ ! -f "$src/$h" ]; then
            fallo "$nombre no trae la cabecera $h"
            return 1
        fi
        install -m 0644 "$src/$h" "$SYSROOT/include/$h"
    done
    ok "$(basename "$archivo") y $cabeceras instalados en el sysroot"
    return 0
}

for entrada in "${COMPLEMENTOS[@]}"; do
    IFS='|' read -r c_nombre c_repo c_tag c_commit c_hdrs <<< "$entrada"
    construir_complemento "$c_nombre" "$c_repo" "$c_tag" "$c_commit" "$c_hdrs" || exit 1
done

# --- El desenrollador de excepciones ----------------------------------------
#
# Rust enlaza `-lunwind` en el objetivo musl: necesita los simbolos `_Unwind_*`
# del ABI de Itanium. El sysroot tiene que aportarlos, porque la alternativa
# —dejar que rustc use su directorio `self-contained`— mete SU copia de musl en
# la linea de enlace junto a la del sysroot: dos libc distintas y un resultado
# que depende del orden de los `-L`.
#
# EL CAMINO QUE SE PROBO Y NO SIRVE
# ---------------------------------
# El desenrollador "natural" de un toolchain gcc es `libgcc_eh.a`. El que
# instala la distribucion NO vale: esta compilado contra glibc y llama a
# `_dl_find_object`, una API que glibc anadio en 2.35 y que musl no tiene. El
# enlace muere con:
#
#     libgcc_eh.a(unwind-dw2-fde-dip.o): undefined reference to `_dl_find_object'
#
# Un `libgcc_eh` valido para musl solo sale de un gcc construido CONTRA musl
# (lo que hace musl-cross-make), no del gcc del sistema.
#
# EL DESENROLLADOR CORRECTO
# -------------------------
# El propio toolchain de Rust distribuye, para el objetivo musl, la libunwind de
# LLVM ya compilada contra musl. Es exactamente la pieza que falta, es la que
# rustc espera encontrar, y viene emparejada con el compilador con el que se va
# a construir. Se copia al sysroot y se COMPRUEBA que cumple dos cosas:
#
#   1. que define los simbolos `_Unwind_*`, y
#   2. que no referencia ningun simbolo exclusivo de glibc.
#
# La segunda comprobacion es la que habria cazado el intento anterior antes de
# llegar al enlazador, y por eso se queda aqui de forma permanente.
paso "desenrollador de excepciones"
RUSTC_SYSROOT="$(rustc --print sysroot 2>/dev/null)"
UNWIND_RUST="$RUSTC_SYSROOT/lib/rustlib/$TRIPLE_RUST/lib/self-contained/libunwind.a"
if [ ! -f "$UNWIND_RUST" ]; then
    fallo "no aparece $UNWIND_RUST"
    echo "      | instala el objetivo: rustup target add $TRIPLE_RUST"
    exit 1
fi

SIMBOLOS_DEF="$(nm --defined-only "$UNWIND_RUST" 2>/dev/null || true)"
if ! contiene "$SIMBOLOS_DEF" "_Unwind_RaiseException"; then
    fallo "$UNWIND_RUST no define los simbolos _Unwind_*"
    exit 1
fi

# Simbolos que solo existen en glibc. Si el desenrollador dependiera de alguno,
# el binario no seria portable por mucho que enlazara aqui.
SIMBOLOS_UND="$(nm --undefined-only "$UNWIND_RUST" 2>/dev/null || true)"
glibcismos=0
for simbolo in _dl_find_object __libc_start_main _dl_iterate_phdr __gnu_get_libc_version; do
    if contiene "$SIMBOLOS_UND" "[[:space:]]U[[:space:]]+$simbolo\$"; then
        fallo "el desenrollador depende de un simbolo de glibc: $simbolo"
        glibcismos=$((glibcismos + 1))
    fi
done
[ "$glibcismos" -eq 0 ] || exit 1

install -m 0644 "$UNWIND_RUST" "$SYSROOT/lib/libunwind.a"
ok "libunwind de LLVM para musl ($(rustc --version | awk '{print $2}'))"

# --- Verificacion: que compile Y que el binario sea estatico de verdad -----
paso "verificacion del toolchain"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/prueba.c" <<'C'
/* Toca las tres piezas a la vez: la libc (stdio), la UAPI del kernel
 * (asm/unistd.h, que es la cabecera exacta con la que moria libbpf) y una
 * llamada al sistema real, para que el binario no sea trivialmente optimizable. */
#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include <argp.h>

/* argp_parse tiene que RESOLVERSE al enlazar, no solo declararse: la
 * comprobacion de elfutils es exactamente esa. */
static error_t nada(int clave, char *arg, struct argp_state *st) {
    (void)clave; (void)arg; (void)st;
    return ARGP_ERR_UNKNOWN;
}

int main(void) {
    static const struct argp ap = { 0, nada, 0, 0, 0, 0, 0 };
    int idx = 0;
    char *argv0[] = { (char *)"prueba", 0 };
    (void)argp_parse(&ap, 1, argv0, ARGP_SILENT | ARGP_NO_EXIT, &idx, 0);
    printf("__NR_bpf=%d pid=%d argp=ok\n", (int)__NR_bpf, (int)getpid());
    return 0;
}
C
if ! "$CCWRAP" -static -O2 -o "$TMP/prueba" "$TMP/prueba.c" -largp 2> "$TMP/err"; then
    fallo "el sysroot no compila un programa que use libc + UAPI"
    sed 's/^/      | /' "$TMP/err"
    exit 1
fi
descripcion="$(file -b "$TMP/prueba" 2>/dev/null || echo "?")"
if ! contiene "$descripcion" "statically linked"; then
    fallo "el binario de prueba no salio estatico: $descripcion"
    exit 1
fi
SALIDA_LDD="$(ldd "$TMP/prueba" 2>&1 || true)"
if ! contiene "$SALIDA_LDD" "not a dynamic executable"; then
    fallo "ldd encuentra dependencias dinamicas en el binario de prueba"
    printf '%s\n' "$SALIDA_LDD" | sed 's/^/      | /'
    exit 1
fi
salida="$("$TMP/prueba" 2>&1)"
if ! contiene "$salida" "__NR_bpf=321 .*argp=ok"; then
    fallo "el binario de prueba no se ejecuta o la UAPI no cuadra: $salida"
    exit 1
fi
ok "compila, enlaza estatico y ejecuta ($salida)"

# --- Sello ------------------------------------------------------------------
# De que se construyo este sysroot y que huella tiene. tools/ci/hermetico.sh no
# construye nada con un sysroot sin sello, sellado por otra receta o con otras
# versiones, o cuyo arbol haya cambiado despues de sellarlo. Por eso CUALQUIER
# cambio de este fichero obliga a rehacer el sysroot.
paso "sello del sysroot"
if ! fijado_escribir_sello "$SYSROOT" "$RAIZ/tools/toolchain/preparar_musl.sh"; then
    fallo "no se pudo escribir $SYSROOT/SELLO"
    exit 1
fi
ok "$SYSROOT/SELLO (arbol $(fijado_sello_valor "$SYSROOT/SELLO" arbol | cut -c1-16)...)"

echo
printf '%sSysroot listo.%s Exporta para cargo:\n' "$NEGRITA" "$FIN"
cat <<USO
    export AEGIS_MUSL_SYSROOT=$SYSROOT
    export CC_${TRIPLE_RUST//-/_}=$CCWRAP
    export AR_${TRIPLE_RUST//-/_}=ar
USO
