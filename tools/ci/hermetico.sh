#!/usr/bin/env bash
#
# Job de CI: construccion hermetica y artefactos universales (FASE 42).
#
# QUE DEMUESTRA
# -------------
# Que el agente que se entrega a un cliente no depende de NADA de la maquina
# donde se compilo. Un EDR se despliega en flotas heterogeneas —RHEL 8, Ubuntu
# 20.04, Debian 12, Alpine, Amazon Linux—, y un binario enlazado contra la glibc
# del runner de CI deja de arrancar en cuanto la libc del endpoint no coincide.
# Ese fallo aparece en el despliegue del cliente, no en el laboratorio.
#
# COMO SE COMPRUEBA
# -----------------
# No basta con mirar la salida de `ldd`. Se inspecciona el ELF y se exige:
#   1. sin PT_INTERP        -> nadie tiene que cargar un enlazador dinamico
#   2. sin DT_NEEDED        -> no pide ninguna biblioteca compartida
#   3. sin RPATH/RUNPATH    -> no busca bibliotecas en rutas del constructor
#   4. sin simbolos dinamicos indefinidos
#   5. y que el binario ARRANCA
#
# Uso:  tools/ci/hermetico.sh
#   AEGIS_PIE=0  produce binarios estaticos NO-PIE (ver mas abajo)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: hermetico (artefactos estaticos universales)"

TRIPLE="x86_64-unknown-linux-musl"
SYSROOT="${AEGIS_MUSL_SYSROOT:-/opt/aegis/musl-sysroot}"
CCWRAP="$SYSROOT/bin/aegis-musl-gcc"
DIST="$RAIZ/dist-hermetico"

# Binarios que se publican, con las caracteristicas que necesita cada uno para
# ser el artefacto REAL. La lista NO se escribe aqui: sale de
# tools/config/instalables.toml, la unica del proyecto, en la forma
# `paquete:binario:features`. Antes habia una copia aqui y otra en
# artifacts.sh, y dos listas de lo mismo acaban diciendo cosas distintas.
mapfile -t PUBLICADOS < <(cargo xtask instalables --hermetico)
if [ "${#PUBLICADOS[@]}" -eq 0 ]; then
    fallo "cargo xtask instalables no devolvio ningun binario hermetico"
    exit 1
fi

# Donde deja cargo los artefactos: respeta CARGO_TARGET_DIR. Suponer `target/`
# hacia que, con el directorio de compilacion fuera del arbol (lo normal en CI),
# un binario construido bien se diera por AUSENTE.
DIR_TARGET="${CARGO_TARGET_DIR:-$RAIZ/target}"

# --- El sysroot -------------------------------------------------------------
paso "sysroot musl"
if [ ! -x "$CCWRAP" ]; then
    # Un FALLO, no una omision. Durante meses esto salia con codigo 0 y la
    # tanda entera decia «verde» sin haber construido ni un artefacto
    # hermetico: una puerta que se salta a si misma cuando le falta una pieza
    # no es una puerta. La matriz de kernels arranca estos binarios en cada
    # distribucion, asi que sin ellos no hay nada que probar.
    fallo "no hay sysroot en $SYSROOT"
    echo "      | construyelo con: tools/toolchain/preparar_musl.sh"
    exit 1
fi
ok "$SYSROOT"

if ! rustup target list --installed 2>/dev/null | grep -qx "$TRIPLE"; then
    fallo "falta el objetivo de Rust $TRIPLE"
    echo "      | instalalo con: rustup target add $TRIPLE"
    exit 1
fi

# --- Modo de enlazado -------------------------------------------------------
#
# Por defecto se produce static-pie y NO estatico a secas. Los dos son igual de
# independientes de la libc del anfitrion; la diferencia es que un binario
# no-PIE se carga siempre en la MISMA direccion y pierde ASLR. En un agente que
# corre como root y procesa datos de un atacante, regalar la aleatorizacion del
# espacio de direcciones para que `ldd` imprima una frase mas bonita es un mal
# negocio: `ldd` dice "statically linked" en un static-pie y "not a dynamic
# executable" en un no-PIE, y las dos significan lo mismo para el despliegue.
#
# Quien necesite la variante no-PIE (por ejemplo para un cargador antiguo que no
# maneje ET_DYN) la obtiene con AEGIS_PIE=0.
PIE="${AEGIS_PIE:-1}"
if [ "$PIE" = "1" ]; then
    MODO="static-pie (con ASLR)"
    FLAGS_EXTRA=""
else
    MODO="estatico no-PIE (sin ASLR)"
    FLAGS_EXTRA="-C relocation-model=static"
fi
paso "modo de enlazado"
ok "$MODO"

export CC_x86_64_unknown_linux_musl="$CCWRAP"
export AR_x86_64_unknown_linux_musl="ar"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$CCWRAP"
# link-self-contained=no: los objetos de arranque, la libc, libm y el
# desenrollador salen TODOS del sysroot. Con el valor por defecto, rustc anade
# ademas SU copia de musl y quedan dos libc en la misma linea de enlace.
export RUSTFLAGS="-C link-self-contained=no $FLAGS_EXTRA"

rm -rf "$DIST"; mkdir -p "$DIST"
FALLOS=0
CONSTRUIDOS=()

for entrada in "${PUBLICADOS[@]}"; do
    IFS=':' read -r paquete binario extras <<< "$entrada"
    log="$(mktemp)"
    paso "compilar $binario"
    args=(build --release --locked --target "$TRIPLE" -p "$paquete" --bin "$binario")
    [ -n "$extras" ] && args+=(--features "$extras")
    if cargo "${args[@]}" > "$log" 2>&1; then
        ruta="$DIR_TARGET/$TRIPLE/release/$binario"
        if [ -x "$ruta" ]; then
            cp "$ruta" "$DIST/$binario"
            ok "$(du -h "$DIST/$binario" | cut -f1)"
            CONSTRUIDOS+=("$binario")
        else
            fallo "el binario no aparecio en $ruta"; FALLOS=$((FALLOS+1))
        fi
    else
        fallo; tail -25 "$log" | sed 's/^/      | /'; FALLOS=$((FALLOS+1))
    fi
    rm -f "$log"
done

if [ "${#CONSTRUIDOS[@]}" -eq 0 ]; then
    fallo "no se construyo ningun artefacto hermetico"
    exit 1
fi

# --- La comprobacion que importa -------------------------------------------
paso "independencia de la libc del anfitrion"
IMPUROS=0
for b in "${CONSTRUIDOS[@]}"; do
    ruta="$DIST/$b"
    problemas=""

    if readelf -l "$ruta" 2>/dev/null | grep -q "INTERP"; then
        problemas="$problemas PT_INTERP"
    fi
    dinamicas="$(readelf -d "$ruta" 2>/dev/null | grep -cE "\(NEEDED\)" || true)"
    [ "${dinamicas:-0}" -gt 0 ] && problemas="$problemas ${dinamicas}xNEEDED"
    if readelf -d "$ruta" 2>/dev/null | grep -qE "\(RPATH\)|\(RUNPATH\)"; then
        problemas="$problemas RPATH"
    fi
    # El simbolo nulo del indice 0 siempre es UND: no cuenta.
    und="$(readelf --dyn-syms "$ruta" 2>/dev/null | awk '$7=="UND" && $8!="" {n++} END{print n+0}')"
    [ "${und:-0}" -gt 0 ] && problemas="$problemas ${und}xUND"

    if [ -n "$problemas" ]; then
        printf '      | %-18s DEPENDE DEL ANFITRION:%s\n' "$b" "$problemas"
        IMPUROS=$((IMPUROS+1))
    else
        printf '      | %-18s sin interprete, sin NEEDED, sin UND\n' "$b"
    fi
done
if [ "$IMPUROS" -eq 0 ]; then
    ok "los ${#CONSTRUIDOS[@]} artefactos son autonomos"
else
    fallo "$IMPUROS artefacto(s) arrastran dependencias del anfitrion"
    FALLOS=$((FALLOS+1))
fi

paso "veredicto de las herramientas del sistema"
for b in "${CONSTRUIDOS[@]}"; do
    printf '      | %-18s ldd: %-26s file: %s\n' "$b" \
        "$(ldd "$DIST/$b" 2>&1 | tr -d '\n\t' | head -c 26)" \
        "$(file -b "$DIST/$b" | cut -d, -f1-4)"
done
ok

# --- Que ademas arranquen ---------------------------------------------------
# Un ELF puede cumplir todo lo anterior y no ejecutarse (objetos de arranque
# mal casados, TLS roto). Se comprueba ejecutandolos.
paso "los artefactos arrancan"
MUERTOS=0
for b in "${CONSTRUIDOS[@]}"; do
    salida="$(timeout 20 "$DIST/$b" --help 2>&1)"
    codigo=$?
    # 124 = timeout: es un demonio y quedarse corriendo es lo correcto.
    if [ "$codigo" -eq 0 ] || [ "$codigo" -eq 124 ] || [ -n "$salida" ]; then
        printf '      | %-18s arranca (codigo %d)\n' "$b" "$codigo"
    else
        printf '      | %-18s NO ARRANCA (codigo %d)\n' "$b" "$codigo"
        MUERTOS=$((MUERTOS+1))
    fi
done
if [ "$MUERTOS" -eq 0 ]; then ok "todos ejecutan"; else
    fallo "$MUERTOS artefacto(s) no ejecutan"; FALLOS=$((FALLOS+1)); fi

# --- Procedencia ------------------------------------------------------------
paso "sumas y manifiesto"
( cd "$DIST" && sha256sum "${CONSTRUIDOS[@]}" > SHA256SUMS )
cat > "$DIST/MANIFIESTO.txt" <<MAN
AegisCore - artefactos hermeticos
=================================
commit        : $(git rev-parse HEAD 2>/dev/null || echo "desconocido")
arbol limpio  : $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo "si" || echo "NO")
objetivo      : $TRIPLE
enlazado      : $MODO
sysroot       : $SYSROOT
compilador C  : $($CCWRAP --version 2>/dev/null | head -1)
compilador    : $(rustc --version 2>/dev/null)
construido    : $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC)
binarios      : ${CONSTRUIDOS[*]}
MAN
ok "dist-hermetico/SHA256SUMS y MANIFIESTO.txt"

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
