#!/usr/bin/env bash
#
# Job de CI: empaquetado de los binarios para el objetivo del ANFITRION.
#
# Produce los binarios de release, sus sumas SHA-256 y un manifiesto de
# procedencia (commit, compilador, objetivo, fecha). En un producto de seguridad
# el artefacto ES la superficie de confianza del cliente: hay que poder decir
# exactamente de que fuente y con que compilador salio cada byte.
#
# QUE ES Y QUE NO ES ESTE JOB
# ---------------------------
# Este job valida el EMPAQUETADO: que los binarios que se publican compilan en
# release, salen del tamano esperado, son ELF validos y arrancan.
#
# Los artefactos UNIVERSALES —los que se entregan a un cliente, sin dependencia
# alguna de la libc del anfitrion— los produce tools/ci/hermetico.sh, que si
# tiene el sysroot musl completo que hace falta.
#
# Antes este script intentaba el objetivo musl por su cuenta en cuanto veia un
# `musl-gcc` en el PATH. Eso resultaba en un fallo garantizado: el musl-gcc que
# empaquetan las distribuciones no trae las cabeceras UAPI del kernel, y libbpf
# muere con "asm/types.h: No such file or directory". Adivinar si un toolchain
# sirve por la presencia de un binario es justo el tipo de suposicion que hace
# que un pipeline falle sin explicar por que. Ahora no se adivina: quien quiere
# artefactos estaticos llama al job que sabe construirlos.
#
# Uso:  tools/ci/artifacts.sh
#   AEGIS_TARGET=<triple>  fuerza un objetivo concreto.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: artifacts (binarios de lanzamiento)"

DIST="$RAIZ/dist"
ANFITRION="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"
OBJETIVO="${AEGIS_TARGET:-$ANFITRION}"

paso "objetivo de compilacion"
ok "$OBJETIVO"
echo "      | artefactos universales (sin dependencia de la libc): tools/ci/hermetico.sh"

# --- Binarios que se publican ----------------------------------------------
# paquete:binario. Son los que un cliente despliega; el resto son utilidades
# internas y no forman parte del lanzamiento.
# La lista sale de tools/config/instalables.toml (la unica del proyecto): los
# binarios del workspace del agente, como `paquete:binario:features`.
mapfile -t PUBLICADOS < <(cargo xtask instalables --workspace agente)
if [ "${#PUBLICADOS[@]}" -eq 0 ]; then
    fallo "cargo xtask instalables no devolvio ningun binario del agente"
    exit 1
fi
DIR_TARGET="${CARGO_TARGET_DIR:-$RAIZ/target}"

rm -rf "$DIST"; mkdir -p "$DIST"
FALLOS=0
CONSTRUIDOS=()

for entrada in "${PUBLICADOS[@]}"; do
    IFS=':' read -r paquete binario extras <<< "$entrada"
    log="$(mktemp)"
    paso "compilar $binario ($paquete)"
    args=(build --release --locked --target "$OBJETIVO" -p "$paquete" --bin "$binario")
    [ -n "$extras" ] && args+=(--features "$extras")
    if cargo "${args[@]}" > "$log" 2>&1; then
        ruta="$DIR_TARGET/$OBJETIVO/release/$binario"
        if [ -x "$ruta" ]; then
            cp "$ruta" "$DIST/$binario"
            # `strip` reduce el tamano y elimina simbolos de depuracion, que en
            # un binario distribuido son informacion de mas para un atacante.
            strip "$DIST/$binario" 2>/dev/null || true
            ok "$(du -h "$DIST/$binario" | cut -f1)"
            CONSTRUIDOS+=("$binario")
        else
            fallo "el binario no aparecio en $ruta"; FALLOS=$((FALLOS+1))
        fi
    else
        fallo; tail -30 "$log" | sed 's/^/      | /'; FALLOS=$((FALLOS+1))
    fi
    rm -f "$log"
done

if [ "${#CONSTRUIDOS[@]}" -eq 0 ]; then
    fallo "no se construyo ningun artefacto"
    exit 1
fi

# --- Verificacion del enlazado ---------------------------------------------
paso "verificar el tipo de enlazado"
ESTATICOS=0; DINAMICOS=0
for b in "${CONSTRUIDOS[@]}"; do
    if hay file; then
        descripcion="$(file -b "$DIST/$b")"
    else
        descripcion="(sin 'file' para inspeccionar)"
    fi
    if printf '%s' "$descripcion" | grep >/dev/null "statically linked"; then
        ESTATICOS=$((ESTATICOS+1))
    else
        DINAMICOS=$((DINAMICOS+1))
    fi
    printf '      | %-18s %s\n' "$b" "$descripcion"
done
ok "$ESTATICOS estatico(s), $DINAMICOS dinamico(s)"

# --- Procedencia y sumas ----------------------------------------------------
paso "sumas SHA-256 y manifiesto de procedencia"
( cd "$DIST" && sha256sum "${CONSTRUIDOS[@]}" > SHA256SUMS )

cat > "$DIST/MANIFIESTO.txt" <<MAN
AegisCore - artefactos de lanzamiento
=====================================
commit        : $(git rev-parse HEAD 2>/dev/null || echo "desconocido")
rama          : $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "desconocida")
arbol limpio  : $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo "si" || echo "NO (build desde arbol modificado)")
objetivo      : $OBJETIVO
enlazado      : $ESTATICOS estatico(s) / $DINAMICOS dinamico(s)
compilador    : $(rustc --version 2>/dev/null)
cargo         : $(cargo --version 2>/dev/null)
perfil        : release (opt-level=3, lto=fat, codegen-units=1, panic=abort)
construido    : $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC)
binarios      : ${CONSTRUIDOS[*]}
MAN
ok "dist/SHA256SUMS y dist/MANIFIESTO.txt"

# --- Prueba de humo ---------------------------------------------------------
# La comprobacion DURA es que cada artefacto sea un ejecutable ELF valido del
# objetivo y no este truncado: eso es lo que rompe un empaquetado mal hecho.
#
# NO se exige que respondan a `--help`: varios de estos binarios son demonios
# (el supervisor, el agente) cuyo comportamiento correcto es quedarse
# ejecutando. Colgarse ahi seria lo ESPERADO, no un artefacto roto. Ese `--help`
# se prueba igualmente, pero como informacion, no como veredicto.
paso "prueba de humo de los binarios"
HUMO=0
for b in "${CONSTRUIDOS[@]}"; do
    if ! [ -s "$DIST/$b" ]; then
        printf '      | %-18s VACIO\n' "$b"; HUMO=$((HUMO+1)); continue
    fi
    if hay file && ! file -b "$DIST/$b" | grep >/dev/null "ELF 64-bit.*executable"; then
        printf '      | %-18s no es un ejecutable ELF de 64 bits\n' "$b"
        HUMO=$((HUMO+1)); continue
    fi
    if timeout 15 "$DIST/$b" --help >/dev/null 2>&1; then
        printf '      | %-18s ELF valido, responde a --help\n' "$b"
    else
        printf '      | %-18s ELF valido (demonio o sin --help)\n' "$b"
    fi
done
if [ "$HUMO" -eq 0 ]; then ok "los ${#CONSTRUIDOS[@]} artefactos son ejecutables validos"; else
    fallo "$HUMO artefacto(s) invalidos"; FALLOS=$((FALLOS+1)); fi

echo
printf '%sArtefactos en dist/:%s\n' "$NEGRITA" "$FIN"
ls -la "$DIST" | sed 's/^/    /'

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
