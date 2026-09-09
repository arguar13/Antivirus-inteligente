#!/usr/bin/env bash
#
# Job de CI: construccion de los artefactos finales de lanzamiento.
#
# Produce los binarios de release, sus sumas SHA-256 y un manifiesto de
# procedencia (commit, compilador, objetivo, fecha). En un producto de seguridad
# el artefacto ES la superficie de confianza del cliente: hay que poder decir
# exactamente de que fuente y con que compilador salio cada byte.
#
# Enlazado estatico: se intenta el objetivo musl, que produce binarios sin
# dependencias de la libc del sistema —despliegan en cualquier distribucion, que
# es justo lo que hace falta en una flota heterogenea—. Donde falte el
# compilador cruzado de C (varios crates llevan C: yara-x, ring, libbpf), se cae
# con honestidad al objetivo del anfitrion y se DICE que el binario es dinamico.
#
# Uso:  tools/ci/artifacts.sh
#   AEGIS_TARGET=<triple>  fuerza un objetivo concreto.
#   AEGIS_STATIC=1         exige enlazado estatico (falla si no se consigue).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: artifacts (binarios de lanzamiento)"

DIST="$RAIZ/dist"
MUSL="x86_64-unknown-linux-musl"
ANFITRION="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"

# --- Eleccion del objetivo --------------------------------------------------
elegir_objetivo() {
    if [ -n "${AEGIS_TARGET:-}" ]; then
        echo "$AEGIS_TARGET"; return
    fi
    # musl solo si el objetivo esta instalado Y hay compilador de C cruzado,
    # porque las dependencias con codigo C no enlazan sin el.
    if rustup target list --installed 2>/dev/null | grep -qx "$MUSL" && hay musl-gcc; then
        echo "$MUSL"; return
    fi
    echo "$ANFITRION"
}
OBJETIVO="$(elegir_objetivo)"

paso "objetivo de compilacion"
if [ "$OBJETIVO" = "$MUSL" ]; then
    ok "$OBJETIVO (enlazado estatico)"
else
    ok "$OBJETIVO (enlazado dinamico contra la libc del sistema)"
    if [ "${AEGIS_STATIC:-0}" = "1" ]; then
        fallo "se exigio enlazado estatico pero falta el objetivo musl o musl-gcc"
        echo "      | instala:  rustup target add $MUSL && apt-get install -y musl-tools"
        exit 1
    fi
    if ! rustup target list --installed 2>/dev/null | grep -qx "$MUSL"; then
        omitido "musl no instalado: los binarios dependeran de la libc del sistema"
    elif ! hay musl-gcc; then
        omitido "falta musl-gcc (paquete musl-tools): varias dependencias llevan C"
    fi
fi

# --- Binarios que se publican ----------------------------------------------
# paquete:binario. Son los que un cliente despliega; el resto son utilidades
# internas y no forman parte del lanzamiento.
PUBLICADOS=(
    "aegis-agent:aegis-agent"       # el agente EDR
    "aegis-ctl:aegisctl"            # CLI de administracion local
    "aegis-watchdog:aegis-watchdog" # supervisor de auto-defensa
    "aegis-fleet:aegis-fleet"       # cliente de flota (mTLS)
)

rm -rf "$DIST"; mkdir -p "$DIST"
FALLOS=0
CONSTRUIDOS=()

for entrada in "${PUBLICADOS[@]}"; do
    paquete="${entrada%%:*}"; binario="${entrada##*:}"
    log="$(mktemp)"
    paso "compilar $binario ($paquete)"
    if cargo build --release --locked --target "$OBJETIVO" -p "$paquete" --bin "$binario" \
        > "$log" 2>&1; then
        ruta="target/$OBJETIVO/release/$binario"
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
    if printf '%s' "$descripcion" | grep -q "statically linked"; then
        ESTATICOS=$((ESTATICOS+1))
    else
        DINAMICOS=$((DINAMICOS+1))
    fi
    printf '      | %-18s %s\n' "$b" "$descripcion"
done
ok "$ESTATICOS estatico(s), $DINAMICOS dinamico(s)"

if [ "${AEGIS_STATIC:-0}" = "1" ] && [ "$DINAMICOS" -ne 0 ]; then
    fallo "se exigio enlazado estatico y $DINAMICOS binario(s) salieron dinamicos"
    exit 1
fi

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
    if hay file && ! file -b "$DIST/$b" | grep -q "ELF 64-bit.*executable"; then
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
