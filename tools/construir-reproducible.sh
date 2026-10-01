#!/usr/bin/env bash
#
# Reproducibilidad de los instalables (H-06; grupo `reproducible` de make ci).
#
# QUE MIDE, Y NADA MAS
# --------------------
# Construye DOS VECES los instalables hermeticos con tools/ci/hermetico.sh —la
# lista sale de tools/config/instalables.toml: hoy aegis-agent, aegisctl,
# aegis-watchdog y aegis-fleet— desde el MISMO arbol, en DOS directorios de
# destino distintos y con SOURCE_DATE_EPOCH = fecha del commit, y compara el
# SHA-256 de cada binario. Si uno difiere, lo diagnostica (diffoscope si esta;
# si no, la primera seccion ELF distinta y las cadenas que cambian) y FALLA.
#
# Es reproducibilidad TEMPORAL y EN ESTA MAQUINA: mismo compilador, mismo
# sysroot, mismo BTF, misma ruta del repositorio. NO demuestra:
#   - la reproducibilidad entre maquinas (otro runner, otra ruta, otro rustc);
#   - que los binarios de dist-hermetico/ sean identicos a estos: aquellos se
#     construyen con otra lista de remapeos de ruta (su propio directorio de
#     destino), y sus bytes pueden diferir sin que eso diga nada de estos.
#
# LO QUE HABIA ANTES
# ------------------
# Este script compilaba con rustc un fib.rs de juguete escrito en /tmp, y sin
# rustc en el PATH salia con 0 y «OMITIDA». Ningun instalable se habia
# construido dos veces. Ahora, si falta una pieza (sysroot, cargo, espacio), la
# puerta FALLA diciendo cual.
#
# LOS DOS DIRECTORIOS
# -------------------
#   A  conserva su cache entre tandas: una construccion incremental, como la de
#      quien desarrolla.
#   B  se borra antes y despues: una construccion desde cero.
# Que coincidan dice ademas que la historia de la cache no cambia el resultado.
# Con AEGIS_REPRO_LIMPIO=1 se borra tambien A (dos construcciones en frio).
#
# Las dos construcciones pasan a rustc EXACTAMENTE los mismos flags: los dos
# directorios de destino se remapean a /objetivo en las dos
# (AEGIS_REMAP_OBJETIVOS, ver tools/ci/hermetico.sh). Con flags distintos, una
# diferencia no se podria atribuir al no-determinismo.
#
# COSTE
# -----
# Una construccion hermetica completa (LTO fat, codegen-units=1) en B en cada
# tanda, mas la incremental de A. Disco: dos arboles de destino musl de release;
# se exigen AEGIS_REPRO_ESPACIO_MIN_GB (12 por defecto) libres antes de empezar,
# y B se borra al acabar.
#
# Variables:
#   AEGIS_REPRO_DIR             base de A y B (defecto: $CARGO_TARGET_DIR/reproducible,
#                               o /var/tmp/aegis-reproducible). Sin espacios: el
#                               Makefile de eBPF recibe OUT_DIR sin comillas.
#   AEGIS_REPRO_LIMPIO=1        construir tambien A desde cero.
#   AEGIS_REPRO_ESPACIO_MIN_GB  espacio libre minimo en la base (12).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/ci/_comun.sh"
cd "$RAIZ"

titulo "Reproducibilidad: los instalables hermeticos, construidos dos veces"

# --- Requisitos: si falta algo, FALLO, no omision ---------------------------
paso "herramientas"
for h in cargo rustc git sha256sum readelf cmp awk; do
    if ! hay "$h"; then
        fallo "falta $h: sin el no hay veredicto de reproducibilidad"
        exit 1
    fi
done
ok

# --- Donde ------------------------------------------------------------------
BASE="${AEGIS_REPRO_DIR:-${CARGO_TARGET_DIR:+$CARGO_TARGET_DIR/reproducible}}"
BASE="${BASE:-/var/tmp/aegis-reproducible}"
case "$BASE" in
    /*) ;;
    *) BASE="$RAIZ/$BASE" ;;
esac
case "$BASE" in
    *" "*)
        fallo "la base \"$BASE\" tiene espacios"
        echo "      | el Makefile de eBPF recibe OUT_DIR sin comillas; fija AEGIS_REPRO_DIR"
        exit 1
        ;;
esac
DIR_A="$BASE/a"
DIR_B="$BASE/b"
DIAG="$BASE/diagnostico"
mkdir -p "$BASE" || { fallo "no se puede crear $BASE"; exit 1; }

paso "espacio en $BASE"
MIN_GB="${AEGIS_REPRO_ESPACIO_MIN_GB:-12}"
LIBRE_GB="$(df -Pk "$BASE" | awk 'NR==2 { print int($4 / 1048576) }')"
if [ "${LIBRE_GB:-0}" -lt "$MIN_GB" ]; then
    fallo "quedan ${LIBRE_GB:-0} GiB y hacen falta $MIN_GB (dos arboles de destino de release)"
    exit 1
fi
ok "${LIBRE_GB} GiB libres"

# --- Que se construye -------------------------------------------------------
paso "arbol y fecha de la fuente"
if ! HUELLA_ANTES="$("$RAIZ/tools/huella-arbol.sh")"; then
    fallo "no se pudo calcular la huella del arbol (git no responde sobre $RAIZ)"
    exit 1
fi
if ! SDE="$(git log -1 --format=%ct HEAD 2>/dev/null)" || [ -z "$SDE" ]; then
    fallo "no se pudo leer la fecha del commit para SOURCE_DATE_EPOCH"
    exit 1
fi
COMMIT="$(git rev-parse --short HEAD)"
ok "commit $COMMIT, SOURCE_DATE_EPOCH=$SDE, huella ${HUELLA_ANTES:0:16}"
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "      | el arbol tiene cambios sin comitear: se construye ESTE arbol, no el commit"
fi

rm -rf "$DIR_B" "$DIAG"
if [ "${AEGIS_REPRO_LIMPIO:-0}" = "1" ]; then
    rm -rf "$DIR_A"
fi
if [ -d "$DIR_A" ]; then
    MODO_A="incremental (cache de tandas anteriores)"
else
    MODO_A="desde cero"
fi
MODO_B="desde cero"
# B se borra al salir, pase lo que pase: es lo que mas disco ocupa.
trap 'rm -rf "$DIR_B"' EXIT

construir() {
    local nombre="$1" destino="$2" log="$BASE/construccion-$1.log"
    paso "construccion $nombre ($destino)"
    local inicio=$SECONDS
    if CARGO_TARGET_DIR="$destino" \
        AEGIS_DIST="$destino/dist" \
        AEGIS_REMAP_OBJETIVOS="$DIR_A:$DIR_B" \
        SOURCE_DATE_EPOCH="$SDE" \
        "$RAIZ/tools/ci/hermetico.sh" > "$log" 2>&1; then
        ok "$((SECONDS - inicio)) s"
    else
        fallo "tools/ci/hermetico.sh fallo en la construccion $nombre"
        tail -30 "$log" | sed 's/^/      | /'
        echo "      | (salida completa: $log)"
        exit 1
    fi
}

construir A "$DIR_A"
construir B "$DIR_B"

paso "el arbol no cambio durante la comprobacion"
HUELLA_DESPUES="$("$RAIZ/tools/huella-arbol.sh" || true)"
HA_DIST="$(cat "$DIR_A/dist/HUELLA" 2>/dev/null || true)"
HB_DIST="$(cat "$DIR_B/dist/HUELLA" 2>/dev/null || true)"
if [ "$HUELLA_DESPUES" != "$HUELLA_ANTES" ] || [ "$HA_DIST" != "$HUELLA_ANTES" ] \
    || [ "$HB_DIST" != "$HUELLA_ANTES" ]; then
    fallo "A y B no se construyeron desde el mismo arbol: la comparacion no significaria nada"
    printf '      | antes %s\n      | A     %s\n      | B     %s\n      | despues %s\n' \
        "$HUELLA_ANTES" "$HA_DIST" "$HB_DIST" "$HUELLA_DESPUES"
    exit 1
fi
ok

# --- La comparacion ---------------------------------------------------------
lista() { awk '{ print $2 }' "$1" | sort; }

paso "mismos instalables en A y en B"
if [ ! -s "$DIR_A/dist/SHA256SUMS" ] || [ ! -s "$DIR_B/dist/SHA256SUMS" ]; then
    fallo "falta SHA256SUMS en alguna de las dos construcciones"
    exit 1
fi
if [ "$(lista "$DIR_A/dist/SHA256SUMS")" != "$(lista "$DIR_B/dist/SHA256SUMS")" ]; then
    fallo "A y B no produjeron los mismos binarios"
    diff <(lista "$DIR_A/dist/SHA256SUMS") <(lista "$DIR_B/dist/SHA256SUMS") | sed 's/^/      | /'
    exit 1
fi
mapfile -t BINARIOS < <(lista "$DIR_A/dist/SHA256SUMS")
ok "${BINARIOS[*]}"

paso "SHA-256 de cada instalable, A frente a B"
DISTINTOS=()
for b in "${BINARIOS[@]}"; do
    # Se recalcula sobre los ficheros: SHA256SUMS es de hermetico.sh, y aqui se
    # compara lo que hay en disco.
    ha="$(sha256sum "$DIR_A/dist/$b" | cut -d' ' -f1)"
    hb="$(sha256sum "$DIR_B/dist/$b" | cut -d' ' -f1)"
    if [ "$ha" = "$hb" ]; then
        printf '      | %-16s %s  identico\n' "$b" "$ha"
    else
        printf '      | %-16s DIFIERE\n      |   A %s\n      |   B %s\n' "$b" "$ha" "$hb"
        DISTINTOS+=("$b")
    fi
done

# --- Diagnostico ------------------------------------------------------------
# Secciones con contenido en el fichero: nombre, tipo, desplazamiento y tamano
# (hexadecimal), en el orden de la tabla de secciones.
secciones() {
    readelf -S -W "$1" 2>/dev/null | awk '
        /^ *\[ *[0-9]+\]/ {
            sub(/^ *\[ *[0-9]+\] */, "")
            if ($1 == "NULL" || $2 == "NOBITS") next
            print $1, $2, $4, $5
        }'
}

# SHA-256 de un trozo del fichero.
trozo() {
    tail -c +"$(( $2 + 1 ))" "$1" | head -c "$3" | sha256sum | cut -d' ' -f1
}

diagnosticar() {
    local b="$1" d="$DIAG/$1"
    mkdir -p "$d"
    cp "$DIR_A/dist/$b" "$d/a"
    cp "$DIR_B/dist/$b" "$d/b"
    echo "      | --- $b: diagnostico (copias en $d) ---"

    if hay diffoscope; then
        timeout 900 diffoscope --text "$d/diffoscope.txt" "$d/a" "$d/b" >/dev/null 2>&1
        if [ -s "$d/diffoscope.txt" ]; then
            head -60 "$d/diffoscope.txt" | sed 's/^/      | /'
            echo "      | (informe completo: $d/diffoscope.txt)"
            return
        fi
        echo "      | diffoscope no produjo informe; se sigue con readelf"
    fi

    local primer
    primer="$(cmp "$d/a" "$d/b" 2>&1 | head -1)"
    echo "      | cmp: $primer"
    if ! readelf -h "$d/a" >/dev/null 2>&1; then
        echo "      | no es un ELF legible: no se puede ir mas alla del primer byte"
        return
    fi

    local sa sb
    sa="$(secciones "$d/a")"
    sb="$(secciones "$d/b")"
    if [ "$(awk '{ print $1 }' <<< "$sa")" != "$(awk '{ print $1 }' <<< "$sb")" ]; then
        echo "      | la LISTA de secciones difiere (el enlazado no es el mismo):"
        diff <(awk '{ print $1 }' <<< "$sa") <(awk '{ print $1 }' <<< "$sb") \
            | grep '^[<>]' | head -10 | sed 's/^/      |   /'
    fi

    local primera="" n=0 nombre tipo off tam linea offb tamb ha hb
    while read -r nombre tipo off tam; do
        linea="$(awk -v s="$nombre" '$1 == s { print; exit }' <<< "$sb")"
        [ -z "$linea" ] && continue
        read -r _ _ offb tamb <<< "$linea"
        ha="$(trozo "$d/a" "$((16#$off))" "$((16#$tam))")"
        hb="$(trozo "$d/b" "$((16#$offb))" "$((16#$tamb))")"
        if [ "$ha" != "$hb" ]; then
            n=$((n + 1))
            [ -z "$primera" ] && primera="$nombre"
            printf '      |   %-28s difiere (A %d bytes, B %d bytes)\n' \
                "$nombre" "$((16#$tam))" "$((16#$tamb))"
        fi
    done <<< "$sa"
    if [ -n "$primera" ]; then
        echo "      | primera seccion distinta: $primera ($n en total)"
    else
        echo "      | ninguna seccion con contenido difiere: la diferencia esta en las"
        echo "      | cabeceras o fuera de las secciones (tabla de programa, relleno)"
    fi

    if hay strings; then
        echo "      | cadenas que solo estan en uno de los dos (hasta 15):"
        diff <(strings -a -n 8 "$d/a" | sort -u) <(strings -a -n 8 "$d/b" | sort -u) \
            | grep '^[<>]' | head -15 | sed 's/^/      |   /'
    fi
    echo "      | pistas: una ruta (/root/..., target/..., out/) es un remapeo que falta;"
    echo "      | una fecha, SOURCE_DATE_EPOCH o un build.rs; .note.gnu.build-id difiere"
    echo "      | SIEMPRE que difiere otra cosa (es consecuencia, no causa)."
}

if [ "${#DISTINTOS[@]}" -gt 0 ]; then
    fallo "${#DISTINTOS[@]} de ${#BINARIOS[@]} instalables NO son reproducibles: ${DISTINTOS[*]}"
    for b in "${DISTINTOS[@]}"; do
        diagnosticar "$b"
    done
    echo "      | Hay que arreglar la CAUSA (ver docs/100-procedencia.md); no se"
    echo "      | acepta una lista de binarios exentos."
    exit 1
fi

ok "${#BINARIOS[@]} instalables: mismo SHA-256 en las dos construcciones"
echo "      | A: $MODO_A; B: $MODO_B; commit $COMMIT; $(rustc --version 2>/dev/null)"
echo "      | Medido: reproducibilidad temporal en esta maquina (mismo arbol, dos"
echo "      | directorios de destino, SOURCE_DATE_EPOCH del commit)."
echo "      | No medido: entre maquinas; ni que dist-hermetico/ sea identico a esto."
exit 0
