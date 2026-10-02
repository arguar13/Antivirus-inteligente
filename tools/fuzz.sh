#!/usr/bin/env bash
#
# Fuzzing continuo de AegisCore (FASE 35; objetivos del trabajador, FASE 1 del
# MP-16).
#
# Corre cada objetivo de libFuzzer un tiempo acotado sobre los parsers que
# reciben entrada no confiable: protobuf de flota, DER de certificados, tramas
# RPC, event log TCG, variables UEFI, /proc/maps, AegisQL y TODO lo que corre en
# el trabajador confinado (ELF, PE, Mach-O, modelo, desensamblador, emulador y
# su protocolo). La invariante es simple y dura: NINGUN parser entra en panico,
# se cuelga o agota la memoria ante entrada arbitraria.
#
# Uso:  tools/fuzz.sh [SEGUNDOS_POR_OBJETIVO]
#   Por defecto 30 s/objetivo. make ci corre los del trabajador unos segundos
#   (grupo `trabajador`); la ejecucion nocturna de la forja, diez minutos cada
#   uno (.forgejo/workflows/fuzz-nocturno.yml).
#
#   FUZZ_OBJETIVOS="a b"   solo esos objetivos (acepta comodines: trabajador_*)
#   AEGIS_EXIGIR_FUZZ=1    sin toolchain de fuzzing, FALLA en vez de omitir
#
# Codigo de salida 0 si ningun objetivo encuentra un fallo; 1 si alguno lo hace.
#
# EL TOOLCHAIN ESTA FIJADO. libFuzzer y el sanitizador exigen nightly, y un
# nightly sin fecha es otro compilador cada dia: la version esta en
# tools/toolchain/nightly-fuzz.txt y el runner la instala
# (deploy/ci/instalar-runner.sh). Antes el script tomaba «el nightly que
# hubiera» y, sin ninguno, se OMITIA con codigo 0: en la maquina de desarrollo el
# fuzzing no se habia ejecutado nunca y la tanda salia verde (FASE 1 del MP-16).
#
# CUANDO ENCUENTRA ALGO: el caso queda en fuzz/artifacts/<objetivo>/. Se arregla
# el parser y el caso se copia a fuzz/semillas/<objetivo>/, donde la prueba
# `crates/aegis-trabajador/tests/fuzzing.rs` lo pasa por el analizador en cada
# `cargo test`: el hallazgo se convierte en regresion.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'
SEGUNDOS="${1:-30}"
NIGHTLY="$(tr -d '[:space:]' < tools/toolchain/nightly-fuzz.txt)"

TODOS=(
    fleet_proto
    fleet_x509
    fleet_frame
    firmware_eventlog
    firmware_uefi
    scal_maps
    aegisql
    aegisql_historico
    aegisql_coste
    servidor_api_cuerpos
    servidor_grpc_mensajes
    trabajador_protocolo
    trabajador_modelo
    trabajador_pe
    trabajador_macho
    trabajador_desensamblado
    trabajador_emulacion
)
OBJETIVOS=()
if [ -n "${FUZZ_OBJETIVOS:-}" ]; then
    for patron in $FUZZ_OBJETIVOS; do
        for o in "${TODOS[@]}"; do
            # shellcheck disable=SC2053
            [[ "$o" == $patron ]] && OBJETIVOS+=("$o")
        done
    done
else
    OBJETIVOS=("${TODOS[@]}")
fi

falta() {
    if [ "${AEGIS_EXIGIR_FUZZ:-0}" = "1" ]; then
        printf '%s== Fuzzing: FALTA %s ==%s\n' "$ROJO" "$1" "$FIN"
        exit 1
    fi
    printf '%s== Fuzzing OMITIDO: falta %s ==%s\n' "$GRIS" "$1" "$FIN"
    exit 0
}
rustup toolchain list 2>/dev/null | grep -q "^$NIGHTLY" \
    || falta "el toolchain $NIGHTLY (rustup toolchain install $NIGHTLY --profile minimal)"
cargo "+$NIGHTLY" fuzz --version >/dev/null 2>&1 \
    || falta "cargo-fuzz (cargo install --locked cargo-fuzz)"

printf '%s== Fuzzing continuo: %d objetivo(s), %ss cada uno, %s ==%s\n' \
    "$NEGRITA" "${#OBJETIVOS[@]}" "$SEGUNDOS" "$NIGHTLY" "$FIN"

REGISTROS="$(mktemp -d)"
trap 'rm -rf "$REGISTROS"' EXIT
# Supresiones de fugas que no lo son (asignaciones estaticas de un solo uso),
# cada una justificada en el fichero; el resto de la deteccion sigue activa. Se
# copia a una ruta sin espacios: LSAN_OPTIONS no admite la del repositorio.
cp fuzz/lsan.supp "$REGISTROS/lsan.supp"
export LSAN_OPTIONS="suppressions=$REGISTROS/lsan.supp:print_suppressions=0"
FALLOS=0
for objetivo in "${OBJETIVOS[@]}"; do
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$objetivo"
    # El primer directorio es el corpus vivo (ignorado por git): cada ejecucion
    # arranca donde quedo la anterior. El segundo, las semillas y regresiones
    # versionadas. Topes por entrada: 512 MiB y 10 s, el techo del trabajador con
    # margen para el sanitizador; pasarlos es un fallo, no ruido.
    # Los objetivos del plano de control viven en server/fuzz (otro workspace,
    # FASE 6.2 del MP-16) y se nombran aqui con el prefijo `servidor_`.
    dir_fuzz=fuzz
    nombre="$objetivo"
    case "$objetivo" in
        servidor_*) dir_fuzz=server/fuzz; nombre="${objetivo#servidor_}" ;;
    esac
    mkdir -p "$dir_fuzz/corpus/$nombre"
    semillas=()
    [ -d "$dir_fuzz/semillas/$nombre" ] && semillas=("$dir_fuzz/semillas/$nombre")
    if cargo "+$NIGHTLY" fuzz run --fuzz-dir "$dir_fuzz" "$nombre" "$dir_fuzz/corpus/$nombre" "${semillas[@]}" -- \
        -max_total_time="$SEGUNDOS" -rss_limit_mb=512 -timeout=10 -print_final_stats=1 \
        > "$REGISTROS/$objetivo.log" 2>&1; then
        stats=$(grep -E "^#[0-9]+\s+DONE" "$REGISTROS/$objetivo.log" | tail -1 \
            | sed -E 's/.*(cov: [0-9]+).*(exec\/s: [0-9]+).*/\1, \2/')
        printf '    %sOK%s  %s\n' "$VERDE" "$FIN" "$stats"
    else
        printf '    %sFALLO%s  el objetivo encontro un caso que rompe la invariante\n' "$ROJO" "$FIN"
        # El caso reproductor: la ultima linea util del log y el artefacto.
        grep -iE "panic|SUMMARY|ERROR|Test unit written|error\[" "$REGISTROS/$objetivo.log" \
            | tail -8 | sed 's/^/      | /'
        FALLOS=$((FALLOS + 1))
    fi
done

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sFuzzing: ningun parser rompio ante entrada arbitraria.%s\n' "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sFuzzing: %d objetivo(s) encontraron un fallo. Reproductor en fuzz/artifacts/.%s\n' \
    "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
