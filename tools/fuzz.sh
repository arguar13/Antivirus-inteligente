#!/usr/bin/env bash
#
# Fuzzing continuo de AegisCore (FASE 35).
#
# Corre cada objetivo de libFuzzer un tiempo acotado sobre los parsers que
# reciben entrada no confiable (protobuf de flota, DER de certificados, tramas
# RPC, event log TCG, variables UEFI, /proc/maps). La invariante es simple y
# dura: NINGUN parser entra en panico ante entrada arbitraria. Un panico ante un
# mensaje malformado es una via de denegacion de servicio; el fuzzing lo
# encuentra antes que el atacante.
#
# Uso:  tools/fuzz.sh [SEGUNDOS_POR_OBJETIVO]
#   Por defecto 30 s/objetivo (apto para CI). Un pipeline nocturno usa mas.
#
# Codigo de salida 0 si ningun objetivo encuentra un fallo; 1 si alguno lo hace;
# se OMITE (0) si la maquina no tiene el toolchain de fuzzing.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'
SEGUNDOS="${1:-30}"

OBJETIVOS=(
    fleet_proto
    fleet_x509
    fleet_frame
    firmware_eventlog
    firmware_uefi
    scal_maps
    aegisql
)

# El fuzzing exige toolchain nightly (por el sanitizador y libFuzzer) y el
# subcomando cargo-fuzz. Si falta, se OMITE con honestidad, como el resto de las
# comprobaciones dependientes del entorno del proyecto.
if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    printf '%s== Fuzzing OMITIDO: no hay toolchain nightly ==%s\n' "$GRIS" "$FIN"
    exit 0
fi
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    printf '%s== Fuzzing OMITIDO: falta cargo-fuzz (cargo install cargo-fuzz) ==%s\n' "$GRIS" "$FIN"
    exit 0
fi

printf '%s== Fuzzing continuo: %d objetivo(s), %ss cada uno ==%s\n' \
    "$NEGRITA" "${#OBJETIVOS[@]}" "$SEGUNDOS" "$FIN"

FALLOS=0
for objetivo in "${OBJETIVOS[@]}"; do
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$objetivo"
    # -max_total_time acota el tiempo; el corpus persiste entre corridas y hace
    # que el fuzzing sea "continuo": cada ejecucion arranca donde quedo la
    # anterior. Un hallazgo deja un fichero en fuzz/artifacts/<objetivo>/.
    if cargo +nightly fuzz run "$objetivo" -- \
        -max_total_time="$SEGUNDOS" -print_final_stats=1 \
        > "/tmp/aegis-fuzz-$objetivo.log" 2>&1; then
        stats=$(grep -E "^#[0-9]+\s+DONE" "/tmp/aegis-fuzz-$objetivo.log" | tail -1 \
            | sed -E 's/.*(cov: [0-9]+).*(exec\/s: [0-9]+).*/\1, \2/')
        printf '    %sOK%s  %s\n' "$VERDE" "$FIN" "$stats"
    else
        printf '    %sFALLO%s  el objetivo encontro un caso que rompe la invariante\n' "$ROJO" "$FIN"
        # El caso reproductor: la ultima linea util del log y el artefacto.
        grep -iE "panic|SUMMARY|ERROR|Test unit written" "/tmp/aegis-fuzz-$objetivo.log" \
            | tail -5 | sed 's/^/      | /'
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
