#!/usr/bin/env bash
#
# Sanitizacion de memoria de AegisCore (FASE 35).
#
# AegisCore tiene `unsafe` alli donde toca el kernel: ptrace, process_vm_readv,
# perf_event_open, eBPF, las sondas de ABI. El compilador no comprueba esas
# rutas; los sanitizadores en ejecucion, si. Este script corre las pruebas de
# los crates con `unsafe` de primera parte bajo AddressSanitizer, que detecta
# lecturas/escrituras fuera de rango, uso despues de liberar y fugas.
#
# Uso:  tools/sanitize.sh
#
# Codigo de salida 0 si ningun sanitizador se queja; 1 si alguno lo hace; se
# OMITE (0) si no hay toolchain nightly (el sanitizador lo exige).
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'
TRIPLE="x86_64-unknown-linux-gnu"

# Crates con `unsafe` de primera parte que vale la pena instrumentar. Se excluye
# lo que es FFI pura de terceros (el sanitizador no ve dentro de la libc del
# sistema) y lo que exige privilegios que el runner no tiene.
CRATES=(
    aegis-scal        # process_vm_readv, /proc
    aegis-ipc         # ring buffer compartido, ABI
    aegis-syscallguard # ptrace, perf_event_open
    aegis-firmware    # parsers de bytes de firmware
    aegis-fleet       # parsers de red y cripto
    aegis-memhunter   # pread sobre pagemap, process_vm_readv, mmap/mprotect en las
                      # pruebas vivas: toda la ruta unsafe de la FASE 65
    aegis-l7hunter    # parseo de ELF de ficheros arbitrarios y decodificacion de
                      # registros del ring buffer: los dos son entrada hostil
    aegis-fwaudit     # el crate es #![forbid(unsafe_code)], pero lo que analiza
                      # —tablas ACPI del firmware, imagenes de ROM SPI, volumenes
                      # UEFI y ficheros FFS— es la entrada mas hostil que hay: la
                      # escribe algo que se ejecuta ANTES que el sistema operativo.
                      # ASan aqui no busca unsafe propio, busca que ningun indice
                      # calculado a partir de esos bytes se salga de su buffer
    aegis-wire        # mismo motivo que aegis-fwaudit, y mas expuesto todavia: el
                      # crate es #![forbid(unsafe_code)], pero DISECTA BYTES DE LA
                      # RED sin autenticacion previa. Cada longitud, desplazamiento
                      # e indice sale de datos que escribe el atacante, y es
                      # exactamente el sitio donde ClamAV, Suricata y Zeek acumulan
                      # su historial de desbordamientos. ASan corre aqui los
                      # ataques ya construidos —solape TCP, punteros DNS, DER
                      # anidado, cadena IPv6— buscando que ninguno se salga
)

if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    printf '%s== Sanitizadores OMITIDOS: no hay toolchain nightly ==%s\n' "$GRIS" "$FIN"
    exit 0
fi

printf '%s== AddressSanitizer sobre %d crate(s) con unsafe de primera parte ==%s\n' \
    "$NEGRITA" "${#CRATES[@]}" "$FIN"

FALLOS=0
for crate in "${CRATES[@]}"; do
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$crate"
    # -Zsanitizer=address instrumenta el crate y sus dependencias; el triple
    # explicito es obligatorio para que la instrumentacion se aplique.
    if RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS="detect_leaks=1" \
        cargo +nightly test -p "$crate" --target "$TRIPLE" \
        > "/tmp/aegis-asan-$crate.log" 2>&1; then
        pasados=$(grep -hoE "[0-9]+ passed" "/tmp/aegis-asan-$crate.log" \
            | awk '{s+=$1} END {print s+0}')
        printf '    %sOK%s  %s prueba(s) bajo ASan sin error de memoria\n' \
            "$VERDE" "$FIN" "$pasados"
    else
        # Distinguir un fallo del sanitizador de un fallo de compilacion o de un
        # test que no aplica en este entorno.
        if grep -qE "ERROR: AddressSanitizer|SUMMARY: AddressSanitizer|LeakSanitizer" \
            "/tmp/aegis-asan-$crate.log"; then
            printf '    %sFALLO%s  el sanitizador detecto un error de memoria\n' "$ROJO" "$FIN"
            grep -A3 -E "ERROR: AddressSanitizer|SUMMARY:" "/tmp/aegis-asan-$crate.log" \
                | head -8 | sed 's/^/      | /'
            FALLOS=$((FALLOS + 1))
        else
            printf '    %sFALLO%s  las pruebas no pasaron bajo el sanitizador\n' "$ROJO" "$FIN"
            grep -E "error\[|test result: FAILED|panicked" "/tmp/aegis-asan-$crate.log" \
                | head -5 | sed 's/^/      | /'
            FALLOS=$((FALLOS + 1))
        fi
    fi
done

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sSanitizadores: sin errores de memoria en las rutas unsafe.%s\n' \
        "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sSanitizadores: %d crate(s) con hallazgos.%s\n' "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
