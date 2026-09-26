#!/usr/bin/env bash
#
# Verificacion de AegisFirmware+ (FASE 92): auditoria de plataforma de grado
# CHIPSEC, con la escritura imposible de expresar.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. INOCUIDAD, antes que nada. Cada superficie nueva —configuracion PCI,
#      tablas ACPI, /proc, microcodigo del fabricante, /dev/mem, MSR— se abre por
#      el unico tipo del crate que abre ficheros, y se intenta escribir por el
#      descriptor real: el KERNEL tiene que rechazarlo. Y por separado, que la
#      escritura ni siquiera se pueda EXPRESAR: pruebas `compile_fail` con el
#      codigo de error atado (no hay metodo, no es io::Write, el fichero de
#      dentro es privado, y el lector fisico no tiene wrmsr).
#   2. Los decisores de cada registro, con los valores de los datasheets de
#      Intel: la tabla de verdad de bios_wp, PRx que cubren o no la BIOS entera,
#      SMRAMC, TSEG, SMRR en todas las CPU, WSMT, DMAR, variables UEFI, la
#      cadena de arranque y el microcodigo.
#   3. El AML REAL de esta maquina, decodificado entero y COTEJADO en esta misma
#      puerta contra las dos herramientas de referencia de Intel: el numero de
#      metodos estaticos contra `iasl -d`, y el de incondicionales contra lo que
#      `acpiexec` carga de verdad. Las cifras no estan escritas en ninguna prueba:
#      se miden aqui, cada vez.
#   4. Los ficheros REALES de microcodigo del fabricante suman cero todos.
#   5. La auditoria de plataforma de ESTA maquina, entera, sin compromisos, y con
#      cada cosa que no se pudo mirar dicha con su motivo.
#   6. La tabla de equivalencia con CHIPSEC es coherente con el codigo.
#
# EL MURO, DECLARADO: esta maquina es una maquina virtual de Hyper-V. No hay
# chipset de Intel visible, ni UEFI, ni TPM, ni modulo msr. Las lecturas de esos
# registros se declaran NO APLICABLES con su motivo; sus DECISORES se prueban
# enteros con los valores de los datasheets. No se ha podido ejecutar CHIPSEC:
# su controlador de kernel exige las cabeceras del kernel, y WSL no las publica.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-plataforma-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

echo "==> AegisFirmware+: INOCUIDAD — cada superficie nueva rechaza la escritura en el kernel"
if cargo test -p aegis-fwaudit --quiet --test solo_lectura -- --nocapture \
    >"$TMP/inocuidad.log" 2>"$TMP/inocuidad.err"; then
    grep -E '^\s+(configuracion|tabla|/proc|mitigaciones|microcodigo|variables|memoria|MSR|superficies)' \
        "$TMP/inocuidad.err" | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} (escrituras de CERO bytes y truncado al tamano ACTUAL: el kernel mira el modo"
    echo "    ${VERDE}  ${FIN} antes que la longitud, asi que el rechazo se demuestra igual, y la prueba no"
    echo "    ${VERDE}  ${FIN} podria danar nada ni aunque la garantia fallara)"
else
    fallo "la garantia de solo lectura NO se sostiene en alguna superficie" "$TMP/inocuidad.err"
fi

echo "==> AegisFirmware+: la escritura no se puede EXPRESAR (compile_fail con codigo de error)"
if cargo test -p aegis-fwaudit --quiet --doc >"$TMP/doc.log" 2>&1; then
    N=$(grep -c 'compile fail ... ok' "$TMP/doc.log")
    if [ "$N" -lt 5 ]; then
        fallo "se esperaban 5 pruebas compile_fail y pasaron $N" "$TMP/doc.log"
    fi
    echo "    ${VERDE}OK${FIN} ($N: sin metodo de escritura (E0599), no es io::Write (E0277), el fichero"
    echo "    ${VERDE}  ${FIN} de dentro es privado (E0616), y el lector fisico no tiene wrmsr ni escritura"
    echo "    ${VERDE}  ${FIN} de memoria (E0599 x2))"
else
    fallo "las pruebas compile_fail no pasan" "$TMP/doc.log"
fi

echo "==> AegisFirmware+: decisores de registros, tablas, variables, cadena y microcodigo"
if cargo test -p aegis-fwaudit --quiet --lib -- registros:: msr:: pci:: tablas:: variables:: \
    ruta_dispositivo:: opcion_rom:: arranque:: microcodigo:: mitigaciones:: comprobacion:: \
    senal:: linea_base:: >"$TMP/decisores.log" 2>&1; then
    N=$(grep -oE '[0-9]+ passed' "$TMP/decisores.log" | head -1)
    echo "    ${VERDE}OK${FIN} ($N: BLE sin SMM_BWP es la carrera; PRx solo cuentan si cubren la BIOS"
    echo "    ${VERDE}  ${FIN} ENTERA y FLOCKDN los fija; un solo nucleo sin bloqueo se nombra; AuditMode"
    echo "    ${VERDE}  ${FIN} anula Secure Boot; un evento cuyo texto no es lo medido se delata; y las"
    echo "    ${VERDE}  ${FIN} exposiciones NUNCA mueven el juicio del arbitro)"
else
    fallo "algun decisor no pasa" "$TMP/decisores.log"
fi

echo "==> AegisFirmware+: el AML REAL, decodificado y cotejado contra iasl y acpiexec"
if ! cargo test -p aegis-fwaudit --quiet --lib -- aml:: --nocapture \
    >"$TMP/aml.log" 2>"$TMP/aml.err"; then
    fallo "el desensamblador AML no pasa" "$TMP/aml.err"
fi
LINEA=$(grep -E '^AML real:' "$TMP/aml.err" | head -1)
if [ -z "$LINEA" ]; then
    echo "    ${GRIS}NO APLICABLE: esta maquina no expone DSDT${FIN}"
else
    echo "    ${GRIS}$LINEA${FIN}"
    NUESTROS=$(echo "$LINEA" | grep -oE '[0-9]+ metodos' | grep -oE '[0-9]+')
    INCOND=$(echo "$LINEA" | grep -oE '[0-9]+ incondicionales' | grep -oE '[0-9]+')
    # Las tablas AML reales, copiadas a un directorio propio.
    mkdir -p "$TMP/aml"
    for t in /sys/firmware/acpi/tables/DSDT /sys/firmware/acpi/tables/SSDT* \
             /sys/firmware/acpi/tables/dynamic/SSDT*; do
        [ -r "$t" ] && cp "$t" "$TMP/aml/$(basename "$(dirname "$t")")-$(basename "$t").dat"
    done
    if command -v iasl >/dev/null 2>&1; then
        IASL=0
        for f in "$TMP"/aml/*.dat; do
            (cd "$TMP/aml" && iasl -d "$(basename "$f")" >/dev/null 2>&1)
            dsl="${f%.dat}.dsl"
            [ -f "$dsl" ] && IASL=$((IASL + $(grep -c 'Method (' "$dsl")))
        done
        if [ "$IASL" = "$NUESTROS" ]; then
            echo "    ${VERDE}OK${FIN} metodos estaticos: $NUESTROS aqui, $IASL segun iasl -d — IDENTICOS"
        else
            fallo "metodos estaticos: $NUESTROS aqui y $IASL segun iasl -d"
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: iasl no esta instalado (paquete acpica-tools): el cotejo no se puede hacer"
        exit 1
    fi
    if command -v acpiexec >/dev/null 2>&1; then
        (cd "$TMP/aml" && acpiexec -b "methods" ./*.dat >"$TMP/acpiexec.log" 2>&1)
        # "Table [DSDT: DSDT01  ] (id 01) - 60 Objects with 5 Devices, 2 Regions, 7 Methods (...)"
        CARGADOS=$(grep -oE ', *[0-9]+ Methods' "$TMP/acpiexec.log" | grep -oE '[0-9]+' | paste -sd+ - | bc)
        if [ "${CARGADOS:-x}" = "$INCOND" ]; then
            echo "    ${VERDE}OK${FIN} metodos incondicionales: $INCOND aqui, $CARGADOS cargados por acpiexec — IDENTICOS"
            echo "    ${GRIS}(el resto vive dentro de bloques If que el interprete resuelve al cargar con${FIN}"
            echo "    ${GRIS} valores de la maquina viva: el analisis estatico los ve todos y los marca)${FIN}"
        else
            fallo "incondicionales: $INCOND aqui y ${CARGADOS:-?} cargados por acpiexec" "$TMP/acpiexec.log"
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: acpiexec no esta instalado (paquete acpica-tools)"
        exit 1
    fi
fi

echo "==> AegisFirmware+: el microcodigo REAL del fabricante, integro"
if cargo test -p aegis-fwaudit --quiet --lib -- microcodigo::pruebas::los_ficheros_reales --nocapture \
    >"$TMP/ucode.log" 2>"$TMP/ucode.err"; then
    L=$(grep -E 'microcodigo de Intel real|NO APLICABLE' "$TMP/ucode.err" | head -1)
    echo "    ${VERDE}OK${FIN} ${L}"
else
    fallo "algun fichero del fabricante no suma cero" "$TMP/ucode.err"
fi

echo "==> AegisFirmware+: equivalencia con CHIPSEC, coherente con el codigo"
if cargo test -p aegis-fwaudit --quiet --lib -- chipsec:: --nocapture \
    >"$TMP/chipsec.log" 2>"$TMP/chipsec.err"; then
    echo "    ${VERDE}OK${FIN} $(grep -E '^CHIPSEC:' "$TMP/chipsec.err" | head -1)"
    echo "    ${GRIS}CHIPSEC NO se ha ejecutado aqui: su controlador exige las cabeceras del kernel,${FIN}"
    echo "    ${GRIS}que WSL no publica. Se compara por modulos equivalentes, y los que escriben o${FIN}"
    echo "    ${GRIS}atacan para confirmar se cuentan aparte: no son victoria ni derrota.${FIN}"
else
    fallo "la tabla de CHIPSEC no cuadra con el codigo" "$TMP/chipsec.err"
fi

echo "==> AegisFirmware+: la plataforma REAL de esta maquina (lo que ve un endpoint)"
if cargo run -q -p aegis-fwaudit --example plataforma_support >"$TMP/vivo.log" 2>&1; then
    sed 's/^/    | /' "$TMP/vivo.log"
    echo "    ${VERDE}OK${FIN} (sin compromisos; las exposiciones son postura y no hacen fallar, y lo que"
    echo "    ${VERDE}  ${FIN} no se pudo mirar esta dicho con su motivo)"
else
    fallo "la auditoria de plataforma de esta maquina da un compromiso" "$TMP/vivo.log"
fi
exit 0
