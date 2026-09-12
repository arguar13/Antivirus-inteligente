#!/usr/bin/env bash
#
# Verificacion de AegisFirmwareAudit (auditoria de firmware SOLO LECTURA, FASE 67).
#
# ESTA FASE TIENE UNA PROPIEDAD QUE NINGUNA OTRA TIENE: el riesgo no esta en no
# detectar, esta en ESCRIBIR. Una escritura accidental sobre la ROM SPI no es un
# bug, es un LADRILLO: la maquina no vuelve a arrancar y no hay recuperacion por
# software. Por eso la primera comprobacion de este script no es de deteccion,
# es de INOCUIDAD, y es la unica que se ejerce contra el kernel:
#
#   write()     sobre el descriptor que usa el crate -> EBADF
#   pwrite()    idem                                 -> EBADF
#   ftruncate() idem                                 -> EBADF
#
# No es "confiamos en que no llamamos a write": es que el kernel lo impide, y se
# comprueba llamandolo de verdad. La segunda capa —`#![forbid(unsafe_code)]` mas
# un tipo `LecturaSolo` que no expone ninguna operacion de escritura— la verifica
# el compilador, y por eso las pruebas que INTENTAN escribir viven en un crate de
# integracion aparte: dentro del crate ni siquiera se pueden escribir.
#
# Lo que se afirma de deteccion:
#
#   - Las tablas ACPI REALES del firmware de esta maquina se parsean, y su
#     checksum de 8 bits da cero. Ese checksum no se inventa en una prueba: es
#     el que grabo el fabricante.
#   - La auditoria completa de esta maquina sale LIMPIA. Si no saliera, o el
#     equipo esta comprometido o el decisor esta mal calibrado — y lo segundo
#     significa una alerta critica en cada endpoint del cliente el primer dia.
#   - WPBT, descriptor de flash de Intel, volumenes UEFI y ficheros FFS se
#     ejercen con vectores binarios construidos byte a byte segun la spec,
#     incluyendo los hostiles (longitudes mentirosas, tamanos cero, basura).
#
# EL MURO, que se declara y no se disimula: LEER la ROM SPI. Requiere que el
# kernel exponga la flash como MTD (`/sys/class/mtd`), lo que exige un driver
# como intel-spi o spi-nor que casi ninguna distribucion activa, y ademas root.
# Cuando no se puede, el informe dice NO APLICABLE con su motivo — nunca "OK".
# Confundir "no se puede mirar" con "esta bien" es el fallo que el tri-estado de
# CheckState existe para impedir, y este script comprueba que no se comete.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisFirmwareAudit: INOCUIDAD — el kernel rechaza toda escritura"
if cargo test -p aegis-fwaudit --quiet --test solo_lectura \
    >/tmp/aegis-fwaudit-solo-lectura.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (write, pwrite y ftruncate sobre el descriptor del crate: EBADF los tres,"
    echo "    ${VERDE}  ${FIN} llamados de verdad al kernel, no deducidos de que no se use File::write)"
else
    echo "    ${ROJO}FALLO${FIN}: la garantia de solo lectura NO se sostiene. Un EDR que pueda"
    echo "    ${ROJO}     ${FIN} escribir en la ROM SPI es peor que el implante que busca: deja"
    echo "    ${ROJO}     ${FIN} la placa inservible sin recuperacion por software."
    sed 's/^/    | /' /tmp/aegis-fwaudit-solo-lectura.log | tail -30
    exit 1
fi

echo "==> AegisFirmwareAudit: las tablas ACPI REALES de esta maquina"
# stdout y stderr van a ficheros DISTINTOS a proposito: los puntos de progreso del
# harness de pruebas salen por stdout y se intercalan a media linea con lo que las
# pruebas imprimen por stderr, dejando ilegible el inventario de tablas reales.
if cargo test -p aegis-fwaudit --quiet acpi::pruebas:: -- --nocapture \
    >/tmp/aegis-fwaudit-acpi.log 2>/tmp/aegis-fwaudit-acpi.err; then
    echo "    ${VERDE}OK${FIN} (las tablas que grabo el fabricante se parsean y su checksum de 8 bits"
    echo "    ${VERDE}  ${FIN} da cero; una cabecera mentirosa o truncada se rechaza sin leer fuera)"
    grep -E 'ACPI reales|checksum' /tmp/aegis-fwaudit-acpi.err |
        sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
else
    echo "    ${ROJO}FALLO${FIN}: el parseo de las tablas ACPI reales no cuadra"
    cat /tmp/aegis-fwaudit-acpi.log /tmp/aegis-fwaudit-acpi.err |
        sed 's/^/    | /' | tail -30
    exit 1
fi

echo "==> AegisFirmwareAudit: WPBT, descriptor Intel, volumenes UEFI y ficheros FFS"
if cargo test -p aegis-fwaudit --quiet -- wpbt::pruebas:: spi::pruebas:: uefi::pruebas:: \
    linea_base::pruebas:: anomalias::pruebas:: >/tmp/aegis-fwaudit-parsers.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (una WPBT que descarga y ejecuta se delata, y los argumentos legitimos"
    echo "    ${VERDE}  ${FIN} de fabricante NO; el hash canonico de un FFS no cambia cuando muta su"
    echo "    ${VERDE}  ${FIN} byte de estado en la flash; un hash revocado gana sobre un GUID conocido;"
    echo "    ${VERDE}  ${FIN} y las entradas hostiles —longitud mentirosa, tamano cero, basura— acaban"
    echo "    ${VERDE}  ${FIN} el recorrido en vez de colgarlo o leer fuera de rango)"
else
    echo "    ${ROJO}FALLO${FIN}: el analisis de firmware no pasa"
    sed 's/^/    | /' /tmp/aegis-fwaudit-parsers.log | tail -30
    exit 1
fi

echo "==> AegisFirmwareAudit: el veredicto, y que DIGA lo que no pudo mirar"
if cargo test -p aegis-fwaudit --quiet pruebas:: -- --nocapture --skip acpi:: --skip wpbt:: \
    --skip spi:: --skip uefi:: --skip linea_base:: --skip anomalias:: --skip solo_lectura:: \
    >/tmp/aegis-fwaudit-informe.log 2>/tmp/aegis-fwaudit-informe.err; then
    echo "    ${VERDE}OK${FIN} (el firmware de esta maquina sale limpio; una ROM con un modulo reescrito"
    echo "    ${VERDE}  ${FIN} se detecta contra su linea base; y SIN linea base el veredicto es"
    echo "    ${VERDE}  ${FIN} INDETERMINADO, no 'correcto': no es lo mismo no encontrar nada que"
    echo "    ${VERDE}  ${FIN} no tener con que comparar)"
else
    echo "    ${ROJO}FALLO${FIN}: el decisor de la auditoria no pasa"
    cat /tmp/aegis-fwaudit-informe.log /tmp/aegis-fwaudit-informe.err |
        sed 's/^/    | /' | tail -30
    exit 1
fi

echo "==> AegisFirmwareAudit: auditoria REAL de esta maquina (lo que ve un endpoint)"
if cargo run -q -p aegis-fwaudit --example fwaudit_support \
    >/tmp/aegis-fwaudit-vivo.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-fwaudit-vivo.log
    if grep -q 'spi-rom *no aplicable' /tmp/aegis-fwaudit-vivo.log; then
        echo "    ${VERDE}OK${FIN} (limpio, y el muro DECLARADO)"
        echo "    ${GRIS}La LECTURA de la ROM SPI NO se ejercio aqui: este kernel no expone la flash${FIN}"
        echo "    ${GRIS}como MTD. El decisor que consume esa imagen SI se prueba, arriba, con${FIN}"
        echo "    ${GRIS}volumenes UEFI y ficheros FFS construidos byte a byte.${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (limpio, y esta maquina SI expone la ROM SPI: se leyo de verdad)"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: la auditoria de esta maquina no sale limpia"
    sed 's/^/    | /' /tmp/aegis-fwaudit-vivo.log | tail -30
    exit 1
fi
exit 0
