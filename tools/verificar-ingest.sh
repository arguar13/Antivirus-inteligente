#!/usr/bin/env bash
#
# Verificacion de AegisIngest y AegisPipeline (FASE 74).
#
# QUE HACE ESTA FASE: tragarse los registros que ya escribe el resto de la casa
# —el syslog de los cortafuegos, el diario de los Linux, el registro de sucesos
# de los Windows, los ficheros de las aplicaciones y los planos de control de las
# nubes— y correlacionarlos con la telemetria propia. Sin esto, AegisCore es un
# EDR; con esto es una plataforma.
#
# LAS CUATRO COSAS QUE LA HACEN UNA CANALIZACION Y NO UN TUBO, y como se
# comprueba cada una:
#
#   1. ENTREGA AL MENOS UNA VEZ, con punto de control durable. La regla de orden
#      —sincronizar el diario y DESPUES avanzar el punto— es asimetrica a
#      proposito: un corte entre las dos produce DUPLICADOS, que la
#      deduplicacion absorbe, mientras que el orden contrario produciria
#      PERDIDAS, que no se arreglan porque nadie sabe siquiera que hubo. Hay
#      prueba de las dos direcciones.
#
#   2. MEMORIA ACOTADA DE EXTREMO A EXTREMO. Ninguna cola crece sin limite en
#      ningun punto: ni la del endpoint, ni la ventana de deduplicacion, ni el
#      reordenador. Se comprueba con un emisor mas rapido que el receptor,
#      midiendo la ocupacion en cada vuelta.
#
#   3. ORDEN POR OCURRENCIA. Un endpoint apagado un dia entrega su lote al
#      reconectar; ordenado por llegada, un ataque repartido en dos dias
#      pareceria un pico de un segundo. La prueba mide la separacion real que
#      sale por el otro lado.
#
#   4. LA PERDIDA SE DECLARA. Todo lo que se descarta se cuenta y por prioridad.
#      Un sistema que pierde eventos en silencio es peor que uno que se niega a
#      aceptarlos.
#
# LO QUE ESTA FASE TRATA COMO ENTRADA HOSTIL, que es todo:
# un registro lo escribe cualquiera, incluido el atacante. syslog abierto a un
# puerto sin autenticacion, ficheros que escriben aplicaciones de terceros,
# diarios binarios y EVTX de una maquina que puede estar comprometida. Cada
# analizador tiene sus pruebas de entrada preparada: cadenas que no cierran,
# desplazamientos que apuntan fuera del fichero, cadenas de punteros que se
# muerden la cola, documentos anidados dos mil veces y longitudes declaradas que
# no se corresponden con lo que hay.
#
# LOS MUROS DE ESTA FASE, declarados en vez de disimulados:
#
#   (a) journald comprime los campos grandes con tres algoritmos. Aqui se
#       descomprime LZ4, implementado en el propio crate —cuarenta lineas, cero
#       dependencias—. XZ y ZSTD NO: meter un descompresor de zstd en el proceso
#       mas privilegiado de la maquina es una decision que se toma a proposito o
#       no se toma. El campo afectado se entrega MARCADO con el algoritmo que
#       haria falta y se cuenta.
#   (b) El texto legible de un suceso de Windows NO esta en el fichero EVTX: vive
#       en una tabla de mensajes dentro de la DLL del proveedor, en la maquina de
#       origen y en su idioma. Se analiza la estructura entera —cada valor con su
#       nombre— y se lleva un catalogo de los identificadores que importan, que
#       ademas es lo que de verdad sirve para detectar: un 4625 es un fallo de
#       autenticacion en cualquier idioma; su frase, no.
#   (c) Los registros de nube se ingieren en el PLANO DE CONTROL, no en el
#       agente: no salen de ninguna maquina del cliente, y poner sus credenciales
#       en un endpoint seria regalar el activo que un atacante busca ahi.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisIngest: los analizadores, contra formatos reales byte a byte"
if cargo test -q -p aegis-ingest > /tmp/aegis-ingest.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ingest.log | head -1))"
    echo "    ${GRIS}syslog contra los ejemplos LITERALES de los RFC 5424 y 3164; el${FIN}"
    echo "    ${GRIS}diario de systemd y el EVTX contra ficheros construidos byte a byte${FIN}"
    echo "    ${GRIS}con su formato real —la unica forma de probar un analizador binario${FIN}"
    echo "    ${GRIS}sin depender de que la maquina de integracion sea Windows, y ademas${FIN}"
    echo "    ${GRIS}la unica de fabricar los ficheros hostiles que ningun sistema sano${FIN}"
    echo "    ${GRIS}genera—. Y la rotacion: se escribe DESPUES de la ultima lectura y${FIN}"
    echo "    ${GRIS}ANTES del «mv», que es la franja que pierde casi todo el mundo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ingest.log)"
    tail -30 /tmp/aegis-ingest.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisIngest: el arbol de dependencias del endpoint"
ARBOL=$(cargo tree -p aegis-ingest --edges normal --prefix none 2>/dev/null \
        | awk '{print $1}' | sort -u | grep -v '^$' | wc -l)
if [ "$ARBOL" -gt 0 ] && [ "$ARBOL" -lt 40 ]; then
    echo "    ${VERDE}OK${FIN} (arbol de $ARBOL crates)"
    echo "    ${GRIS}Esta es la superficie MAS ANCHA del producto: un puerto 514 abierto${FIN}"
    echo "    ${GRIS}acepta una trama de cualquiera que llegue a la red, y no hay${FIN}"
    echo "    ${GRIS}autenticacion en el protocolo ni la va a haber. Cada crate que se${FIN}"
    echo "    ${GRIS}enlace aqui analiza esa entrada dentro del proceso mas privilegiado${FIN}"
    echo "    ${GRIS}de la maquina. Por eso el calendario, el LZ4 y los analizadores son${FIN}"
    echo "    ${GRIS}propios: no por gusto, sino porque la alternativa es importar${FIN}"
    echo "    ${GRIS}codigo de terceros al sitio donde entra lo que escribe el atacante.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: arbol de $ARBOL crates (se esperaba menos de 40)"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisIngest: la cuota de memoria sale del presupuesto del host"
if cargo run -q -p aegis-presupuesto --example reparto -- --campo reposo > /dev/null 2>&1; then
    CUOTA=$(cargo run -q -p aegis-presupuesto --example reparto 2>/dev/null \
            | grep -m1 'ingesta' | awk '{print $2, $3}')
    echo "    ${VERDE}OK${FIN} (en esta maquina: $CUOTA)"
    echo "    ${GRIS}La ingesta de registros de terceros es el segundo componente cuyo${FIN}"
    echo "    ${GRIS}volumen decide alguien de fuera —el primero es la red—, asi que${FIN}"
    echo "    ${GRIS}tiene cuota propia y medida dentro del presupuesto del agente en vez${FIN}"
    echo "    ${GRIS}de una constante inventada en su propio fichero. Un cliente que${FIN}"
    echo "    ${GRIS}encamine el syslog de mil aparatos a un endpoint nota contrapresion${FIN}"
    echo "    ${GRIS}mucho antes de que el motor de comportamiento suelte estado.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el reparto del presupuesto no responde"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisPipeline: cuotas por inquilino, deduplicacion y orden"
if (cd server && cargo test -q -p aegis-pipeline) > /tmp/aegis-pipeline.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-pipeline.log | head -1))"
    echo "    ${GRIS}La deduplicacion es EXACTA y no un filtro de Bloom, y esa es una${FIN}"
    echo "    ${GRIS}decision de seguridad y no de rendimiento: un falso positivo de un${FIN}"
    echo "    ${GRIS}Bloom significa «ya lo he visto» cuando no es cierto, y lo que se${FIN}"
    echo "    ${GRIS}hace con un duplicado es TIRARLO. O sea, borrar un evento unico en${FIN}"
    echo "    ${GRIS}silencio y sin saber cual. El fallo de la estructura de aqui es el${FIN}"
    echo "    ${GRIS}contrario —un duplicado muy tardio se ve dos veces— y es inofensivo.${FIN}"
    echo "    ${GRIS}Y dos cubos por inquilino, no uno: con uno, un atacante genera ruido${FIN}"
    echo "    ${GRIS}en cualquier aplicacion del cliente, agota su cuota, y sus PROPIAS${FIN}"
    echo "    ${GRIS}huellas dejan de subir. No tendria que hacer nada mas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-pipeline.log)"
    tail -30 /tmp/aegis-pipeline.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisIngest: origenes vivos en esta maquina"
VIVOS=0
if [ -d /var/log/journal ] || [ -d /run/log/journal ]; then
    N=$(find /var/log/journal /run/log/journal -name '*.journal' 2>/dev/null | wc -l)
    echo "    ${VERDE}journald${FIN}: $N fichero(s) de diario presentes"
    VIVOS=$((VIVOS + 1))
fi
if ls /var/log/*.log >/dev/null 2>&1 || [ -f /var/log/syslog ] || [ -f /var/log/messages ]; then
    echo "    ${VERDE}ficheros${FIN}: hay log plano en /var/log"
    VIVOS=$((VIVOS + 1))
fi
if [ "$VIVOS" -eq 0 ]; then
    echo "    ${GRIS}AUSENTES${FIN}: este contenedor no tiene ni diario de systemd ni log en"
    echo "    ${GRIS}/var/log. Es el muro de la fase EN ESTA MAQUINA y se declara en vez${FIN}"
    echo "    ${GRIS}de disimularse. Lo que SI se ejercita arriba, entero: los cuatro${FIN}"
    echo "    ${GRIS}analizadores contra ficheros con el formato real, la rotacion contra${FIN}"
    echo "    ${GRIS}ficheros de verdad en disco con inodos de verdad, el punto de control${FIN}"
    echo "    ${GRIS}con «fsync» y sustitucion atomica de verdad, y la tuberia entera de${FIN}"
    echo "    ${GRIS}origen a entrega con reinicio en medio.${FIN}"
fi

echo "==> AegisIngest: EVTX y nube, los dos muros que no dependen de esta maquina"
echo "    ${GRIS}El texto legible de un suceso de Windows no esta en el EVTX: vive en${FIN}"
echo "    ${GRIS}la DLL del proveedor, en la maquina de origen y en su idioma. Se${FIN}"
echo "    ${GRIS}analiza la estructura ENTERA —BinXML, plantillas y sustituciones— y el${FIN}"
echo "    ${GRIS}significado lo pone un catalogo de identificadores, que ademas no${FIN}"
echo "    ${GRIS}depende del idioma: un 4625 es un fallo de autenticacion en aleman${FIN}"
echo "    ${GRIS}igual que en castellano; su frase, no.${FIN}"
echo "    ${GRIS}Y los registros de nube se ingieren en el PLANO DE CONTROL: no salen${FIN}"
echo "    ${GRIS}de ninguna maquina del cliente, y darle a un endpoint credenciales de${FIN}"
echo "    ${GRIS}la nube entera seria poner ahi justo el activo que se busca en un${FIN}"
echo "    ${GRIS}endpoint. Los tres formatos se prueban contra documentos reales.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisIngest verificado${FIN}"
else
    echo "${ROJO}==> AegisIngest: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
