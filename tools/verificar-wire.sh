#!/usr/bin/env bash
#
# Verificacion de AegisWire (diseccion semantica de protocolos, FASE 70).
#
# QUE HACE ESTA FASE, y que gobierna todo lo demas: convierte bytes que escribe
# el ATACANTE, sin autenticacion previa y a velocidad de linea, en hechos con
# significado. Es la superficie de ataque mas expuesta del producto, y es
# exactamente donde ClamAV, Suricata y Zeek acumulan su historial de CVE de
# desbordamiento. De ahi las tres decisiones que este script comprueba una a una.
#
# PRIMERA: CERO dependencias externas nuevas. Un disector con una biblioteca de
# parsing generica es codigo no auditado en el sitio mas caliente del agente.
#
# SEGUNDA: el motor es SANS-IO. No abre sockets, no toca la NIC, no tiene reloj.
# Por eso cada ataque de esta fase se construye ENTERO en una prueba, sin red y
# sin privilegios, en vez de quedarse declarado como muro. Es la diferencia entre
# «resiste la evasion por solape» y «aqui esta la evasion por solape, ejercida».
#
# TERCERA: lo que el atacante controla —numero de flujos, secuencia TCP, longitud
# de un campo, profundidad de un DER, tamano de un fichero— tiene cota, y cada
# vez que una cota recorta algo SE CUENTA. Un dato que se tira sin contarlo es un
# agujero de visibilidad que nadie sabe que tiene.
#
# LOS MUROS DE ESTA FASE, declarados en vez de disimulados:
#
#   (a) La CAPTURA desde la NIC no se ejercita aqui: el motor es sans-io a
#       proposito y la captura vive en aegis-net. Lo que se prueba es todo lo que
#       pasa DESPUES del paquete, que es donde estan los ataques.
#   (b) La defragmentacion IP NO se hace. Se declara el datagrama como
#       fragmentado y los fragmentos posteriores no se analizan como transporte.
#       Reensamblar IP es otra superficie entera y mezclarla haria imposible
#       razonar sobre ninguna de las dos.
#   (c) El contenido CIFRADO no se ve, y no se finge verlo. De TLS se saca el
#       saludo, la huella y el certificado. Lo de dentro lo ve aegis-l7hunter con
#       uprobes, no este crate.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisWire: la evasion por solape de segmentos TCP, ejercida entera"
if cargo test -p aegis-wire --quiet reensamblado:: \
    >/tmp/aegis-wire-reensamblado.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Ptacek y Newsham, 1998, y sigue funcionando contra productos mal"
    echo "    ${VERDE}  ${FIN} hechos: si el sensor resuelve el solape con OTRA politica que el"
    echo "    ${VERDE}  ${FIN} destino, reconstruye un flujo que el endpoint nunca vera y todas sus"
    echo "    ${VERDE}  ${FIN} reglas miran datos que no existieron. Aqui la politica es un enumerado"
    echo "    ${VERDE}  ${FIN} que se ELIGE, y las dos variantes reconstruyen de verdad cosas"
    echo "    ${VERDE}  ${FIN} distintas: si no, la politica no existiria)"
    echo "    ${GRIS}Y la mitad peligrosa: el solape que llega DESPUES de entregar los bytes.${FIN}"
    echo "    ${GRIS}Sin ventana de historia eso es indistinguible de una retransmision y el${FIN}"
    echo "    ${GRIS}ataque pasa contado como ruido. La ventana esta acotada y su limite se${FIN}"
    echo "    ${GRIS}DECLARA: mas atras se cuenta como retransmision, que es lo unico que se${FIN}"
    echo "    ${GRIS}puede afirmar, en vez de mentir en cualquiera de los dos sentidos.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el reensamblado no resiste la evasion por solape"
    sed 's/^/    | /' /tmp/aegis-wire-reensamblado.log | tail -30
    exit 1
fi

echo "==> AegisWire: los disectores contra entrada hostil (DNS, HTTP, TLS, DER...)"
if cargo test -p aegis-wire --quiet -- dns:: http:: tls:: der:: ipv6:: smb:: directorio:: texto:: udp:: md5:: lector:: \
    >/tmp/aegis-wire-disectores.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el bucle de punteros de compresion DNS corta con progreso estricto;"
    echo "    ${VERDE}  ${FIN} el ASN.1 se recorre con PILA EXPLICITA y no con recursion, porque un"
    echo "    ${VERDE}  ${FIN} DER anidado a proposito revienta la pila de un disector recursivo; la"
    echo "    ${VERDE}  ${FIN} cadena de extensiones IPv6 DECLARA que no pudo llegar al transporte en"
    echo "    ${VERDE}  ${FIN} vez de rendirse en silencio, que es justo lo que busca quien la manda;"
    echo "    ${VERDE}  ${FIN} y el contrabando HTTP con Content-Length y Transfer-Encoding a la vez"
    echo "    ${VERDE}  ${FIN} se delata con su codigo)"
    echo "    ${GRIS}Las huellas JA3/JA3S/JA4 filtran GREASE: sin ese filtro la huella de${FIN}"
    echo "    ${GRIS}Chrome cambia en cada conexion y no sirve para reconocer nada.${FIN}"
    echo "    ${GRIS}Y el MD5 de aqui es SOLO una etiqueta de interoperabilidad JA3: esta${FIN}"
    echo "    ${GRIS}escrito y documentado como tal, y jamas se usa para seguridad.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: algun disector no aguanta su entrada hostil"
    sed 's/^/    | /' /tmp/aegis-wire-disectores.log | tail -30
    exit 1
fi

echo "==> AegisWire: las cotas de memoria, MEDIDAS bajo el ataque que las busca"
if cargo test -p aegis-wire --quiet -- flujo:: motor::pruebas::retener \
    motor::pruebas::expulsar motor::pruebas::la_contabilidad motor::pruebas::el_bufer \
    motor::pruebas::abrir motor::pruebas::un_cuerpo_enorme ficheros::pruebas::un_fichero_gigante \
    >/tmp/aegis-wire-cotas.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (y la cota que de verdad sostiene el presupuesto es la GLOBAL: una"
    echo "    ${VERDE}  ${FIN} cota por flujo multiplicada por un numero de flujos que elige el"
    echo "    ${VERDE}  ${FIN} atacante NO es una cota, es un producto. Medido: con solo la cota por"
    echo "    ${VERDE}  ${FIN} flujo, 3.000 flujos reteniendo UN segmento cada uno ya reservan 4 MB,"
    echo "    ${VERDE}  ${FIN} que extrapolado al tope de flujos son 133 MB en un agente cuyo"
    echo "    ${VERDE}  ${FIN} presupuesto ENTERO son 45. Con el techo global: 256 KB)"
    echo "    ${GRIS}Expulsar un flujo suelta TAMBIEN su bufer de aplicacion y su${FIN}"
    echo "    ${GRIS}transferencia en curso. Sin eso no seria un peor caso teorico: seria${FIN}"
    echo "    ${GRIS}una fuga, una por cada expulsion.${FIN}"
    echo "    ${GRIS}Y un cuerpo HTTP de ocho megas ATRAVIESA el motor sin acumularse: el${FIN}"
    echo "    ${GRIS}hash se calcula al vuelo, asi que mirar ficheros grandes no cuesta${FIN}"
    echo "    ${GRIS}memoria proporcional a su tamano.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: las cotas de memoria no se sostienen bajo ataque"
    sed 's/^/    | /' /tmp/aegis-wire-cotas.log | tail -30
    exit 1
fi

echo "==> AegisWire: extraccion de ficheros por CONTENIDO, no por lo que se declare"
if cargo test -p aegis-wire --quiet ficheros:: \
    >/tmp/aegis-wire-ficheros.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el nombre y el Content-Type los escribe quien manda el fichero: un"
    echo "    ${VERDE}  ${FIN} 'application/pdf' sobre un PE no es un caso raro, es LA tecnica. El"
    echo "    ${VERDE}  ${FIN} tipo sale de los BYTES, y la contradiccion entre lo declarado y lo real"
    echo "    ${VERDE}  ${FIN} se emite como senal propia. Un fichero honesto no levanta ninguna, que"
    echo "    ${VERDE}  ${FIN} es lo que impide que la senal se entierre en ruido)"
    echo "    ${GRIS}El hash de un fichero troceado en 1.400 trozos es el MISMO que el del${FIN}"
    echo "    ${GRIS}fichero entero: si no lo fuera, trocear la descarga evadiria la${FIN}"
    echo "    ${GRIS}comparacion contra indicadores, que es gratis para el atacante.${FIN}"
    echo "    ${GRIS}Y la ISO se reconoce EN FLUJO con su magia 32 KB dentro, sin guardar${FIN}"
    echo "    ${GRIS}esos 32 KB: es el vehiculo que se usa hoy para saltarse la marca de${FIN}"
    echo "    ${GRIS}procedencia de Windows, y renunciar a verlo no era una opcion.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la extraccion de ficheros no cumple su contrato"
    sed 's/^/    | /' /tmp/aegis-wire-ficheros.log | tail -30
    exit 1
fi

echo "==> AegisWire: los ataques de extremo a extremo, con paquetes de verdad"
if cargo test -p aegis-wire --quiet --test evasion \
    >/tmp/aegis-wire-evasion.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (paquetes IPv4+TCP construidos byte a byte y metidos por el mismo"
    echo "    ${VERDE}  ${FIN} sitio por el que entraria el trafico real. Se comprueban las TRES"
    echo "    ${VERDE}  ${FIN} cosas juntas: que reconstruye lo que reconstruiria el destino, que"
    echo "    ${VERDE}  ${FIN} DELATA el intento, y que sigue vivo y acotado despues. Un sensor que"
    echo "    ${VERDE}  ${FIN} resiste un ataque sin contarlo deja al analista sin saber que le"
    echo "    ${VERDE}  ${FIN} atacaron: eso no es defensa, es un agujero con buena cara)"
    echo "    ${GRIS}Un fragmento IP POSTERIOR no se analiza como transporte: leerlo asi${FIN}"
    echo "    ${GRIS}interpretaria carga util como puertos y numero de secuencia, e${FIN}"
    echo "    ${GRIS}inyectaria bytes elegidos por el atacante en el reensamblador.${FIN}"
    echo "    ${GRIS}Y un mensaje se cuenta UNA VEZ: el disector siempre empieza por el${FIN}"
    echo "    ${GRIS}principio del bufer, asi que no apartar lo ya interpretado repetiria${FIN}"
    echo "    ${GRIS}sus hechos en cada paquete Y dejaria sin ver la segunda peticion de${FIN}"
    echo "    ${GRIS}una conexion reutilizada — gratis de explotar encadenando la descarga${FIN}"
    echo "    ${GRIS}detras de algo inocente.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: los ataques de extremo a extremo no pasan"
    sed 's/^/    | /' /tmp/aegis-wire-evasion.log | tail -30
    exit 1
fi

echo "==> AegisWire: cero dependencias externas nuevas (superficie de ataque)"
# Los crates 'aegis-*' son propios y no cuentan como superficie importada: su
# codigo es nuestro y cada uno tiene su propia verificacion. Lo que se vigila
# aqui es lo de TERCEROS, que es lo que no auditamos linea a linea.
EXTERNAS=$(cargo tree -p aegis-wire --edges normal --prefix none 2>/dev/null \
    | awk '{print $1}' | sort -u | grep -vE '^(aegis-|$)' || true)
# El cierre COMPLETO de sha2 + thiserror, enumerado a proposito en vez de con un
# patron laxo: si manana entra algo, tiene que doler.
PERMITIDAS='^(sha2|thiserror|thiserror-impl|cfg-if|generic-array|typenum|digest|block-buffer|crypto-common|cpufeatures|libc|proc-macro2|quote|syn|unicode-ident)$'
EXTRA=$(echo "$EXTERNAS" | grep -vE "$PERMITIDAS" || true)
CUANTAS=$(echo "$EXTERNAS" | grep -c . || true)
if [ -z "$EXTRA" ]; then
    echo "    ${VERDE}OK${FIN} (${CUANTAS} crates de terceros en total, y son el cierre entero de"
    echo "    ${VERDE}  ${FIN} sha2 —que ya enlazaba el agente, y que JA4 necesita por definicion del"
    echo "    ${VERDE}  ${FIN} estandar— y de thiserror. Nada mas entra al camino que analiza bytes"
    echo "    ${VERDE}  ${FIN} hostiles: comparese con los 340 crates que arrastra libp2p, que por eso"
    echo "    ${VERDE}  ${FIN} mismo vive fuera del agente)"
else
    echo "    ${ROJO}FALLO${FIN}: han entrado dependencias de terceros no justificadas:"
    echo "$EXTRA" | sed 's/^/    | /'
    echo "    ${ROJO}     ${FIN} Si la nueva dependencia es necesaria, justificala en el Cargo.toml"
    echo "    ${ROJO}     ${FIN} del crate y anadela aqui A PROPOSITO. Ampliar el patron sin pensar"
    echo "    ${ROJO}     ${FIN} es como se cuela un arbol de dependencias entero sin que nadie lo vea."
    exit 1
fi
exit 0
