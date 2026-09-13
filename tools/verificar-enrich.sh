#!/usr/bin/env bash
#
# Verificacion de AegisEnrich (enriquecimiento con privacidad, FASE 77).
#
# LA REGLA QUE DEFINE LA FASE: consultar por un resumen le dice al proveedor que
# ese fichero esta en tu red. No es un efecto secundario de la consulta: ES la
# consulta. Le das informacion que no tenia, gratis, y no se puede retirar.
#
# Casi siempre compensa. Pero «casi siempre» es una decision, y una decision que
# nadie ve no es una decision: es un valor por defecto. De modo que el marco
# obliga a DECLARAR que sale, y el panel se lo enseña al analista ANTES de
# ejecutar el analizador.
#
# Las cinco cosas que se comprueban aqui, y por que ninguna se puede dar por
# supuesta:
#
#   - un analizador que se cuelga corre mientras un analista espera, asi que si
#     no se corta de verdad, bloquea al resto y el enriquecimiento entero deja de
#     usarse;
#   - el modo sin salida tiene que cumplirse POR CONSTRUCCION: una bandera
#     `si sin_salida: no consultes` es opcional, y el analizador que se escriba el
#     mes que viene se la olvida;
#   - lo que devuelve un analizador lo escribio un tercero por Internet, dentro
#     del proceso con mas privilegios del producto;
#   - la cuota se comprueba bajo concurrencia porque comprobar-y-actuar deja
#     pasar de mas, y pasarse de cuota corta el servicio justo durante un
#     incidente;
#   - y la fusion tiene que ser determinista, o dos ejecuciones sobre el mismo
#     incidente dan resultados distintos y el informe no vale.
#
# EL MURO, declarado en vez de disimulado: esta puerta no habla con ningun
# proveedor real. No es una limitacion de la maquina de integracion: es que una
# puerta de calidad que depende de un tercero por Internet falla los dias que ese
# tercero tiene un mal dia, y una puerta que falla sin motivo se acaba ignorando.
# Lo que se ejercita es la maquinaria que DECIDE —las puertas, el aislamiento, la
# cuota, el saneado y la fusion—, que es donde estan los fallos que importan.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisEnrich: las nueve piezas del marco"
if (cd server && cargo test -q -p aegis-enrich) > /tmp/aegis-enrich.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-enrich.log | head -1))"
    echo "    ${GRIS}La comprobacion de privacidad esta en UN sitio y no en cada${FIN}"
    echo "    ${GRIS}analizador: una regla repartida por veinte analizadores es una${FIN}"
    echo "    ${GRIS}regla que el analizador numero veintiuno se salta sin que nadie lo${FIN}"
    echo "    ${GRIS}note. Una cuenta de usuario, una ruta, una linea de ordenes y una${FIN}"
    echo "    ${GRIS}direccion privada NO salen — y la respuesta dice POR QUE, porque${FIN}"
    echo "    ${GRIS}«no se consulto» sin motivo se lee igual que «no habia nada».${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-enrich.log)"
    tail -30 /tmp/aegis-enrich.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnrich: un enriquecimiento real, con las cinco propiedades a la vez"
if (cd server && CARGO_INCREMENTAL=0 cargo run -q -p aegis-enrich --example consulta) \
    > /tmp/aegis-consulta.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-consulta.log
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Lo que esta ejecucion enseña y una prueba unitaria no puede: las${FIN}"
    echo "    ${GRIS}cinco propiedades se sostienen A LA VEZ. El analizador que se cuelga${FIN}"
    echo "    ${GRIS}corre junto al que entra en panico, al que devuelve basura y al que${FIN}"
    echo "    ${GRIS}funciona — y el analista recibe su veredicto igual, con la cuenta de${FIN}"
    echo "    ${GRIS}quien dijo que y de que fallo cada cual.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}"
    tail -40 /tmp/aegis-consulta.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnrich: ningun analizador abre su propia conexion"
# Esto es lo que `salida.rs` promete y no puede imponer por si solo: el modo sin
# salida se cumple porque al analizador no se le ENTREGA por donde salir, pero
# Rust no puede negarle el acceso a la biblioteca estandar. De modo que la
# frontera se comprueba aqui, sobre el codigo, y no se deja en una promesa: un
# analizador que llamara directamente a las primitivas de red se saltaria el modo
# entero sin que nadie lo notara hasta que un cliente con la red aislada viera
# trafico saliente.
#
# Se miran lineas de CODIGO, no comentarios: `salida.rs` nombra `std::net` en su
# encabezado justo para explicar este muro, y una comprobacion que castigara
# documentar el riesgo empujaria a dejar de documentarlo.
PROHIBIDO='std::net|TcpStream|UdpSocket|TcpListener|reqwest|hyper::Client|ureq|curl'
if FUGAS=$(grep -rnE "$PROHIBIDO" server/crates/aegis-enrich/src server/crates/aegis-enrich/examples 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'); then
    echo "    ${ROJO}FALLO${FIN}: hay codigo que abre su propia conexion, saltandose la frontera"
    echo "$FUGAS" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
else
    echo "    ${VERDE}OK${FIN}: la unica via a la red es la capacidad que entrega el orquestador"
    echo "    ${GRIS}La diferencia que esto defiende es la que va de «prometio no salir»${FIN}"
    echo "    ${GRIS}a «no se le dio por donde». Un analizador recibe Option<&dyn Salida>,${FIN}"
    echo "    ${GRIS}y en modo sin salida ese objeto sencillamente no existe: no hay nada${FIN}"
    echo "    ${GRIS}que entregarle, asi que no hay nada que se pueda olvidar comprobar.${FIN}"
fi

echo "==> AegisEnrich: la declaracion de exposicion es obligatoria en el TIPO"
# Un campo de texto libre se rellena con «consulta reputacion» y no dice nada. Lo
# que hace que la declaracion valga es que sea un tipo con enumerados cerrados y
# un campo obligatorio de la ficha: un analizador sin exposicion declarada NO
# COMPILA, que es la unica forma de que nadie se la salte.
if grep -q "pub exposicion: Exposicion," server/crates/aegis-enrich/src/analizador.rs \
    && grep -q "pub enum Campo" server/crates/aegis-enrich/src/exposicion.rs \
    && grep -q "pub enum Destino" server/crates/aegis-enrich/src/exposicion.rs; then
    echo "    ${VERDE}OK${FIN}: es un campo de la ficha, con enumerados cerrados"
    echo "    ${GRIS}Y la clase de la fuente tampoco la elige el analizador: viene del${FIN}"
    echo "    ${GRIS}registro. Si viniera en la respuesta, un canal comunitario podria${FIN}"
    echo "    ${GRIS}declararse autoritativo y saltarse la jerarquia entera de la fusion,${FIN}"
    echo "    ${GRIS}que es la escalada de privilegios que se monta sobre un sistema de${FIN}"
    echo "    ${GRIS}reputacion.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la exposicion dejo de ser obligatoria en el tipo"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnrich: proveedores reales"
if [ -n "${AEGIS_ENRICH_CLAVES:-}" ]; then
    echo "    ${VERDE}disponible${FIN}: AEGIS_ENRICH_CLAVES configurada"
else
    echo "    ${GRIS}AUSENTE${FIN}: sin claves no se habla con ningun proveedor real."
    echo "    ${GRIS}Y es deliberado: una puerta de calidad que depende de un tercero por${FIN}"
    echo "    ${GRIS}Internet falla los dias que ese tercero tiene un mal dia, y una${FIN}"
    echo "    ${GRIS}puerta que falla sin motivo se acaba ignorando — que es peor que no${FIN}"
    echo "    ${GRIS}tenerla. Lo que SI queda comprobado arriba, contra codigo real: el${FIN}"
    echo "    ${GRIS}orden de las seis puertas, con la de privacidad primero por ser la${FIN}"
    echo "    ${GRIS}unica irreversible; el corte por plazo de un analizador colgado; la${FIN}"
    echo "    ${GRIS}recogida de uno que entra en panico; el saneado de una respuesta${FIN}"
    echo "    ${GRIS}manipulada; 1.440 peticiones concurrentes contra una rafaga de 100; y${FIN}"
    echo "    ${GRIS}doce fusiones seguidas que dan exactamente el mismo veredicto.${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisEnrich verificado${FIN}"
else
    echo "${ROJO}==> AegisEnrich: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
