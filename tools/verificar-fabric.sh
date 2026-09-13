#!/usr/bin/env bash
#
# Verificacion de AegisFabric (un solo modelo de entidad, un solo veredicto, FASE 79).
#
# LA TESIS, dicha sin adornos: nueve subsistemas de deteccion, cada uno con su
# propia idea de «que es una cosa» y su propio enumerado de veredicto, producen
# NUEVE SUCESOS SIN RELACION ante un mismo ataque. Antes de esta fase este arbol
# tenia DOCE enumerados de veredicto y NUEVE de severidad, y ninguno estaba mal
# por separado — lo que no habia era una sola tabla que dijera cual se traduce a
# cual.
#
# Lo que esta fase construye no es una capa mas: es el tejido que hace que la
# misma cosa se llame igual en los nueve, y que lo que digan se combine en un
# sitio con un criterio que se puede leer. Eso NO se consigue integrando productos
# de fabricantes distintos, y es la unica ventaja de este diseño que no se puede
# copiar comprando.
#
# EL MURO, declarado en vez de disimulado: el circuito no detona en un hipervisor
# real ni abre sockets. No es una limitacion de la maquina de integracion — es que
# CADA subsistema ya ejerce eso en su propia puerta (aegis-detonate arranca microVM
# de verdad, aegis-wire lee paquetes byte a byte). Lo que aqui corre es la UNION,
# que es lo unico que ninguna de esas puertas puede comprobar: que el fichero que
# el disector extrae del flujo y el que el detonador detona son, para el sistema,
# la misma cosa.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisFabric: el modelo de entidad, la escala, el arbitro y el linaje"
if cargo test -q -p aegis-entidad > /tmp/aegis-entidad.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-entidad.log | head -1))"
    echo "    ${GRIS}El identificador se DERIVA, no se coordina: dos observadores con los${FIN}"
    echo "    ${GRIS}mismos hechos llegan al mismo nombre sin hablar entre ellos — es el${FIN}"
    echo "    ${GRIS}reparto por sorteo de aegis-scale aplicado a nombrar cosas. Y lo que${FIN}"
    echo "    ${GRIS}mas importa es lo que NO se fusiona: un PID reciclado no hereda la${FIN}"
    echo "    ${GRIS}historia del anterior (por eso el identificador lleva el arranque),${FIN}"
    echo "    ${GRIS}el contenido y la ubicacion son entidades DISTINTAS (el mismo fichero${FIN}"
    echo "    ${GRIS}en dos rutas no es una cosa, y dos ficheros distintos en la misma ruta${FIN}"
    echo "    ${GRIS}tampoco), y el mismo flujo visto desde los dos extremos SI es uno.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-entidad.log)"
    tail -30 /tmp/aegis-entidad.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: el inventario y la costura de traduccion"
if (cd server && cargo test -q -p aegis-tejido --lib) > /tmp/aegis-tejido-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-tejido-lib.log | head -1))"
    echo "    ${GRIS}El inventario esta en el codigo y no en un documento por una razon${FIN}"
    echo "    ${GRIS}comprobable: un documento se queda viejo en silencio. La puerta${FIN}"
    echo "    ${GRIS}recorre los trece motores y exige que cada uno tenga su fila, asi que${FIN}"
    echo "    ${GRIS}un motor nuevo sin traduccion declarada ROMPE la compilacion de las${FIN}"
    echo "    ${GRIS}pruebas. Y la traduccion vive en UN modulo por lo mismo que el${FIN}"
    echo "    ${GRIS}estrangulamiento de difusion de la FASE 78: una regla repartida por${FIN}"
    echo "    ${GRIS}veinte sitios es una regla que el veintiuno se salta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-tejido-lib.log)"
    tail -30 /tmp/aegis-tejido-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: el circuito completo, once subsistemas y un identificador"
if (cd server && cargo test -q -p aegis-tejido --test circuito) > /tmp/aegis-circuito.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-circuito.log | head -1))"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-circuito.log)"
    tail -40 /tmp/aegis-circuito.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: la ejecucion entera, con las cinco propiedades a la vez"
if (cd server && CARGO_INCREMENTAL=0 cargo run -q -p aegis-tejido --example circuito) \
    > /tmp/aegis-fabric.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-fabric.log
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Lo que esta ejecucion enseña y una prueba unitaria no puede: que el${FIN}"
    echo "    ${GRIS}paquete que entra por la red y el indicador que sale por TAXII hablan${FIN}"
    echo "    ${GRIS}de la MISMA entidad, con el mismo identificador, habiendo pasado por${FIN}"
    echo "    ${GRIS}el corpus mundial, la microVM, el arbitro, el caso, el${FIN}"
    echo "    ${GRIS}enriquecimiento, el camino de ataque, la contencion y el enjambre.${FIN}"
    echo "    ${GRIS}Un conjunto de productos integrados no puede dar eso: cada uno nombra${FIN}"
    echo "    ${GRIS}las cosas a su manera y la correlacion acaba siendo una heuristica${FIN}"
    echo "    ${GRIS}sobre cadenas de texto que casi acierta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-fabric.log)"
    tail -40 /tmp/aegis-fabric.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: el arbol del endpoint no crece ni un crate"
# LA COMPROBACION NO ES «POCAS DEPENDENCIAS», ES «NINGUNA NUEVA». Contar crates
# invita a discutir si diez son muchos o pocos. Lo que importa es otra cosa: que
# TODO lo que aegis-entidad arrastra el agente YA lo tenia, asi que unificar el
# modelo de entidad no amplia ni un crate la superficie de ataque del endpoint.
cargo tree -p aegis-entidad --edges normal --prefix none 2>/dev/null \
    | awk '{print $1}' | grep -v '^aegis-entidad$' | grep . | sort -u > /tmp/aegis-arbol-entidad.txt
cargo tree -p aegis-agent --edges normal --prefix none 2>/dev/null \
    | awk '{print $1}' | grep . | sort -u > /tmp/aegis-arbol-agente.txt
NUEVAS=$(comm -23 /tmp/aegis-arbol-entidad.txt /tmp/aegis-arbol-agente.txt)
CUANTAS=$(printf '%s' "$NUEVAS" | grep -c . || true)
TOTAL=$(grep -c . /tmp/aegis-arbol-entidad.txt || true)
if [ "${CUANTAS:-0}" -eq 0 ]; then
    echo "    ${VERDE}OK${FIN}: 0 crates nuevos; los $TOTAL que arrastra el agente ya los tenia"
    echo "    ${GRIS}El nucleo de esta fase corre en el ENDPOINT, no solo en el servidor:${FIN}"
    echo "    ${GRIS}el agente tiene que poder derivar el identificador y arbitrar sin${FIN}"
    echo "    ${GRIS}preguntarle a nadie. Su unica dependencia directa es sha2, que el${FIN}"
    echo "    ${GRIS}agente YA tenia por aegis-sync. En un producto que corre con${FIN}"
    echo "    ${GRIS}privilegios en cada maquina ese arbol ES superficie de ataque, y la${FIN}"
    echo "    ${GRIS}mitad del diseño de esta fase es que la unificacion no lo engorde.${FIN}"
    echo "    ${GRIS}Contar crates invitaria a discutir si diez son muchos; lo que se${FIN}"
    echo "    ${GRIS}comprueba es que no hay NINGUNO nuevo, que no admite discusion.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: $CUANTAS crate(s) que el agente no tenia"
    printf '%s\n' "$NUEVAS" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: el tejido no se cuela en el agente"
if grep -q "aegis-tejido" crates/*/Cargo.toml 2>/dev/null; then
    echo "    ${ROJO}FALLO${FIN}: un crate del agente depende de aegis-tejido"
    grep -l "aegis-tejido" crates/*/Cargo.toml | sed 's/^/    | /'
    echo "    ${ROJO}El tejido depende de TODOS los subsistemas, incluidos los del${FIN}"
    echo "    ${ROJO}servidor: meterlo en el agente arrastraria tokio, sqlx y compañia al${FIN}"
    echo "    ${ROJO}proceso privilegiado del endpoint.${FIN}"
    FALLOS=$((FALLOS + 1))
else
    echo "    ${VERDE}OK${FIN}: ningun crate del agente depende del tejido"
    echo "    ${GRIS}La direccion de la dependencia importa: el tejido depende de todos${FIN}"
    echo "    ${GRIS}los subsistemas y NINGUNO depende de el. Al reves, el tejido dejaria${FIN}"
    echo "    ${GRIS}de poder cambiar sin tocarlos a todos, y la traduccion volveria a${FIN}"
    echo "    ${GRIS}repartirse por veinte sitios — que es de lo que se venia.${FIN}"
fi

echo "==> AegisFabric: el nombre de cada marcado dice lo que vale"
if grep -q 'Tlp::Amber => "TLP:AMBER"' server/crates/aegis-share/src/marcado.rs \
    && grep -q 'Tlp::AmberStrict => "TLP:AMBER+STRICT"' server/crates/aegis-share/src/marcado.rs; then
    echo "    ${VERDE}OK${FIN}: Tlp::Amber vale TLP:AMBER y Tlp::AmberStrict vale TLP:AMBER+STRICT"
    echo "    ${GRIS}Aqui estuvieron cambiados, y lo encontro esta fase al usar el tipo${FIN}"
    echo "    ${GRIS}desde fuera. El orden era correcto y todas las comprobaciones${FIN}"
    echo "    ${GRIS}funcionaban, asi que NINGUNA prueba lo veia: la ida y vuelta de${FIN}"
    echo "    ${GRIS}etiqueta es estable con los nombres cambiados, porque solo compara el${FIN}"
    echo "    ${GRIS}sistema consigo mismo. Lo que rompe es quien escribe «if tlp <=${FIN}"
    echo "    ${GRIS}Tlp::Amber { compartir }» y sin saberlo deja pasar tambien${FIN}"
    echo "    ${GRIS}AMBER+STRICT. Un identificador que miente sobre su valor es un fallo${FIN}"
    echo "    ${GRIS}de seguridad aunque la aritmetica este bien.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el nombre de una variante de TLP no coincide con su valor"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisFabric: infraestructura real"
echo "    ${GRIS}AUSENTE${FIN}: el circuito no arranca hipervisor ni abre sockets, y es"
echo "    ${GRIS}deliberado. Cada subsistema YA ejerce eso en su propia puerta —${FIN}"
echo "    ${GRIS}aegis-detonate arranca microVM de verdad, aegis-wire reconstruye flujos${FIN}"
echo "    ${GRIS}byte a byte, aegis-swarm habla entre dos nodos libp2p reales—. Lo que${FIN}"
echo "    ${GRIS}esta puerta comprueba es lo que ninguna de esas puede: la UNION. Y esa${FIN}"
echo "    ${GRIS}si corre entera, con el codigo real de los once subsistemas.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisFabric verificado${FIN}"
else
    echo "${ROJO}==> AegisFabric: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
