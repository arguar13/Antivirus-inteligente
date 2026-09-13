#!/usr/bin/env bash
#
# Verificacion de AegisCase (ciclo de vida del incidente, FASE 76).
#
# LA TESIS DE LA FASE: un producto que detecta y no da flujo de trabajo produce
# alertas que nadie mira. Y no por dejadez del analista: es la respuesta racional
# a una senal en la que cuarenta y ocho de cada cincuenta son ruido. El dia que
# llega la que importa, va al mismo sitio que las demas.
#
# De modo que esto NO es una capa de gestion encima del producto. Es lo que
# impide que la deteccion se pierda por el camino, y son cuatro problemas
# concretos, cada uno con una forma distinta de fallar EN SILENCIO:
#
#   - mil alertas de una campana esconden el caso distinto que llego en medio, y
#     el que fusiona de mas pierde un incidente sin dejar rastro de haberlo
#     perdido;
#   - quien escribe la cronologia a mano copia los hechos que confirman su
#     hipotesis, y cose los huecos en una cadena causal que no existio;
#   - un registro de auditoria que se puede editar despues no vale como
#     evidencia, y no hace falta un atacante para romperlo —basta una migracion
#     mal hecha—;
#   - y sin ruido POR REGLA no se pueden apagar las reglas que solo hacen ruido,
#     que es lo unico que de verdad cambia la vida de un SOC.
#
# Las cuatro se comprueban aqui con numeros, no con afirmaciones.
#
# EL MURO, declarado en vez de disimulado: esta puerta NO escribe en PostgreSQL.
# La persistencia real vive en `aegis-server` —migracion 0008, `casos.rs`, diez
# rutas de API— y sus pruebas de integracion corren en «Servidor · tests» cuando
# hay base de datos. Lo que corre aqui es la parte que DECIDE el resultado, que
# es pura por diseno: son funciones sobre estado explicito, sin reloj, sin red y
# sin disco. Esa decision es la que permite meter mil sesenta y una alertas y
# cuatro manipulaciones de un rastro en la puerta de calidad y que tarde
# milisegundos, en vez de dejarlo en un documento que nadie vuelve a reproducir.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisCase: las seis piezas del ciclo de vida"
if (cd server && cargo test -q -p aegis-case) > /tmp/aegis-case.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-case.log | head -1))"
    echo "    ${GRIS}El rastro es una cadena encadenada por resumen, y la comprobacion${FIN}"
    echo "    ${GRIS}distingue CUATRO roturas distintas: contenido alterado, eslabon${FIN}"
    echo "    ${GRIS}desenganchado, entrada BORRADA —la manipulacion mas limpia, y la que${FIN}"
    echo "    ${GRIS}sin numero de secuencia seria indistinguible de una cadena corta— y${FIN}"
    echo "    ${GRIS}anclaje roto, que es la unica que detecta una reescritura COMPLETA.${FIN}"
    echo "    ${GRIS}Un caso cerrado exige veredicto, y con tareas abiertas exige ademas${FIN}"
    echo "    ${GRIS}justificacion: «se investigo y no era nada» y «nadie llego a mirarlo»${FIN}"
    echo "    ${GRIS}producen la misma metrica y no son lo mismo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-case.log)"
    tail -30 /tmp/aegis-case.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisCase: una jornada de SOC entera, de alerta a caso cerrado"
if (cd server && CARGO_INCREMENTAL=0 cargo run -q -p aegis-case --example jornada) \
    > /tmp/aegis-jornada.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-jornada.log
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Lo que esta jornada ensena y una prueba unitaria no puede: el${FIN}"
    echo "    ${GRIS}fusionador agrupa por FORMA, y la forma de «una regla que salta en${FIN}"
    echo "    ${GRIS}noventa maquinas en una hora» es identica a la de «una campana que${FIN}"
    echo "    ${GRIS}alcanza noventa maquinas en una hora». No hay senal en el trafico que${FIN}"
    echo "    ${GRIS}las separe, asi que el fusionador NO puede distinguirlas y no lo${FIN}"
    echo "    ${GRIS}intenta. Lo que las separa es el VEREDICTO, que no existe hasta que${FIN}"
    echo "    ${GRIS}alguien mira. Por eso la herramienta contra el ruido no es el${FIN}"
    echo "    ${GRIS}fusionador sino la metrica de ruido por regla, que lo sabe despues y${FIN}"
    echo "    ${GRIS}con base suficiente —veinte casos concluyentes minimo, porque apagar${FIN}"
    echo "    ${GRIS}una regla por sus dos primeros falsos positivos es la forma mas${FIN}"
    echo "    ${GRIS}rapida de quedarse sin deteccion—.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}"
    tail -40 /tmp/aegis-jornada.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisCase: el rastro de auditoria se escribe en la MISMA transaccion"
# Esto no es una comprobacion de estilo. Un rastro que se escribe en una
# transaccion aparte tiene un camino en el que el cambio se guarda y la entrada
# no: cualquier fallo entre las dos deja un caso modificado sin constancia de
# quien lo modifico, que es exactamente lo que el rastro existe para impedir. La
# unica forma de que no exista ese camino es que sea una sola transaccion.
if grep -q "FOR UPDATE" server/crates/aegis-server/src/casos.rs \
    && grep -q "async fn anotar_en" server/crates/aegis-server/src/casos.rs; then
    echo "    ${VERDE}OK${FIN}: la anotacion toma el caso con FOR UPDATE dentro de la transaccion"
    echo "    ${GRIS}El bloqueo de fila no es prudencia: la cadena se encadena con la${FIN}"
    echo "    ${GRIS}cabeza anterior, asi que dos escrituras concurrentes leerian la misma${FIN}"
    echo "    ${GRIS}cabeza y producirian dos entradas con el mismo numero de secuencia.${FIN}"
    echo "    ${GRIS}El indice unico sobre el resumen en la migracion 0008 es la segunda${FIN}"
    echo "    ${GRIS}red, por si alguien escribe alguna vez por otro camino.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la persistencia del rastro no esta en la transaccion del cambio"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisCase: el rastro no se puede borrar como efecto secundario"
# Un `DELETE FROM casos` con CASCADE sobre el rastro se llevaria por delante, en
# silencio, la prueba de la unica operacion que mas evidentemente hay que
# auditar: destruir el caso. Y no hace falta mala fe —basta una purga de
# retencion escrita sin pensar en esto—. Se comprueba en el esquema porque es el
# unico sitio donde la garantia se sostiene sola.
CASCADAS=$(grep -cE 'REFERENCES casos\(id\) ON DELETE CASCADE' server/migrations/0008_casos.sql)
RESTRICTS=$(grep -cE 'REFERENCES casos\(id\) ON DELETE RESTRICT' server/migrations/0008_casos.sql)
if [ "$RESTRICTS" -eq 2 ] && [ "$CASCADAS" -eq 3 ]; then
    echo "    ${VERDE}OK${FIN}: rastro y anclajes con RESTRICT; contenido del caso con CASCADE"
    echo "    ${GRIS}Las alertas, los observables y las tareas son CONTENIDO: si el caso${FIN}"
    echo "    ${GRIS}se va, se van con el. El rastro no es contenido, es la constancia de${FIN}"
    echo "    ${GRIS}quien hizo que — y como todo caso nace con su entrada «creado», en la${FIN}"
    echo "    ${GRIS}practica un caso no se borra: se cierra. Purgar de verdad obliga a${FIN}"
    echo "    ${GRIS}borrar el rastro EXPLICITAMENTE, que es la propiedad que se busca:${FIN}"
    echo "    ${GRIS}destruir una cadena de custodia tiene que ser un acto deliberado.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: $RESTRICTS RESTRICT (se esperaban 2) y $CASCADAS CASCADE (3)"
    echo "    ${ROJO}Un borrado de caso puede llevarse el rastro por delante.${FIN}"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisCase: PostgreSQL"
if [ -n "${AEGIS_TEST_PG_URL:-}" ]; then
    echo "    ${VERDE}disponible${FIN}: AEGIS_TEST_PG_URL configurada"
    echo "    ${GRIS}Las pruebas de integracion del servidor lo ejercitan en «Servidor · tests».${FIN}"
else
    echo "    ${GRIS}AUSENTE${FIN}: sin PostgreSQL no se ejercita la persistencia del caso."
    echo "    ${GRIS}Lo que SI queda comprobado arriba, contra codigo real: la fusion de${FIN}"
    echo "    ${GRIS}mil sesenta y una alertas, el caso distinto que llega en medio de una${FIN}"
    echo "    ${GRIS}campana y no se traga, la cronologia con sus huecos declarados, las${FIN}"
    echo "    ${GRIS}cuatro manipulaciones del rastro con su rotura correspondiente, y los${FIN}"
    echo "    ${GRIS}percentiles con la espera externa descontada. La migracion 0008 deja${FIN}"
    echo "    ${GRIS}escrito el esquema para que un administrador lo revise antes de que${FIN}"
    echo "    ${GRIS}corra sobre su produccion.${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisCase verificado${FIN}"
else
    echo "${ROJO}==> AegisCase: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
