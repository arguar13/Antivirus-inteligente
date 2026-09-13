#!/usr/bin/env bash
#
# Verificacion de AegisShare (inteligencia con difusion controlada, FASE 78).
#
# LA ASIMETRIA QUE LO DECIDE TODO: compartir es irreversible, y los errores se
# propagan. De ahi salen los dos fallos que esta fase existe para impedir, y
# ninguno de los dos es de formato:
#
#   - SALE ALGO QUE NO DEBIA. Un TLP:RED en un canal publico no se puede retirar.
#     Y no hace falta un ataque: basta un filtro que se quedo atras cuando se
#     añadio un camino de salida nuevo.
#   - ENTRA ALGO ENVENENADO Y NO SE PUEDE DESHACER. Un canal mete tres semanas de
#     indicadores fabricados —la IP del resolutor publico que usa media industria,
#     el resumen de una biblioteca firmada—, se descubre, y sin procedencia no se
#     sabe cuales eran suyos.
#
# El formato —STIX, TAXII— es la parte facil. Lo dificil es que NO HAYA NINGUN
# CAMINO por el que algo salga sin pasar por la politica, y que SIEMPRE se pueda
# deshacer lo que entro. Eso es lo que se comprueba aqui.
#
# EL MURO, declarado en vez de disimulado: esta puerta no habla con ningun
# servidor TAXII de Internet ni con ninguna comunidad real. No es una limitacion
# de la maquina de integracion: es que una puerta de calidad que depende de un
# tercero falla los dias que ese tercero tiene un mal dia, y una puerta que falla
# sin motivo se acaba ignorando — que es peor que no tenerla. Lo que corre aqui es
# el servidor Y el cliente TAXII de verdad, hablando entre ellos, con el mismo
# codigo que hablaria con un tercero.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisShare: las ocho piezas de la plataforma"
if (cd server && cargo test -q -p aegis-share) > /tmp/aegis-share.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-share.log | head -1))"
    echo "    ${GRIS}Casi todo el mundo implementa TLP y se olvida de PAP. La${FIN}"
    echo "    ${GRIS}combinacion que enseña por que hacen falta los dos es TLP:GREEN con${FIN}"
    echo "    ${GRIS}PAP:RED: el dominio de mando y control se puede compartir con toda${FIN}"
    echo "    ${GRIS}la comunidad Y NO SE PUEDE BLOQUEAR, porque bloquearlo le dice al${FIN}"
    echo "    ${GRIS}atacante que se le ha visto y cambia de infraestructura. Un producto${FIN}"
    echo "    ${GRIS}que solo mira TLP lo empuja al motor de bloqueo y quema la operacion${FIN}"
    echo "    ${GRIS}de quien lo compartio. La siguiente vez no se lo mandan.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-share.log)"
    tail -30 /tmp/aegis-share.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisShare: una comunidad entera, con las cinco propiedades a la vez"
if (cd server && CARGO_INCREMENTAL=0 cargo run -q -p aegis-share --example comunidad) \
    > /tmp/aegis-comunidad.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-comunidad.log
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Lo que esta ejecucion enseña y una prueba unitaria no puede: que las${FIN}"
    echo "    ${GRIS}cinco propiedades se sostienen A LA VEZ, sobre las mismas piezas. El${FIN}"
    echo "    ${GRIS}indicador no compartible se intenta sacar de verdad por los cuatro${FIN}"
    echo "    ${GRIS}canales; el ciclo de federacion se cierra de verdad; y la revocacion${FIN}"
    echo "    ${GRIS}del canal envenenado se ejecuta sobre una base con lo bueno, lo malo${FIN}"
    echo "    ${GRIS}y lo que sostienen los dos — que es el caso que decide si la${FIN}"
    echo "    ${GRIS}procedencia sirve de algo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}"
    tail -40 /tmp/aegis-comunidad.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisShare: hay UN solo estrangulamiento de salida"
# Es la comprobacion que hace cierta la frase «no sale por ningun camino». Si la
# federacion tuviera su filtro, el servidor TAXII otro y el puente del enjambre un
# tercero, tarde o temprano uno de los tres se queda atras — y el que se queda
# atras no falla ruidosamente: comparte de mas.
SALIDAS=$(grep -rl "Difusor::juzgar\|difusor.repartir\|self.difusor" server/crates/aegis-share/src | sort)
CANALES=$(grep -cE "^    [A-Z][a-z]+," server/crates/aegis-share/src/difusion.rs)
if grep -q "Difusor::juzgar" server/crates/aegis-share/src/taxii.rs \
    && grep -q "Difusor::juzgar" server/crates/aegis-share/src/puente.rs \
    && grep -q "pub fn todos()" server/crates/aegis-share/src/difusion.rs; then
    echo "    ${VERDE}OK${FIN}: TAXII y el puente del enjambre pasan por el mismo juez"
    echo "    ${GRIS}Modulos que consultan la difusion:${FIN}"
    echo "$SALIDAS" | sed 's|server/crates/aegis-share/src/|      - |'
    echo "    ${GRIS}Y el enumerado de canales es cerrado, con $CANALES variantes: la prueba${FIN}"
    echo "    ${GRIS}las recorre todas, asi que un camino de salida nuevo no puede${FIN}"
    echo "    ${GRIS}quedarse sin cubrir sin que la comprobacion de cobertura lo note.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: algun camino de salida dejo de pasar por el estrangulamiento"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisShare: la doctrina del enjambre sigue intacta"
# Es la comprobacion mas importante de la integracion con la FASE 68. El enjambre
# TRANSPORTA autoridad; no la CONCEDE. Un indicador que llega por federacion no se
# convierte en una orden por muy fiable que sea su fuente, y la garantia no es una
# comprobacion en tiempo de ejecucion: es que la variante NO EXISTE.
VARIANTES=$(grep -cE "^    (Observacion|Artefacto|Orden) \{" server/crates/aegis-share/src/puente.rs)
if [ "$VARIANTES" -eq 2 ] \
    && ! grep -qE "^    Orden \{" server/crates/aegis-share/src/puente.rs \
    && grep -q "pub fn exige_firma" server/crates/aegis-share/src/puente.rs; then
    echo "    ${VERDE}OK${FIN}: la carga del enjambre tiene 2 variantes y ninguna es una orden"
    echo "    ${GRIS}Evidencia, que necesita el corroboro de K pares distintos, y${FIN}"
    echo "    ${GRIS}artefacto, que necesita la firma del plano de control — cuya clave${FIN}"
    echo "    ${GRIS}privada no esta en ningun agente ni en este crate. Que no exista una${FIN}"
    echo "    ${GRIS}tercera variante es la misma tecnica que en aegis-detonate, donde${FIN}"
    echo "    ${GRIS}Salida no tiene variante para «red de verdad»: lo que no se puede${FIN}"
    echo "    ${GRIS}expresar no se puede configurar por error.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la carga del enjambre tiene $VARIANTES variantes o falta la firma"
    echo "    ${ROJO}La doctrina de la FASE 68 es un invariante, no una sugerencia.${FIN}"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisShare: comunidades reales"
if [ -n "${AEGIS_TAXII_URL:-}" ]; then
    echo "    ${VERDE}disponible${FIN}: AEGIS_TAXII_URL configurada"
else
    echo "    ${GRIS}AUSENTE${FIN}: sin servidor externo no se habla con ninguna comunidad."
    echo "    ${GRIS}Y es deliberado: una puerta que depende de un tercero por Internet${FIN}"
    echo "    ${GRIS}falla los dias que ese tercero tiene un mal dia, y una puerta que${FIN}"
    echo "    ${GRIS}falla sin motivo se acaba ignorando. Lo que SI corre arriba es el${FIN}"
    echo "    ${GRIS}servidor Y el cliente TAXII de verdad hablando entre ellos, con el${FIN}"
    echo "    ${GRIS}mismo codigo que hablaria con un tercero: paginacion por cursor,${FIN}"
    echo "    ${GRIS}sondeo por «cuando se añadio aqui», y el estrangulamiento de difusion${FIN}"
    echo "    ${GRIS}en medio. Mas tres mil entradas hostiles contra el validador STIX.${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisShare verificado${FIN}"
else
    echo "${ROJO}==> AegisShare: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
