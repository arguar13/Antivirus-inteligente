#!/usr/bin/env bash
#
# Verificacion de AegisStore (FASE 96): el almacen historico indexado por
# entidad, con AegisQL de coste declarado.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. UNA CONSULTA NO TUMBA EL ALMACEN, antes que nada: una consulta que
#      barreria demasiados dias sin filtro de tiempo ni de entidad se RECHAZA
#      antes de leer un solo segmento, y el error dice como arreglarla; la misma
#      consulta, acotada como sugiere, se ejecuta. Contra PostgreSQL real.
#   2. El lenguaje: toda consulta del endpoint da el MISMO arbol por el
#      analizador del historico, y el del endpoint sigue rechazando todo lo que
#      solo existe contra el almacen (ventanas, agregaciones, subconsultas).
#   3. El almacen contra PostgreSQL real: particiones declarativas, purga por
#      DROP, solo las columnas que la consulta usa, indice primario por entidad,
#      secundarios solo si se declaran, agregacion con cubos de tiempo, y la
#      retencion caliente/tibio/frio leyendo el frio de fichero.
#   4. LA MISMA CONSULTA contra el endpoint y contra el historico: el ejecutor
#      REAL del endpoint sobre una tabla REAL de esta maquina y el almacen sobre
#      esas mismas filas devuelven lo mismo.
#
# EL MURO, DECLARADO: la comparativa con OpenSearch no esta hecha (ver docs/87);
# el volumen medido es el de esta maquina, no el de un cluster de produccion.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-almacen-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

echo "==> AegisStore: UNA CONSULTA NO TUMBA EL ALMACEN — la cara se rechaza antes de leer"
if (cd server && cargo test -p aegis-almacen --quiet --test pg -- --nocapture \
        una_consulta_cara_sin_filtro_se_rechaza_con_un_mensaje_util) >"$TMP/rechazo.log" 2>&1; then
    if grep -q 'OMITIDA' "$TMP/rechazo.log"; then
        echo "    ${GRIS}OMITIDO: no hay PostgreSQL; el rechazo no se ejercio contra la base${FIN}"
    else
        grep -m1 'consulta rechazada' "$TMP/rechazo.log" | cut -c1-200 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
        echo "    ${VERDE}OK${FIN} (rechazada sin preguntar por un solo segmento; acotada como sugiere, se ejecuta)"
    fi
else
    fallo "la consulta cara no se rechaza, o la acotada no se ejecuta" "$TMP/rechazo.log"
fi

echo "==> AegisStore: el lenguaje del historico y el del endpoint"
if cargo test -p aegis-parser --quiet >"$TMP/parser.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/parser.log" | head -1))"
else
    fallo "aegis-parser" "$TMP/parser.log"
fi

echo "==> AegisStore: codec, planificador, ejecutor y retencion"
if (cd server && cargo test -p aegis-almacen --quiet --lib) >"$TMP/lib.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/lib.log" | head -1))"
else
    fallo "aegis-almacen" "$TMP/lib.log"
fi

echo "==> AegisStore: contra PostgreSQL real"
if (cd server && cargo test -p aegis-almacen --quiet --test pg -- --test-threads=2) >"$TMP/pg.log" 2>&1; then
    if grep -q 'OMITIDA' "$TMP/pg.log"; then
        echo "    ${GRIS}OMITIDO: no hay PostgreSQL${FIN}"
    else
        echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/pg.log" | head -1))"
    fi
else
    fallo "el almacen contra PostgreSQL" "$TMP/pg.log"
fi

echo "==> AegisStore: LA MISMA CONSULTA contra el endpoint y contra el historico"
if (cd server && cargo test -p aegis-almacen --quiet --test misma_consulta -- --nocapture) >"$TMP/par.log" 2>&1; then
    if grep -q 'OMITIDA' "$TMP/par.log"; then
        echo "    ${GRIS}OMITIDO: no hay PostgreSQL${FIN}"
    else
        N=$(grep -c 'iguales por los dos caminos' "$TMP/par.log")
        echo "    ${VERDE}OK${FIN} ($N consultas de caza, mismas filas por el ejecutor real del endpoint y por el almacen)"
    fi
else
    fallo "el endpoint y el historico no devuelven lo mismo" "$TMP/par.log"
fi

exit 0
