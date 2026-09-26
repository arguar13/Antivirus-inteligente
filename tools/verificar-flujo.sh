#!/usr/bin/env bash
#
# Verificacion de AegisFlow (FASE 97): automatizacion de respuesta con flujos
# tipados y transaccionales, reversion obligatoria y los cinco frenos por paso.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. AUTOATAQUE, antes que nada: la automatizacion como arma. Contra una flota
#      REAL de mil maquinas en el esquema del plano de control (PostgreSQL), los
#      flujos que un error de plantilla escribiria para dejar a la organizacion
#      sin red —aislar la flota entera firmado, lo mismo expandido en mil pasos
#      de una maquina, bloquear 0.0.0.0/0, bloquear la red del controlador de
#      dominio— se detienen y se escalan, y la base de datos queda intacta.
#   2. NO COMPILA, con la razon exacta: se lee lo que dice el compilador de cada
#      prueba compile_fail, no solo que fallo. Un flujo mal tipado (E0308), un
#      paso sin reversion (E0046), un paso irreversible sin firma (E0080 con el
#      mensaje del freno) y una firma fabricada a mano (E0451).
#   3. El motor: reversion en orden inverso, el estado de antes, idempotencia,
#      radio acumulado, firma que cubre UNA ejecucion, lo irreversible escalado.
#   4. El catalogo contra el ESTADO REAL: un flujo que falla a medias deja la
#      base como estaba —fila a fila, microsegundos incluidos—, no deshace lo
#      que el flujo no hizo, compensa una orden ya recogida por el agente, y su
#      reintento no duplica nada.
#
# EL MURO, DECLARADO: la comparativa con Shuffle es por PROPIEDADES, con cada una
# citada de su documentacion (docs/88); no esta medida ejecutandolo, porque
# Shuffle se despliega con Docker y esta maquina no lo tiene. Las ordenes a los
# agentes y al directorio se ENCOLAN en las tablas reales; aplicarlas es del
# agente y del conector (fases anteriores), no de esta.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-flujo-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

echo "==> AegisFlow: AUTOATAQUE — la automatizacion como arma, contra mil maquinas"
if (cd server && cargo test -p aegis-flujo --quiet --test autoataque -- --nocapture) >"$TMP/auto.log" 2>&1; then
    # El autoataque sin base de datos no es un autoataque: no se da por bueno.
    grep -q 'OMITIDA' "$TMP/auto.log" && fallo "no hay PostgreSQL: el autoataque no se ejercio" "$TMP/auto.log"
    grep -E '^([1-4]\.|control:)' "$TMP/auto.log" | cut -c1-170 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} (los cuatro detenidos y escalados; ni una maquina aislada, ni una orden, ni una red bloqueada)"
else
    fallo "la automatizacion se puede usar como arma" "$TMP/auto.log"
fi

echo "==> AegisFlow: lo que NO COMPILA, y por que"
# Sin --quiet y con --nocapture: rustdoc solo comprueba los codigos de error de
# compile_fail en nightly, asi que aqui se lee el error real de cada una.
if (cd server && cargo test -p aegis-flujo --doc -- --nocapture) >"$TMP/doc.log" 2>&1; then
    N=$(grep -c 'compile fail ... ok' "$TMP/doc.log")
    [ "$N" -ge 4 ] || fallo "se esperaban 4 pruebas compile_fail y pasaron $N" "$TMP/doc.log"
    grep -q 'error\[E0308\]: mismatched types' "$TMP/doc.log" \
        && grep -q 'expected `Nodo<Ref<Proceso>>`, found `Nodo<Ref<Fichero>>`' "$TMP/doc.log" \
        || fallo "el flujo mal tipado no falla por el tipo de la entidad" "$TMP/doc.log"
    grep -q 'error\[E0046\]: not all trait items implemented, missing: `revertir`' "$TMP/doc.log" \
        || fallo "el paso sin reversion no falla por la reversion" "$TMP/doc.log"
    grep -q 'error\[E0080\]: evaluation panicked: un paso irreversible exige una Firma humana como permiso' "$TMP/doc.log" \
        || fallo "el paso irreversible sin firma no falla por la firma" "$TMP/doc.log"
    grep -q 'error\[E0451\]: fields `huella` and `quien` of struct `Firma` are private' "$TMP/doc.log" \
        || fallo "la firma fabricada a mano no falla por sus campos privados" "$TMP/doc.log"
    echo "    ${VERDE}OK${FIN} ($N compile_fail, cada una por su razon: un fichero no es un proceso (E0308),"
    echo "    ${VERDE}  ${FIN} falta revertir (E0046), irreversible sin firma (E0080), firma fabricada (E0451))"
else
    fallo "las pruebas compile_fail no pasan" "$TMP/doc.log"
fi

echo "==> AegisFlow: el motor — reversion, estado de antes, idempotencia, radio acumulado, firma"
if (cd server && cargo test -p aegis-flujo --quiet --lib --test motor) >"$TMP/motor.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/motor.log" | awk '{s+=$4} END {print s}') pruebas)"
else
    fallo "el motor" "$TMP/motor.log"
fi

echo "==> AegisFlow: el catalogo contra el ESTADO REAL del plano de control"
if (cd server && cargo test -p aegis-flujo --quiet --test pg -- --nocapture --test-threads=2) >"$TMP/pg.log" 2>&1; then
    grep -q 'OMITIDA' "$TMP/pg.log" && fallo "no hay PostgreSQL: el estado real no se comprobo" "$TMP/pg.log"
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/pg.log" | head -1))"
    echo "    ${GRIS}a medias: maquina liberada y orden retirada, cuenta rehabilitada, la red EXACTAMENTE como estaba,${FIN}"
    echo "    ${GRIS}caso cerrado «no concluyente» con su rastro intacto; lo ajeno no se toca; el reintento no duplica${FIN}"
else
    fallo "el catalogo contra la base de datos" "$TMP/pg.log"
fi

echo "==> AegisFlow: comparativa con Shuffle"
echo "    ${GRIS}por propiedades, citadas de su documentacion (docs/88); no medida ejecutandolo: Shuffle${FIN}"
echo "    ${GRIS}se despliega con Docker y esta maquina no lo tiene${FIN}"
