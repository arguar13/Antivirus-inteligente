#!/usr/bin/env bash
#
# Verificacion de AegisScale (plano de control para 100.000 agentes, FASE 75).
#
# LA TESIS DE LA FASE: la diferencia entre diez agentes y cien mil no es un
# factor de escala, es un diseno distinto. Y los sistemas que no se disenaron
# para ello NO se arreglan anadiendo maquinas, porque lo que falla no es la
# capacidad de una maquina:
#
#   - la funcion que reparte la flota rebaraja el 80 % al anadir un nodo, asi que
#     ampliar el plano de control tira la flota justo cuando iba justo;
#   - la purga de la base de datos tarda cada dia un poco mas, hasta el dia en
#     que no acaba antes de que empiece la siguiente;
#   - veinte mil agentes reconectando a la vez tiran al nodo que acaba de
#     levantarse, y como todos reintentan periodicamente, vuelven a coincidir;
#   - y una actualizacion progresiva rompe EN SILENCIO por un campo nuevo que un
#     nodo de la version anterior ignora sin dar error.
#
# Las cuatro se comprueban aqui con numeros, no con afirmaciones.
#
# EL MURO, declarado en vez de disimulado: la prueba de carga de esta puerta NO
# levanta cien mil conexiones mTLS reales ni escribe en PostgreSQL. No es una
# limitacion de la maquina de integracion: es que el diseno NO levanta cien mil
# conexiones —no caben, y esa es justamente la conclusion del modulo de
# sesiones—. El escenario contra un plano de control real con PostgreSQL real
# existe y se lanza con `fleet_simulator`, el otro binario, que habla el
# protocolo autentico con certificados de la CA real. Lo que corre aqui es la
# parte que DECIDE el resultado a esa escala y que se puede ejecutar en cualquier
# maquina, para que la cifra este en la puerta de calidad y no en un documento
# que nadie vuelve a reproducir.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisScale: las cuatro piezas del plano de control a escala"
if (cd server && cargo test -q -p aegis-scale) > /tmp/aegis-scale.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-scale.log | head -1))"
    echo "    ${GRIS}El reparto por sorteo es una FUNCION PURA de (agente, nodos): dos${FIN}"
    echo "    ${GRIS}nodos con la misma lista calculan la misma asignacion sin hablar${FIN}"
    echo "    ${GRIS}entre ellos, y en una particion de red eso es la diferencia entre${FIN}"
    echo "    ${GRIS}seguir funcionando y necesitar consenso para atender un latido.${FIN}"
    echo "    ${GRIS}La purga es un DROP de particion y nunca un DELETE, y se hace con${FIN}"
    echo "    ${GRIS}DETACH CONCURRENTLY antes, porque un DROP sobre una particion${FIN}"
    echo "    ${GRIS}adjunta bloquea la tabla PADRE y para la ingesta de todas las demas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-scale.log)"
    tail -30 /tmp/aegis-scale.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisScale: la prueba de carga de 100.000 agentes"
if (cd server && CARGO_INCREMENTAL=0 cargo run -q --release -p fleet-simulator --bin escala) \
    > /tmp/aegis-escala.log 2>&1; then
    sed 's/^/    | /' /tmp/aegis-escala.log
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}La comprobacion que justifica la prueba no es la latencia: es que${FIN}"
    echo "    ${GRIS}CADA evento que entro esta contado en la salida, en el rechazo o en${FIN}"
    echo "    ${GRIS}el duplicado. Un sistema que pierde eventos en silencio a esta${FIN}"
    echo "    ${GRIS}escala no se nota nunca, porque nadie cuenta cuatrocientos mil.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}"
    tail -30 /tmp/aegis-escala.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisScale: el escenario contra PostgreSQL real"
if [ -n "${AEGIS_TEST_PG_URL:-}" ]; then
    echo "    ${VERDE}disponible${FIN}: AEGIS_TEST_PG_URL configurada"
    echo "    ${GRIS}Las pruebas de integracion del servidor lo ejercitan en «Servidor · tests».${FIN}"
else
    echo "    ${GRIS}AUSENTE${FIN}: sin PostgreSQL no se ejercita la escritura a escala."
    echo "    ${GRIS}Lo que SI se comprueba arriba, contra codigo real y con numeros: el${FIN}"
    echo "    ${GRIS}reparto de cien mil agentes entre dieciseis nodos, cuantos se mueven${FIN}"
    echo "    ${GRIS}al anadir el diecisiete, la capacidad de conexion con su ciclo de${FIN}"
    echo "    ${GRIS}trabajo, la manada tras la caida de un nodo, y la canalizacion entera${FIN}"
    echo "    ${GRIS}con cuatrocientos mil eventos de telemetria realista.${FIN}"
    echo "    ${GRIS}El SQL de las particiones se genera y se comprueba pieza a pieza sin${FIN}"
    echo "    ${GRIS}base de datos: que no queden huecos, que no se solape nada, y que la${FIN}"
    echo "    ${GRIS}purga sea un DROP. Ejecutarlo contra PostgreSQL es el siguiente paso${FIN}"
    echo "    ${GRIS}natural, y la migracion 0007 lo deja escrito para que un${FIN}"
    echo "    ${GRIS}administrador lo revise antes de que corra sobre su produccion.${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisScale verificado${FIN}"
else
    echo "${ROJO}==> AegisScale: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
