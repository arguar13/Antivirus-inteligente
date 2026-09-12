#!/usr/bin/env bash
#
# Verificacion de AegisOrchestrator (AI-RO, FASE 64) y de su INTEGRACION VIVA con
# el flujo de eventos del plano de control. Informa SIEMPRE de que se pudo ejercer
# y que no, como el resto de fases con muro.
#
# Tres capas, y las tres se declaran por separado porque su nivel de evidencia es
# distinto:
#
#   1. LA MAQUINA DE ESTADOS (aegis-orchestrator). Elige el playbook segun la
#      amenaza, lanza las acciones EN PARALELO, sobrevive a fallos parciales, es
#      idempotente en el reintento y no toca la flota por una sospecha debil.
#      Logica pura: se prueba entera, sin muro.
#
#   2. EL PUENTE VIVO (aegis-server::remediacion). Es lo que convierte un veredicto
#      del motor ITDR en un playbook sobre un endpoint: que se persista la alerta
#      pase lo que pase, que un ataque que dura varios lotes NO relance el playbook,
#      que un fallo parcial no se trague las demas acciones y que la identidad
#      implicada viaje en cada orden. Tambien logica: se prueba entera.
#
#   3. LA INFRAESTRUCTURA REAL (PostgreSQL). El cerrojo que impide que dos
#      instancias del plano de control remedien el mismo incidente dos veces NO es
#      codigo: es un indice unico parcial de PostgreSQL. Afirmarlo sin una base de
#      datos seria mentir, asi que si no hay PostgreSQL se DICE, y no se finge.
#
# El muro que queda, y que ninguna de las tres capas cubre, es la EJECUCION en el
# endpoint: programar el XDP en el kernel, matar el proceso, revocar el ticket en
# la KDC o volcar la RAM ocurre en el AGENTE, contra un sistema real. El plano de
# control ORDENA (y eso si se comprueba: la orden queda encolada de verdad); que el
# endpoint la APLIQUE es otro hecho, y confundirlos es como se acaba creyendo
# aislada una maquina que sigue hablando con el atacante.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

if [ ! -d server ]; then
    echo "    ${GRIS}servidor no presente en este arbol: omitido${FIN}"
    exit 0
fi

echo "==> AegisOrchestrator: la maquina de estados de remediacion se prueba entera"
if cargo test --manifest-path server/Cargo.toml -p aegis-orchestrator --quiet \
    >/tmp/aegis-orchestrator.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Golden Ticket -> 4 acciones en paralelo; fallo parcial resiliente; reintento idempotente; no-critico no actua)"
else
    echo "    ${ROJO}FALLO${FIN}: la maquina de estados de remediacion no pasa"
    sed 's/^/    | /' /tmp/aegis-orchestrator.log | tail -30
    exit 1
fi

echo "==> Puente vivo ITDR -> AI-RO: la decision de responder se prueba entera"
if cargo test --manifest-path server/Cargo.toml -p aegis-server --lib --quiet remediacion:: \
    >/tmp/aegis-remediacion.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (deteccion -> playbook sobre el endpoint; un ataque de varios lotes NO se relanza;"
    echo "    ${VERDE}  ${FIN} la alerta se persiste aunque la respuesta falle y al reves; la identidad viaja en cada orden)"
else
    echo "    ${ROJO}FALLO${FIN}: el puente entre el motor de identidad y la respuesta automatica no pasa"
    sed 's/^/    | /' /tmp/aegis-remediacion.log | tail -30
    exit 1
fi

echo "==> Cerrojo distribuido y ejecutor de flota contra PostgreSQL REAL"
# Las pruebas se omiten SOLAS, con aviso, si no hay base de datos. Se distingue
# aqui entre "paso contra infraestructura real" y "no se pudo ejercer aqui",
# porque la diferencia es justo la garantia que se esta afirmando.
if cargo test --manifest-path server/Cargo.toml -p aegis-server --test remediacion_viva \
    -- --nocapture >/tmp/aegis-remediacion-viva.log 2>&1; then
    if grep -q 'OMITIDA: no hay PostgreSQL' /tmp/aegis-remediacion-viva.log; then
        echo "    ${GRIS}PostgreSQL: NO disponible en esta maquina.${FIN}"
        echo "    ${GRIS}El cerrojo que impide remediar dos veces el mismo incidente es un indice unico${FIN}"
        echo "    ${GRIS}parcial de PostgreSQL; sin base de datos NO se ejercio aqui. La DECISION que se${FIN}"
        echo "    ${GRIS}apoya en el, SI (arriba). Levantar PostgreSQL y AEGIS_TEST_PG_URL lo ejerce.${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (dos instancias a la vez abren UNA sola remediacion; el enfriamiento impide"
        echo "    ${VERDE}  ${FIN} relanzar y luego deja; el aislamiento se marca y la orden se encola de verdad;"
        echo "    ${VERDE}  ${FIN} circuito completo identidad -> deteccion -> playbook -> comandos, sin un solo doble)"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: la integracion contra infraestructura real no pasa"
    sed 's/^/    | /' /tmp/aegis-remediacion-viva.log | tail -30
    exit 1
fi

echo "==> AegisOrchestrator: APLICACION de las acciones en el endpoint (muro)"
echo "    ${GRIS}NO ejercida aqui: programar el XDP en el kernel del endpoint, matar un proceso,${FIN}"
echo "    ${GRIS}revocar un ticket en la KDC o volcar la RAM ocurre en el AGENTE, contra un sistema${FIN}"
echo "    ${GRIS}real. Lo que si se comprueba arriba es que el plano de control lo ORDENA: la orden${FIN}"
echo "    ${GRIS}queda encolada y el inventario marcado. Ordenado y aplicado son dos hechos distintos.${FIN}"
exit 0
