#!/usr/bin/env bash
#
# Verificacion de AegisPredict (prediccion y contencion preventiva, FASE 69).
#
# LO QUE ESTE MOTOR AUTORIZA, y que gobierna todo lo demas: AegisPredict no
# escribe informes, PROPONE AISLAR MAQUINAS DE PRODUCCION. De ahi dos decisiones
# que este script comprueba una por una.
#
# PRIMERA: nada esta entrenado. Ni las probabilidades de las aristas ni los pesos
# de la criticidad. Estan puestos a mano, con su razon, y por eso el resultado se
# puede imprimir en una frase que un analista puede leer y rebatir. Un vector de
# activaciones no se discute, y lo que no se discute no se pone delante de un
# cliente cuya maquina se va a quedar sin red.
#
# SEGUNDA: todo es determinista. Mismo grafo, mismo camino, mismo radio, misma
# propuesta —desempates incluidos—. El informe que justifica aislar una maquina
# el lunes tiene que dar lo mismo cuando alguien lo audite el martes.
#
# Y los DOS PELIGROS de la contencion preventiva, que se ejercen los dos:
#
#   (a) Que el modelo se equivoque y la cura sea la enfermedad. Aislar
#       doscientas maquinas por una prediccion es una denegacion de servicio
#       auto-infligida: por encima de cierto tamano la contencion ES la
#       interrupcion. Hay un tope duro, y pasado el, el motor NO actua: escala a
#       una persona.
#   (b) Que el atacante dirija la prediccion. El es quien se mueve lateralmente,
#       quien se autentica, quien deja credenciales cacheadas: FABRICA ARISTAS.
#       Si el motor actuara sobre cualquier camino, podria construirse uno a
#       traves de la maquina que quiere tirar y lograr que la propia defensa la
#       aisle. La evidencia sin corroborar NO mueve nada automaticamente.
#
# NO HAY MURO EN ESTA FASE: es matematica sobre un grafo, y se comprueba entera,
# incluso contra valores analiticos calculados a mano. Lo unico que no se puede
# verificar aqui es la CALIBRACION de las probabilidades contra brechas reales de
# una organizacion concreta, y por eso los numeros estan explicitos y discutibles
# en `grafo::probabilidad` en vez de escondidos en un modelo.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisPredict: el camino de ataque, contra un producto calculado a mano"
if (cd server && cargo test -p aegis-predict --quiet caminos::) \
    >/tmp/aegis-predict-caminos.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Dijkstra sobre -log p da el optimo EXACTO, no una heuristica: el"
    echo "    ${VERDE}  ${FIN} logaritmo convierte maximizar un producto en minimizar una suma de"
    echo "    ${VERDE}  ${FIN} pesos no negativos. Y el camino mas probable NO es el mas corto: un"
    echo "    ${VERDE}  ${FIN} atajo improbable es peor que un rodeo facil, que es justo el error que"
    echo "    ${VERDE}  ${FIN} comete una busqueda en anchura)"
else
    echo "    ${ROJO}FALLO${FIN}: el calculo de caminos no cuadra"
    sed 's/^/    | /' /tmp/aegis-predict-caminos.log | tail -30
    exit 1
fi

echo "==> AegisPredict: el radio de explosion, contra su valor analitico"
if (cd server && cargo test -p aegis-predict --quiet radio::) \
    >/tmp/aegis-predict-radio.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (la pregunta exacta es #P-completa, asi que se muestrea; la media"
    echo "    ${VERDE}  ${FIN} converge al analitico p + p^2 con error < 0,02, y el margen encoge como"
    echo "    ${VERDE}  ${FIN} 1/sqrt(n) —medido con 200 y 20.000 pasadas—. El margen VIAJA DENTRO del"
    echo "    ${VERDE}  ${FIN} resultado: un numero de Monte Carlo sin su margen se lee como exacto)"
    echo "    ${GRIS}Y segmentar la red REDUCE el radio: si no fuera asi el modelo estaria${FIN}"
    echo "    ${GRIS}invertido y aconsejaria al reves de lo que un defensor debe hacer.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el radio de explosion no converge a lo que debe"
    sed 's/^/    | /' /tmp/aegis-predict-radio.log | tail -30
    exit 1
fi

echo "==> AegisPredict: la criticidad (un portatil vale lo que alcanza)"
if (cd server && cargo test -p aegis-predict --quiet criticidad::) \
    >/tmp/aegis-predict-criticidad.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (un portatil sin valor propio hereda el de la joya que alcanza, con el"
    echo "    ${VERDE}  ${FIN} valor exacto comprobado a mano; decae con la distancia, porque si no"
    echo "    ${VERDE}  ${FIN} toda la flota saldria igual de critica y el ranking no diria nada; y un"
    echo "    ${VERDE}  ${FIN} CICLO converge en vez de dispararse —sin amortiguacion no seria un"
    echo "    ${VERDE}  ${FIN} numero grande, seria infinito)"
else
    echo "    ${ROJO}FALLO${FIN}: la propagacion de criticidad no pasa"
    sed 's/^/    | /' /tmp/aegis-predict-criticidad.log | tail -30
    exit 1
fi

echo "==> AegisPredict: los cinco frenos de la contencion preventiva"
if (cd server && cargo test -p aegis-predict --quiet -- contencion:: grafo::) \
    >/tmp/aegis-predict-frenos.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (1) un activo protegido —plano de control, controlador de dominio— no"
    echo "    ${VERDE}  ${FIN} se toca jamas, pero un DESTINO protegido no impide cortar, porque"
    echo "    ${VERDE}  ${FIN} cortar lo protege; (2) por encima del tope de radio NO se actua, se"
    echo "    ${VERDE}  ${FIN} escala a una persona, y la guarda porcentual tiene suelo para que no"
    echo "    ${VERDE}  ${FIN} escale SIEMPRE en flotas pequenas; (3) la evidencia recien fabricada"
    echo "    ${VERDE}  ${FIN} por el atacante NO mueve nada; (4) un camino improbable tampoco; y"
    echo "    ${VERDE}  ${FIN} (5) se corta la IDENTIDAD antes que aislar la maquina)"
else
    echo "    ${ROJO}FALLO${FIN}: los frenos de la contencion no se sostienen"
    sed 's/^/    | /' /tmp/aegis-predict-frenos.log | tail -30
    exit 1
fi

echo "==> AegisPredict: el circuito vivo (prediccion -> orden encolada de verdad)"
if (cd server && cargo test -p aegis-server --quiet --test prediccion_viva -- --nocapture) \
    >/tmp/aegis-predict-vivo.log 2>&1; then
    if grep -q 'OMITIDA' /tmp/aegis-predict-vivo.log; then
        echo "    ${GRIS}OMITIDO: no hay PostgreSQL. El circuito NO se ejercio.${FIN}"
        echo "    ${GRIS}$(grep -m1 'OMITIDA' /tmp/aegis-predict-vivo.log)${FIN}"
        echo "    ${GRIS}La DECISION (los cinco frenos) SI se prueba, arriba, sin base de datos.${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (contra PostgreSQL REAL: la propuesta acaba siendo UNA orden"
        echo "    ${VERDE}  ${FIN} encolada —no un playbook—, con el mismo verbo que usa el boton de la"
        echo "    ${VERDE}  ${FIN} consola y marcada como PREVENTIVA para que el analista distinga 'se"
        echo "    ${VERDE}  ${FIN} detecto' de 'se predijo'; un endpoint sin matricular falla con un"
        echo "    ${VERDE}  ${FIN} motivo legible y no con integridad referencial en crudo; y una"
        echo "    ${VERDE}  ${FIN} evidencia fabricada escala SIN encolar nada)"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: el circuito vivo no pasa"
    sed 's/^/    | /' /tmp/aegis-predict-vivo.log | tail -30
    exit 1
fi
exit 0
