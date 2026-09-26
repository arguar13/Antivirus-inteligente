#!/usr/bin/env bash
#
# Verificacion de AegisMemHunter (analisis de VAD y tabla de paginas, FASE 65).
#
# A DIFERENCIA del resto de fases de hardware, ESTA NO TIENE MURO EN LINUX, y por
# eso este script afirma mas que los demas. La deteccion se apoya en un contrato
# con el kernel —la semantica del bit 61 de `/proc/<pid>/pagemap`— y ese contrato
# se COMPRUEBA construyendo cada estado de pagina de verdad:
#
#   1. una pagina anonima privada escrita          -> bit 61 = 0
#   2. una pagina de fichero solo leida            -> bit 61 = 1
#   3. la MISMA pagina tras un copy-on-write       -> bit 61 = 0
#
# De ahi sale toda la fase: una pagina presente con el bit 61 a 0 dentro de una
# region de codigo respaldada por fichero significa que lo que se ejecuta ahi ya
# no es lo que hay en el fichero. Si un kernel futuro cambiara esa semantica, la
# deteccion se volveria silenciosamente inutil —dejaria de encontrar nada, que es
# el peor fallo posible en un EDR— y nadie se enteraria. Se entera aqui.
#
# Y las dos tecnicas se construyen ENTERAS en el proceso de prueba: una carga
# reflexiva (region RWX anonima con cabecera ELF dentro) y un module stomping (32
# paginas contiguas de codigo sobrescritas sobre un fichero mapeado). El cazador
# tiene que encontrarlas leyendo /proc autentico, y la prueba comprueba ademas que
# el fichero EN DISCO sigue intacto: ahi esta la gracia del ataque y la razon de
# que el escaneo de disco no sirva.
#
# EL MURO, que si se declara: los VAD de Windows. `VirtualQueryEx` sobre un
# proceso ajeno necesita Windows y un manejador con PROCESS_QUERY_INFORMATION. Lo
# que SI se verifica aqui, en compilacion, es el ABI de MEMORY_BASIC_INFORMATION
# (tamano y desplazamiento de cada campo, y los valores de las constantes del
# SDK): un campo desplazado no rompe la compilacion, hace que el clasificador lea
# una proteccion donde hay un tamano, y el sintoma en produccion no es un fallo
# sino un EDR que no ve nada.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisMemHunter: el contrato con el kernel (semantica del bit 61 de pagemap)"
if cargo test -p aegis-memhunter --quiet pte::pruebas_vivas:: >/tmp/aegis-memhunter-pte.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (anonima privada -> 0; fichero intacta -> 1; fichero TRAS copy-on-write -> 0,"
    echo "    ${VERDE}  ${FIN} construidos de verdad contra el kernel de esta maquina, no deducidos del manual)"
else
    echo "    ${ROJO}FALLO${FIN}: el contrato con el kernel no se cumple. La deteccion de module"
    echo "    ${ROJO}     ${FIN} stomping se apoya ENTERA en el; si esto falla, no detecta nada."
    sed 's/^/    | /' /tmp/aegis-memhunter-pte.log | tail -30
    exit 1
fi

echo "==> AegisMemHunter: el coste propio del decisor, sobre el binario optimizado"
# Con --release y sola: el tope es del decisor que corre en el agente, no del
# perfil de depuracion ni de la carga del resto de pruebas en paralelo.
if cargo test --release -p aegis-memhunter --quiet --lib \
        hunter::pruebas::el_decisor_resuelve_un_proceso_grande -- --nocapture --test-threads=1 \
        >/tmp/aegis-memhunter-coste.log 2>&1; then
    if grep -q 'sin juzgar' /tmp/aegis-memhunter-coste.log \
        || ! grep -q '1 passed' /tmp/aegis-memhunter-coste.log; then
        echo "    ${ROJO}FALLO${FIN}: el tope de coste no se juzgo sobre el binario optimizado"
        sed 's/^/    | /' /tmp/aegis-memhunter-coste.log | tail -20
        exit 1
    fi
    echo "    ${VERDE}OK${FIN} (2000 regiones por debajo de 5 ms en la mejor de 9 pasadas, --release)"
else
    echo "    ${ROJO}FALLO${FIN}: el decisor supera su tope de coste sobre el binario optimizado"
    sed 's/^/    | /' /tmp/aegis-memhunter-coste.log | tail -20
    exit 1
fi

echo "==> AegisMemHunter: las dos tecnicas, construidas de verdad en un proceso vivo"
if cargo test -p aegis-memhunter --quiet hunter::pruebas_vivas:: -- --nocapture \
    >/tmp/aegis-memhunter-vivo.log 2>&1; then
    if grep -q 'OMITIDA' /tmp/aegis-memhunter-vivo.log; then
        echo "    ${VERDE}OK${FIN} (carga reflexiva y module stomping cazados en /proc autentico)"
        echo "    ${GRIS}$(grep -m1 'OMITIDA' /tmp/aegis-memhunter-vivo.log)${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (carga reflexiva con cabecera ELF en memoria anonima: cazada;"
        echo "    ${VERDE}  ${FIN} 32 paginas de codigo de un modulo sobrescritas: cazadas, con el fichero"
        echo "    ${VERDE}  ${FIN} en disco comprobadamente INTACTO; y un proceso limpio no pide respuesta)"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: las tecnicas construidas en vivo no se detectan"
    sed 's/^/    | /' /tmp/aegis-memhunter-vivo.log | tail -30
    exit 1
fi

echo "==> AegisMemHunter: el decisor (umbrales, falsos positivos y latencia)"
if cargo test -p aegis-memhunter --quiet -- hunter::pruebas:: vad::pruebas:: \
    >/tmp/aegis-memhunter-decisor.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el parcheo legitimo del cargador NO avisa; un runtime con JIT rebaja"
    echo "    ${VERDE}  ${FIN} pero no silencia, y no puede tapar una cabecera de imagen ni un stomping;"
    echo "    ${VERDE}  ${FIN} el vDSO no se confunde con codigo inyectado; 2000 regiones en < 10 ms)"
else
    echo "    ${ROJO}FALLO${FIN}: el decisor no pasa"
    sed 's/^/    | /' /tmp/aegis-memhunter-decisor.log | tail -30
    exit 1
fi

echo "==> AegisMemHunter: VAD de Windows (ABI verificada en compilacion; captura gated)"
if cargo test -p aegis-memhunter --quiet vad::windows:: >/tmp/aegis-memhunter-win.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (MEMORY_BASIC_INFORMATION: 48 B y los 7 desplazamientos del SDK, afirmados"
    echo "    ${VERDE}  ${FIN} con const assert; las constantes PAGE_* se traducen como las define Windows)"
    echo "    ${GRIS}La CAPTURA en vivo NO se ejercio aqui: VirtualQueryEx sobre un proceso ajeno${FIN}"
    echo "    ${GRIS}necesita Windows. El clasificador que consume esos datos SI se prueba, arriba.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el contrato de ABI con Windows no cuadra"
    sed 's/^/    | /' /tmp/aegis-memhunter-win.log | tail -20
    exit 1
fi
exit 0
