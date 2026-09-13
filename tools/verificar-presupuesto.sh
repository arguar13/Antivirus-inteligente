#!/usr/bin/env bash
#
# Verificacion del presupuesto de memoria del agente.
#
# QUE SUSTITUYE ESTE SCRIPT. Durante mucho tiempo el presupuesto fue «45 MB», y
# esa cifra tenia tres problemas de los que solo uno era el tamano:
#
#   PRIMERO: un numero para tres regimenes. Un agente que gasta lo mismo
#   vigilando que escaneando el disco entero no es eficiente, es un agente que no
#   esta escaneando. Reposo, pico y techo responden a tres preguntas distintas:
#   que ve el administrador en `top`, que necesita el agente para trabajar, y a
#   partir de donde el agente es un peligro para la maquina que vino a proteger.
#
#   SEGUNDO: un numero para todos los hosts. Una pasarela de 1 GiB y un host de
#   base de datos de 768 GiB no pueden compartir presupuesto. Al segundo le sale
#   mas barato tener el corpus residente que ir al disco en cada escaneo, y
#   negarselo no es prudencia: es hacerle competir contra su propia carga.
#
#   TERCERO, y el que de verdad importaba: era una promesa de un comentario. Se
#   median cuatro segundos al arrancar y nada mas. Una fuga lenta hasta 2 GiB a
#   las tres de la manana pasaba entera, y el watchdog —que vigilaba latido, no
#   memoria— la daba por buena hasta que se llevaba el host por delante.
#
# LAS DOS PUERTAS. Este script mide una vez y compara contra dos umbrales, y los
# dos hacen falta:
#
#   (a) El PRESUPUESTO del host. Es el compromiso con el cliente y escala con la
#       RAM de la maquina. Como unica puerta seria inutil en un servidor grande,
#       donde el reposo vale 384 MiB: un componente podria decuplicar su huella y
#       seguir pasando.
#   (b) La LINEA BASE de arranque. No escala con nada. Es el numero medido con
#       margen, y su trabajo es cazar la regresion: si el agente arranca ocupando
#       el doble que ayer es un bug atribuible aunque quepa de sobra.
#
# EL MURO, declarado en vez de disimulado: esto mide el ARRANQUE en reposo. No
# mide el pico bajo escaneo completo, que depende del corpus desplegado y del
# disco del host, y fingir medirlo aqui con un corpus de juguete daria un numero
# tranquilizador y falso. Lo que si se ejercita entero, contra procesos reales y
# lecturas reales de /proc, es la maquinaria que lo obliga: la deteccion de
# desbordamiento del watchdog y la contencion por regimenes.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

mib() { echo $(( $1 / 1048576 )); }

echo "==> Presupuesto: el reparto por clase de host"
if cargo test -p aegis-presupuesto --quiet >/tmp/aegis-presupuesto.log 2>&1; then
    RESUMEN=$(grep -h "^test result" /tmp/aegis-presupuesto.log | head -1)
    echo "    ${VERDE}OK${FIN} ($RESUMEN)"
    echo "    ${GRIS}Fraccion de la RAM del host con suelo y techo, no una cifra fija: la${FIN}"
    echo "    ${GRIS}fraccion escala, el suelo mantiene capaz al host pequeno, y el techo${FIN}"
    echo "    ${GRIS}impide que el agente crezca en un host grande solo porque puede.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-presupuesto.log)"
    FALLOS=$((FALLOS + 1))
fi

echo "==> Presupuesto: el watchdog reinicia al agente que se come la maquina"
if cargo test -p aegis-watchdog --quiet --test watchdog \
    >/tmp/aegis-presupuesto-wd.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (proceso real, medida real de /proc, decision real)"
    echo "    ${GRIS}Y las dos mitades que lo hacen desplegable: una sola muestra sobre el${FIN}"
    echo "    ${GRIS}techo NO reinicia —reiniciar el EDR abre una ventana sin proteccion, y${FIN}"
    echo "    ${GRIS}quien sepa provocar picos tendria ahi un interruptor para apagarlo—, y${FIN}"
    echo "    ${GRIS}el contador NO sobrevive al reinicio, o el proceso nuevo naceria${FIN}"
    echo "    ${GRIS}condenado y la fuga acotada se volveria una maquina sin EDR.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-presupuesto-wd.log)"
    FALLOS=$((FALLOS + 1))
fi

echo "==> Presupuesto: el drop-in de cgroup v2 que lo obliga desde fuera"
DROPIN=$(cargo run -q -p aegis-presupuesto --example reparto -- --dropin 2>/dev/null)
if echo "$DROPIN" | grep -q "MemoryMax=" && echo "$DROPIN" | grep -q "MemoryHigh=" \
   && echo "$DROPIN" | grep -q "MemorySwapMax=0"; then
    ALTO=$(echo "$DROPIN" | sed -n 's/^MemoryHigh=//p')
    MAXIMO=$(echo "$DROPIN" | sed -n 's/^MemoryMax=//p')
    echo "    ${VERDE}OK${FIN} (MemoryHigh $(mib "$ALTO") MiB blando, MemoryMax $(mib "$MAXIMO") MiB duro)"
    echo "    ${GRIS}Las dos capas de dentro las ejecuta un proceso que puede estar${FIN}"
    echo "    ${GRIS}comprometido o sencillamente tener un bug. Esta la ejecuta el kernel.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el drop-in no impone los dos limites"
    FALLOS=$((FALLOS + 1))
fi

echo "==> Presupuesto: huella real del agente al arrancar"
PRESUPUESTO=$(cargo run -q -p aegis-presupuesto --example reparto -- --campo reposo 2>/dev/null)
LINEA_BASE=$(cargo run -q -p aegis-presupuesto --example reparto -- --campo linea_base 2>/dev/null)
PERFIL=$(cargo run -q -p aegis-presupuesto --example reparto -- --campo perfil 2>/dev/null)
if [ -z "$PRESUPUESTO" ] || [ -z "$LINEA_BASE" ]; then
    echo "    ${ROJO}FALLO${FIN}: no se pudo calcular el presupuesto"
    FALLOS=$((FALLOS + 1))
elif cargo build --release -p aegis-agent -q 2>/dev/null && [ -x target/release/aegis-agent ]; then
    ./target/release/aegis-agent --stats-interval 300 >/dev/null 2>/tmp/aegis-presupuesto.err &
    PID=$!
    sleep 4
    RSS_KB=$(awk '/VmRSS/ {print $2}' "/proc/$PID/status" 2>/dev/null)
    kill -TERM "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    if [ -z "$RSS_KB" ]; then
        echo "    ${GRIS}omitido: el agente no arranco en este entorno${FIN}"
        echo "    ${GRIS}  causa: $(tail -1 /tmp/aegis-presupuesto.err 2>/dev/null | head -c 160)${FIN}"
    else
        RSS=$((RSS_KB * 1024))
        if [ "$RSS" -ge "$PRESUPUESTO" ]; then
            echo "    ${ROJO}FALLO${FIN}: $(mib "$RSS") MiB pasa del reposo de $(mib "$PRESUPUESTO") MiB (perfil $PERFIL)"
            FALLOS=$((FALLOS + 1))
        elif [ "$RSS" -ge "$LINEA_BASE" ]; then
            echo "    ${ROJO}FALLO${FIN}: $(mib "$RSS") MiB pasa de la linea base de $(mib "$LINEA_BASE") MiB"
            echo "    ${ROJO}     ${FIN} (cabe en el presupuesto del host, pero es una REGRESION: el"
            echo "    ${ROJO}     ${FIN} agente arranca ocupando mas que la huella medida y declarada)"
            FALLOS=$((FALLOS + 1))
        else
            echo "    ${VERDE}OK${FIN} ($(mib "$RSS") MiB · reposo $(mib "$PRESUPUESTO") MiB · linea base $(mib "$LINEA_BASE") MiB · perfil $PERFIL)"
        fi
    fi
else
    echo "    ${GRIS}omitido (no se pudo compilar el agente)${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> Presupuesto verificado${FIN}"
else
    echo "${ROJO}==> Presupuesto: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
