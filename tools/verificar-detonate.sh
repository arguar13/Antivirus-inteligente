#!/usr/bin/env bash
#
# Verificacion de AegisDetonate (detonacion en microVM, FASE 73).
#
# QUE HACE ESTA FASE: ejecutar malware a proposito para ver que hace. Todo lo
# demas —la traza, el informe, el analisis— vale exactamente cero si esa
# ejecucion puede tocar algo real, asi que la frontera no es una capa mas: es la
# unica razon por la que el resto puede existir.
#
# LAS TRES PROMESAS, y cual se comprueba como:
#
#   PRIMERA: la muestra no alcanza nada real. NO se declara, se comprueba: hay
#   una prueba que intenta una conexion de verdad a una direccion de verdad
#   desde dentro de la frontera, y otra que la intenta desde fuera. Dan
#   resultados distintos.
#
#   SEGUNDA: la maquina se destruye SIEMPRE. Esta en Drop y no solo en un metodo,
#   porque un metodo se olvida en el camino de error y el camino de error es
#   justo el que se toma cuando algo ha ido mal con una muestra que muerde. Una
#   maquina de detonacion que sobrevive a su detonacion es una maquina infectada
#   corriendo en la infraestructura del que analiza, y ademas invisible.
#
#   TERCERA: el informe no puede mentir. Un sandbox descuidado escribe igual tres
#   cosas: «corrio entera y no hizo nada», «detecto el entorno y se marcho» y «se
#   corto antes de empezar». Solo la primera es benigna. El veredicto no tiene
#   NINGUN camino que llegue a «sin hallazgos» sin descartar las otras dos.
#
# EL INVITADO ESTA INFECTADO A PROPOSITO, y todo lo que sube lo escribe el
# malware: topes en cada longitud, huecos de secuencia anotados en vez de
# abortados —abortar le daria al malware una forma trivial de destruir su propio
# informe— y un error de protocolo que cierra el canal SIN RESINCRONIZAR, porque
# resincronizar le dejaria colocar la marca donde quiera y fabricar tramas.
#
# Y el canal solo transporta hechos: el enumerado de eventos no tiene ni una
# variante que sea una orden. El anfitrion no valida nada porque no hay nada que
# ejecutar.
#
# LOS MUROS DE ESTA FASE, declarados en vez de disimulados:
#
#   (a) ARRANCAR el hipervisor necesita /dev/kvm. Donde no lo hay —una maquina de
#       integracion que ya corre dentro de otra maquina virtual— se genera y se
#       comprueba su configuracion pieza a pieza, pero no se arranca. Lo que SI
#       se ejercita en cualquier sitio es el resto: el trazador contra procesos
#       reales, el aislamiento contra una direccion real, el canal contra un
#       socket real y la destruccion contra un proceso real.
#   (b) Detonar muestras de Windows necesita ademas una licencia y una imagen que
#       no se puede distribuir. La orquestacion, la frontera y el analisis son los
#       mismos; lo que cambia es el invitado.
#   (c) El confinamiento por espacios de nombres NO equivale a una maquina
#       virtual: una elevacion local del kernel saca a la muestra de ahi. Se niega
#       a detonar muestras reales salvo reconocimiento explicito, y el informe
#       lleva escrito con que fuerza estaba encerrada.
#   (d) Hay tecnicas de evasion que NO se contrarrestan —la medicion de tiempos y
#       la credibilidad de la red— y el catalogo lo dice dentro de cada informe,
#       no en un documento que nadie lee en el momento en el que importa.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

# El agente invitado tiene que existir antes de las pruebas de integracion: es el
# binario que va DENTRO de la imagen del invitado, y sin el la detonacion entera
# se quedaria en la orquestacion.
echo "==> AegisDetonate: el agente que va dentro de la maquina infectada"
if cargo build -q -p aegis-invitado 2>/tmp/aegis-det-build.log; then
    ARBOL=$(cargo tree -p aegis-invitado --edges normal --prefix none 2>/dev/null \
            | awk '{print $1}' | sort -u | grep -v '^$' | wc -l)
    echo "    ${VERDE}OK${FIN} (arbol de $ARBOL crates)"
    echo "    ${GRIS}Este binario corre en la misma maquina y con los mismos permisos que${FIN}"
    echo "    ${GRIS}la muestra, y en cuanto ella escale los tendra todos. Cada crate que${FIN}"
    echo "    ${GRIS}se enlace aqui es codigo que el malware puede intentar subvertir para${FIN}"
    echo "    ${GRIS}llegar al anfitrion por el canal, asi que solo entra libc.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-det-build.log)"
    tail -20 /tmp/aegis-det-build.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDetonate: el trazador, contra procesos REALES"
if cargo test -q -p aegis-invitado > /tmp/aegis-det-invitado.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-det-invitado.log | head -1))"
    echo "    ${GRIS}ptrace de verdad sobre procesos de verdad: se sigue a los hijos —lo${FIN}"
    echo "    ${GRIS}primero que hace cualquier malware serio es lanzar uno y morirse—, se${FIN}"
    echo "    ${GRIS}distingue escribir un fichero de leerlo, y el plazo lo aplica un hilo${FIN}"
    echo "    ${GRIS}aparte porque el bucle vive bloqueado en waitpid y una comprobacion${FIN}"
    echo "    ${GRIS}entre iteraciones no llegaria nunca contra una muestra que se para.${FIN}"
    echo "    ${GRIS}Y __WNOTHREAD: el trazador de ptrace es un HILO, no el proceso, asi${FIN}"
    echo "    ${GRIS}que sin el un hilo recoge la notificacion del trazado de otro y el que${FIN}"
    echo "    ${GRIS}si era su trazador se cuelga para siempre.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-det-invitado.log)"
    tail -20 /tmp/aegis-det-invitado.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDetonate: la frontera, el canal hostil y el informe"
if (cd server && cargo test -q -p aegis-detonate --lib) > /tmp/aegis-det-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-det-lib.log | head -1))"
    echo "    ${GRIS}La salida de red NO tiene variante para «red de verdad»: la ausencia${FIN}"
    echo "    ${GRIS}ES la frontera, porque nadie puede configurar por error lo que no se${FIN}"
    echo "    ${GRIS}puede expresar. Y el veredicto no llega a «sin hallazgos» sin haber${FIN}"
    echo "    ${GRIS}descartado antes que la detonacion se cortara y que la muestra${FIN}"
    echo "    ${GRIS}reconociera el entorno: no es una convencion, es el match.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-det-lib.log)"
    tail -25 /tmp/aegis-det-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDetonate: la detonacion entera, de verdad"
if (cd server && cargo test -q -p aegis-detonate --test detonacion_real) \
    > /tmp/aegis-det-e2e.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-det-e2e.log | head -1))"
    echo "    ${GRIS}Una muestra escrita en la prueba que cifra ficheros, borra los${FIN}"
    echo "    ${GRIS}originales y deja una nota de rescate: detonada de verdad, y las tres${FIN}"
    echo "    ${GRIS}cosas aparecen en el informe. Otra que intenta salir a 1.1.1.1 desde${FIN}"
    echo "    ${GRIS}dentro y NO la alcanza. Otra que deja un hijo para sobrevivirse y el${FIN}"
    echo "    ${GRIS}hijo tampoco sobrevive. Y la misma muestra dos veces da la misma${FIN}"
    echo "    ${GRIS}huella, mientras que una que usa azar lo DECLARA en vez de fingir${FIN}"
    echo "    ${GRIS}determinismo normalizando justo lo que interesaba ver.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-det-e2e.log)"
    tail -30 /tmp/aegis-det-e2e.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDetonate: virtualizacion en esta maquina"
if [ -e /dev/kvm ]; then
    echo "    ${VERDE}presente${FIN}: /dev/kvm disponible"
    echo "    ${GRIS}La configuracion del hipervisor se comprueba pieza a pieza en las${FIN}"
    echo "    ${GRIS}pruebas; arrancarla de verdad es el siguiente paso natural aqui.${FIN}"
else
    echo "    ${GRIS}AUSENTE${FIN}: sin /dev/kvm no se arranca ninguna maquina virtual aqui."
    echo "    ${GRIS}Es el muro de la fase y se declara en vez de disimularse. Lo que SI se${FIN}"
    echo "    ${GRIS}ha ejercitado arriba, entero y contra cosas reales: el trazador sobre${FIN}"
    echo "    ${GRIS}procesos, el aislamiento de red contra una direccion de internet, el${FIN}"
    echo "    ${GRIS}canal sobre un socket, la destruccion garantizada sobre un proceso, y${FIN}"
    echo "    ${GRIS}la generacion de la configuracion del hipervisor campo a campo.${FIN}"
    echo "    ${GRIS}Degradar en silencio a un aislamiento mas debil seria peor que negarse${FIN}"
    echo "    ${GRIS}a arrancar: el informe saldria igual y nadie sabria con que fuerza${FIN}"
    echo "    ${GRIS}estaba encerrada la muestra.${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisDetonate verificado${FIN}"
else
    echo "${ROJO}==> AegisDetonate: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
