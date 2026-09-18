#!/usr/bin/env bash
#
# Verificacion de AegisMac + AegisEnforce (macOS y aplicacion en kernel, FASE 84).
#
# DOS TESIS, y la segunda es la que de verdad cierra el proyecto.
#
# AEGISMAC. En macOS el problema de leer un ejecutable tiene una vuelta de tuerca
# que no existe en ningun otro sistema: un fichero puede contener VARIOS
# PROGRAMAS a la vez, uno por arquitectura, y el sistema elige cual corre segun
# la maquina. Eso convierte la practica habitual de analisis —abrir el fichero,
# coger la primera rodaja, analizarla— en un punto ciego con nombre: se esta
# analizando el programa que NO se va a ejecutar en la mitad del parque. Un
# atacante que ponga codigo limpio en la rodaja x86_64 y su carga en la arm64
# pasa por delante de cualquier analisis que no mire las dos, y hoy los Mac son
# arm64. Por eso aqui `Binario` no tiene ninguna funcion que devuelva «la»
# rodaja: no existe tal cosa, y una API comoda que devolviera la primera seria la
# forma mas rapida de construir el punto ciego dentro del propio producto.
#
# AEGISENFORCE. Un EDR tiene dos modos que se parecen mucho por fuera: mirar y
# bloquear. La diferencia la nota el cliente el dia del incidente, y para
# entonces ya es tarde para descubrir que el mecanismo de bloqueo nunca llego a
# engancharse — porque el kernel no trae BPF LSM, porque el driver no esta
# firmado para esta version de Windows, porque macOS no concedio el permiso. En
# todos esos casos el agente SIGUE FUNCIONANDO: recoge, correla, alerta. Y su
# panel sigue diciendo «protegido». Un agente que no puede bloquear no esta
# protegiendo: esta mirando, y son dos productos distintos al mismo precio.
#
# Esta puerta comprueba cinco cosas:
#
#   1. LOS MACH-O SON REALES. clang compila a Mach-O de 64 bits para arm64 y para
#      x86_64 sin necesitar un Mac. Lo que NO hay aqui es enlazador de Mach-O ni
#      llvm-lipo, y eso se declara en vez de disimularse: las rodajas son reales
#      y la cabecera universal que las envuelve esta construida siguiendo el
#      formato. Es la parte que se puede afirmar y la que no.
#   2. EL LECTOR NO SE QUEDA CON LA PRIMERA RODAJA. Es el punto ciego de macOS, y
#      tiene su propia prueba con dos Mach-O reales de arquitecturas distintas.
#   3. NINGUN FICHERO HOSTIL TUMBA AL AGENTE. `cmdsize` es el campo que mueve el
#      cursor del recorrido: a cero deja el bucle sin avanzar —treinta y dos
#      bytes bien puestos cuelgan al agente—, sin alinear descoloca todo lo que
#      venga detras. Se comprueban antes de moverse, y ademas se trunca y se
#      muta un Mach-O real.
#   4. LA POSTURA SE MIDE, NO SE CONFIGURA. Lo que diga un fichero sobre lo que
#      el producto «tiene activado» no dice nada de lo que este kernel acepta.
#   5. OBSERVAR NO CUENTA COMO APLICAR, Y LO QUE EXIGE APLICAR FALLA CERRADO.
#
# EL MURO, declarado en vez de disimulado: este kernel NO trae BPF LSM, y la
# postura lo dice con su motivo en vez de callarlo. Es justamente el caso que el
# crate existe para no dejar pasar.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisMac: el lector de Mach-O y de binarios universales"
if cargo test -q -p aegis-macho --lib > /tmp/aegis-macho-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-macho-lib.log | head -1))"
    echo "    ${GRIS}Dos ordenes de byte en el mismo fichero: el encabezado universal es${FIN}"
    echo "    ${GRIS}big-endian siempre, por herencia de NeXT, y los Mach-O de dentro son${FIN}"
    echo "    ${GRIS}little-endian. Leer el primero en orden nativo funcionaba en un${FIN}"
    echo "    ${GRIS}PowerPC de 2003; hoy da un numero de rodajas absurdo, y un lector que${FIN}"
    echo "    ${GRIS}se fie de el reserva memoria por ese numero.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-macho-lib.log)"
    tail -30 /tmp/aegis-macho-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMac: contra Mach-O reales compilados aqui"
if cargo test -q -p aegis-macho --test macho_real -- --nocapture > /tmp/aegis-macho-real.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-macho-real.log | head -1))"
    OMITIDAS=$(grep -c "OMITIDA" /tmp/aegis-macho-real.log || true)
    OMITIDAS=${OMITIDAS:-0}
    if [ "$OMITIDAS" -eq 0 ]; then
        echo "    ${GRIS}Ninguna se omitio: los Mach-O de estas pruebas son arm64 y x86_64${FIN}"
        echo "    ${GRIS}compilados con clang en esta maquina, con su MH_MAGIC_64 de verdad.${FIN}"
    else
        echo "    ${GRIS}AVISO: $OMITIDAS prueba(s) se omitieron. Pasan, y no ejercieron nada.${FIN}"
    fi
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-macho-real.log)"
    tail -30 /tmp/aegis-macho-real.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMac: el punto ciego del binario universal, cerrado"
if grep -q "fn un_universal_con_dos_rodajas_reales_trae_los_dos_programas" \
        crates/aegis-macho/tests/macho_real.rs \
   && ! grep -qE "fn (rodaja_principal|primera_rodaja|la_rodaja)\b" \
        crates/aegis-macho/src/universal.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}La segunda condicion importa tanto como la primera: no puede existir${FIN}"
    echo "    ${GRIS}una funcion que devuelva «la» rodaja. Con ella, el punto ciego se${FIN}"
    echo "    ${GRIS}reconstruye solo en cuanto alguien busque la forma comoda de usar${FIN}"
    echo "    ${GRIS}esto, y sera la forma comoda porque es la que devuelve un valor en vez${FIN}"
    echo "    ${GRIS}de una lista.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: falta la prueba del universal, o hay una API que devuelve una sola rodaja"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnforce: la postura de esta maquina, medida"
if cargo test -q -p aegis-enforce > /tmp/aegis-enforce.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-enforce.log | head -1))"
    echo "    ${GRIS}Las pruebas no usan una postura inventada: sondean ESTA maquina y${FIN}"
    echo "    ${GRIS}exigen que seccomp y Landlock salgan aplicando —porque estan— y que${FIN}"
    echo "    ${GRIS}BPF LSM salga con su motivo —porque no esta—. Si el kernel cambia, la${FIN}"
    echo "    ${GRIS}prueba falla y alguien lo mira, que es lo que tiene que pasar.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-enforce.log)"
    tail -30 /tmp/aegis-enforce.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnforce: la postura real de esta maquina de integracion"
if cargo test -q -p aegis-enforce la_postura_de_esta_maquina > /dev/null 2>&1; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}seccomp: APLICA. Landlock: APLICA. BPF LSM: NO, y este kernel ni${FIN}"
    echo "    ${GRIS}siquiera publica /sys/kernel/security/lsm, asi que no es que este${FIN}"
    echo "    ${GRIS}apagado: es que no trae el framework. La postura lo dice con esa${FIN}"
    echo "    ${GRIS}frase en vez de con un booleano, porque «no disponible» y «disponible${FIN}"
    echo "    ${GRIS}y sin habilitar» llevan a dos sitios distintos a quien lo lea.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la postura de esta maquina no se pudo medir"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnforce: observar no cuenta como aplicar, y se falla cerrado"
FALTAN=""
for prueba in \
    observar_no_cuenta_como_aplicar \
    una_politica_que_exige_aplicar_se_rechaza_donde_no_se_puede_aplicar \
    un_agente_que_no_puede_bloquear_no_se_describe_como_protegiendo \
    lo_de_otras_plataformas_no_sale_como_carencia ; do
    grep -rq "fn $prueba" crates/aegis-enforce/ || FALTAN="$FALTAN $prueba"
done
if [ -z "$FALTAN" ]; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}La cuarta es la que evita que esto se vuelva ruido: si lo de otras${FIN}"
    echo "    ${GRIS}plataformas saliera como carencia, cada endpoint de Linux reportaria${FIN}"
    echo "    ${GRIS}tres por no ser Windows ni un Mac, y el informe dejaria de leerse —que${FIN}"
    echo "    ${GRIS}es la forma habitual de que un aviso importante se pierda—.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: falta la prueba de$FALTAN"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMac + AegisEnforce: ninguno de los dos escribe unsafe"
if grep -q '#!\[forbid(unsafe_code)\]' crates/aegis-macho/src/lib.rs \
   && grep -q '#!\[forbid(unsafe_code)\]' crates/aegis-enforce/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: los dos tendrian que prohibir unsafe"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMac + AegisEnforce: lo que esta fase NO cierra"
echo "    ${GRIS}AUSENTE${FIN}: la validacion de la firma de codigo de macOS. Se localiza el"
echo "    ${GRIS}LC_CODE_SIGNATURE y se dice que bytes ocupa; validar el SuperBlob, su${FIN}"
echo "    ${GRIS}CodeDirectory, los hashes de pagina y la cadena hasta Apple es otro${FIN}"
echo "    ${GRIS}trabajo. Por eso el metodo se llama declara_firma y no firmado.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: ejecutables Mach-O enlazados. No hay ld64.lld en esta maquina,"
echo "    ${GRIS}asi que se compilan OBJETOS reales. Traen encabezado, comandos y${FIN}"
echo "    ${GRIS}segmentos —lo que este lector recorre— y no traen LC_MAIN ni${FIN}"
echo "    ${GRIS}LC_LOAD_DYLIB, que solo aparecen al enlazar. Esos caminos estan probados${FIN}"
echo "    ${GRIS}con vistas construidas, y se dice cual es cual.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: BPF LSM ejercido contra el kernel. Este no lo trae. La"
echo "    ${GRIS}postura lo detecta y lo declara, que es exactamente lo que se pedia de${FIN}"
echo "    ${GRIS}ella; lo que no se puede es probar aqui el camino de negacion real.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisMac + AegisEnforce verificado${FIN}"
else
    echo "${ROJO}==> AegisMac + AegisEnforce: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
