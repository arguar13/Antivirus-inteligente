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
# Esta puerta comprueba seis cosas:
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
#   6. DISPONIBLE NO CUENTA COMO APLICADO. El estado de cada capa lo imprime el
#      binario, y ningun texto del repo puede dar por impuesta una capa que la
#      postura medida no da por aplicada.
#
# DISPONIBLE NO ES APLICADO (H-28). Que el kernel admita seccomp, Landlock o BPF
# LSM no dice que el producto los este usando. La postura solo da una capa por
# aplicada con evidencia medida sobre un proceso concreto; sin ella, la da por
# disponible. Esta puerta no escribe a mano el estado de ninguna capa: lo imprime
# el ejemplo `postura` de aegis-enforce, y ademas falla si algun texto del repo
# da por impuesta una capa cuyo estado medido no es APLICA.
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
    echo "    ${GRIS}Las pruebas separan lo que el kernel OFRECE de lo que el producto${FIN}"
    echo "    ${GRIS}IMPONE. Sin un proceso medido, la postura de ESTA maquina no puede dar${FIN}"
    echo "    ${GRIS}ninguna capa por aplicada; con un hijo real confinado (filtro seccomp y${FIN}"
    echo "    ${GRIS}dominio Landlock puestos en su hilo) la da por aplicada y dice con que${FIN}"
    echo "    ${GRIS}evidencia: /proc/<tid>/status, no la configuracion.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-enforce.log)"
    tail -30 /tmp/aegis-enforce.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnforce: la postura real de esta maquina, leida del binario"
POSTURA=/tmp/aegis-enforce-postura.txt
if cargo run -q -p aegis-enforce --example postura > "$POSTURA" 2> /tmp/aegis-enforce-postura.err; then
    SIN_EVIDENCIA=""
    while IFS='|' read -r capa etiqueta detalle; do
        case "$capa" in ''|'#'*) continue ;; esac
        echo "    ${GRIS}${capa}: ${etiqueta}. ${detalle}${FIN}"
        if [ "$etiqueta" = "APLICA" ]; then
            SIN_EVIDENCIA="$SIN_EVIDENCIA [$capa]"
        fi
    done < "$POSTURA"
    if [ -n "$SIN_EVIDENCIA" ]; then
        echo "    ${ROJO}FALLO${FIN}: medida sin ningun testigo, y aun asi con evidencia:$SIN_EVIDENCIA"
        FALLOS=$((FALLOS + 1))
    else
        echo "    ${VERDE}OK${FIN}"
        echo "    ${GRIS}Estas lineas no estan escritas en este script: las imprime el ejemplo${FIN}"
        echo "    ${GRIS}postura de aegis-enforce. Sin testigos no hay proceso del producto${FIN}"
        echo "    ${GRIS}sobre el que medir, asi que lo que el kernel ofrece sale DISPONIBLE y${FIN}"
        echo "    ${GRIS}nada sale APLICA. El agente se describe asi:${FIN}"
        echo "    ${GRIS}$(sed -n 's/^# //p' "$POSTURA")${FIN}"
    fi
else
    : > "$POSTURA"
    echo "    ${ROJO}FALLO${FIN}: la postura de esta maquina no se pudo medir"
    tail -30 /tmp/aegis-enforce-postura.err | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisEnforce: ningun texto afirma que se impone lo que solo esta disponible"
AFIRMACIONES=/tmp/aegis-enforce-afirmaciones.txt
: > "$AFIRMACIONES"
if [ -s "$POSTURA" ]; then
    while IFS='|' read -r capa etiqueta _; do
        case "$capa" in ''|'#'*) continue ;; esac
        case "$etiqueta" in APLICA|OTRA-PLATAFORMA) continue ;; esac
        case "$capa" in
            seccomp) re='seccomp' ;;
            Landlock) re='landlock' ;;
            'BPF LSM') re='bpf[-_ ]?lsm' ;;
            XDP) re='xdp' ;;
            *) continue ;;
        esac
        # La capa seguida de dos puntos, barra de tabla o igual (con o sin
        # negrita) y del verbo: el estado escrito a mano como si fuera un hecho.
        como_estado="(${re})[[:space:]]*([*][*])?[[:space:]]*[:|=][[:space:]]*([*][*])?[[:space:]]*(aplica|aplicando|impone|imponiendo)([^[:alnum:]_]|$)"
        # La capa, quiza junto a otra, y el verbo en gerundio: una frase, o el
        # nombre de una prueba, que lo afirma.
        como_frase="(${re})([ _]y[ _][[:alnum:]]+)?[ _](esta|estan|está|están|sale|salen|salga|salgan)[ _](aplicando|imponiendo)"
        grep -rniE --include='*.rs' --include='*.md' --include='*.sh' --include='*.toml' --exclude-dir=target --exclude-dir=.git --exclude-dir=node_modules -e "$como_estado" -e "$como_frase" . 2>/dev/null | sed "s|^|[$capa: $etiqueta] |" >> "$AFIRMACIONES" || true
    done < "$POSTURA"
fi
if [ ! -s "$POSTURA" ]; then
    echo "    ${ROJO}FALLO${FIN}: sin postura medida no se puede contrastar ningun texto"
    FALLOS=$((FALLOS + 1))
elif [ -s "$AFIRMACIONES" ]; then
    echo "    ${ROJO}FALLO${FIN}: estos textos dan por impuesta una capa que la postura medida no da por aplicada:"
    head -40 "$AFIRMACIONES" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
else
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Ningun texto del repo (codigo, docs, scripts, configuracion) escribe${FIN}"
    echo "    ${GRIS}como hecho que se impone una capa que la postura medida da por${FIN}"
    echo "    ${GRIS}disponible, observada o ausente. Lo que se diga de una capa sale de${FIN}"
    echo "    ${GRIS}medirla, no de escribirlo.${FIN}"
fi

echo "==> AegisEnforce: observar no cuenta como aplicar, disponible tampoco, y se falla cerrado"
FALTAN=""
for prueba in \
    observar_no_cuenta_como_aplicar \
    una_politica_que_exige_aplicar_se_rechaza_donde_no_se_puede_aplicar \
    un_agente_que_no_puede_bloquear_no_se_describe_como_protegiendo \
    lo_de_otras_plataformas_no_sale_como_carencia \
    disponible_no_es_aplicado_en_esta_maquina \
    aplica_solo_sale_de_evidencia \
    lo_disponible_no_cumple_una_politica_de_bloqueo \
    sin_evidencia_esta_maquina_se_describe_como_solo_observando \
    un_filtro_heredado_no_es_evidencia \
    aplica_solo_con_un_testigo_medido_y_disponible_sin_el \
    un_testigo_muerto_no_es_evidencia ; do
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
LSM_EN_REPO=$(grep -rl 'SEC("lsm' drivers/linux/aegis-bpf/src 2>/dev/null | wc -l)
ESTADO_BPF=$(awk -F'|' '$1 == "BPF LSM" { print $2 }' "$POSTURA" 2>/dev/null)
echo "    ${GRIS}AUSENTE${FIN}: BPF LSM ejercido contra el kernel. Programas BPF LSM en"
echo "    ${GRIS}drivers/linux/aegis-bpf: ${LSM_EN_REPO}. La postura de esta maquina lo da${FIN}"
echo "    ${GRIS}por ${ESTADO_BPF:-SIN MEDIR}: sin un enlace LSM medido no puede darlo por${FIN}"
echo "    ${GRIS}aplicado, y lo que no se puede es probar aqui el camino de negacion real.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisMac + AegisEnforce verificado${FIN}"
else
    echo "${ROJO}==> AegisMac + AegisEnforce: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
