#!/usr/bin/env bash
#
# Verificacion de AegisDisasm (desensamblado, grafos y capacidades, FASE 85).
#
# LA TESIS. Una firma dice «esto es Emotet» y no dice por que; cuando se
# equivoca no hay forma de saberlo sin repetir el analisis a mano. Una capacidad
# dice «esto inyecta codigo en otro proceso» Y ENSENA LAS INSTRUCCIONES que lo
# hacen. Quien la lea puede comprobarla, y quien la escriba no puede esconder que
# la regla era floja.
#
# Aqui eso no es una convencion sino un tipo: `Capacidad::nueva` devuelve `None`
# sin evidencia, y el campo es privado. Una capacidad sin evidencia no es algo
# que alguien pueda olvidarse de comprobar: es un valor que no existe.
#
# LA OTRA TESIS, la que se mide y casi nunca se mide. Un motor de capacidades se
# juzga por lo que dice de los ficheros que NO son malware, porque son el 99,99 %
# de los que va a ver. Uno que encuentre cinco capacidades en `ls` llena la
# bandeja del analista de ruido, y una bandeja llena de ruido es una bandeja que
# nadie mira. Esta puerta ejecuta el catalogo entero contra `/bin/ls`,
# `/bin/bash` y la libc de la maquina, y exige que salga practicamente nada.
#
# Esta puerta comprueba seis cosas:
#
#   1. EL DECODIFICADOR ACIERTA, COTEJADO CONTRA OTRO. Se desensamblan los
#      binarios de la maquina y se comparan las longitudes instruccion a
#      instruccion contra `objdump`, que es una implementacion independiente. Un
#      desensamblador que se desplaza un byte produce un desensamblado que PARECE
#      correcto, y esa es la peor forma de fallar que puede tener esta pieza.
#   2. EL ANALISIS SE CORTA Y LO DICE. Toda salida viaja con su cobertura, y
#      `completa()` es lo unico que autoriza a leer una lista vacia como «no hay
#      nada». Sin eso, «no dio tiempo a mirar» y «se miro y no habia» producen el
#      mismo hueco en un panel, y solo una es aceptable.
#   3. NINGUNA CAPACIDAD SIN EVIDENCIA, POR CONSTRUCCION.
#   4. CADA REGLA, POR LOS DOS LADOS. Positivo y negativo, las treinta y dos, y
#      la prueba recorre el catalogo: anadir una regla sin probarla rompe la
#      suite.
#   5. EL RUIDO, MEDIDO CONTRA LOS BINARIOS DE ESTA MAQUINA.
#   6. NADA SE EJECUTA. Es la invariante 8, y se verifica por lo que FALTA: no
#      hay en todo el crate una llamada que transfiera control a los bytes
#      analizados, ni que los escriba en disco, ni que abra un proceso.
#
# EL MURO, declarado en vez de disimulado: sobre un binario benigno compilado de
# la forma normal, el analisis de constantes resuelve casi ninguna llamada
# indirecta, porque el patron que resuelve no aparece ahi. Esta escrito con los
# numeros en la cabecera de `llamadas.rs`, y no se disimula subiendo la regla
# hasta que salga algo.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisDisasm: el modelo, los decodificadores y los grafos"
if cargo test -q -p aegis-disasm --lib > /tmp/aegis-disasm-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-disasm-lib.log | head -1))"
    echo "    ${GRIS}El modelo de instruccion guarda lo que el ANALISIS necesita y no el${FIN}"
    echo "    ${GRIS}texto de cada instruccion: dos asignaciones por instruccion, para un${FIN}"
    echo "    ${GRIS}texto que solo se lee en las que acaban siendo evidencia. Asi una cota${FIN}"
    echo "    ${GRIS}de tiempo no se queda sin memoria antes de quedarse sin tiempo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-disasm-lib.log)"
    tail -30 /tmp/aegis-disasm-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: cotejado instruccion a instruccion contra objdump"
if cargo test -q -p aegis-disasm --test disasm_real -- --nocapture \
        > /tmp/aegis-disasm-real.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-disasm-real.log | head -1))"
    grep -oE "/[^ ]*: [0-9]+ instrucciones de [0-9]+ funciones, identicas a objdump" /tmp/aegis-disasm-real.log | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    grep -oE "/[^ ]*: [0-9.]+[mµ]?s — [0-9]+ bloques[^\"]*" /tmp/aegis-disasm-real.log | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-disasm-real.log)"
    tail -30 /tmp/aegis-disasm-real.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: cada regla del catalogo, por los dos lados"
if cargo test -q -p aegis-disasm --test capacidades > /tmp/aegis-disasm-cap.log 2>&1; then
    REGLAS=$(grep -c "^    Regla {" crates/aegis-disasm/src/reglas.rs)
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-disasm-cap.log | head -1), $REGLAS reglas)"
    echo "    ${GRIS}El caso negativo importa mas que el positivo: una regla que dispara${FIN}"
    echo "    ${GRIS}con lo que debe y TAMBIEN con lo que no parece que funciona, y el${FIN}"
    echo "    ${GRIS}fallo aparece en produccion como ruido que el analista aprende a${FIN}"
    echo "    ${GRIS}ignorar. Una regla ignorada es peor que ninguna: ocupa el sitio de la${FIN}"
    echo "    ${GRIS}que si habria servido.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-disasm-cap.log)"
    tail -30 /tmp/aegis-disasm-cap.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: el ruido contra los binarios de esta maquina"
if grep -qE "/(bin|usr)[^ ]*: [0-9]+ capacidades" /tmp/aegis-disasm-real.log; then
    grep -oE "/(bin|usr)[^ ]*: [0-9]+ capacidades [[^]]*]" /tmp/aegis-disasm-real.log \
        | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    echo "    ${GRIS}Llegar a esto costo tres correcciones, y las tres estan escritas en el${FIN}"
    echo "    ${GRIS}codigo: el ambito de funcion, la ventana de proximidad y el segmento${FIN}"
    echo "    ${GRIS}del bloque de entorno por anchura. Antes de ellas el catalogo disparaba${FIN}"
    echo "    ${GRIS}en los tres binarios, con evidencia de aspecto impecable.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: no se midio el ruido contra ningun binario del sistema"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: una capacidad sin evidencia no se puede construir"
if grep -q "    evidencias: Vec<Evidencia>," crates/aegis-disasm/src/capacidad.rs \
   && ! grep -q "    pub evidencias:" crates/aegis-disasm/src/capacidad.rs \
   && grep -q "if evidencias.is_empty() {" crates/aegis-disasm/src/capacidad.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}El campo es privado y el unico constructor devuelve None sin evidencia.${FIN}"
    echo "    ${GRIS}No es una comprobacion que alguien pueda olvidarse de hacer con prisa:${FIN}"
    echo "    ${GRIS}es que el valor no existe. Si el campo se hiciera publico, esta linea${FIN}"
    echo "    ${GRIS}falla y alguien tiene que explicar por que.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el campo de evidencias dejo de ser privado, o el constructor ya no comprueba"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: el analisis no ejecuta nada (invariante 8)"
# Se verifica por lo que FALTA. Un desensamblador que ejecutara lo que
# desensambla es un ejecutor de malware con otro nombre, y la unica forma de
# comprobar que no lo hace es que no exista el camino.
PROHIBIDO=$(grep -rnE "std::process::Command|Command::new|libloading|mmap|PROT_EXEC|transmute|asm!|\.set_permissions|OpenOptions" \
    crates/aegis-disasm/src/ || true)
if [ -z "$PROHIBIDO" ] && grep -q "#!\[forbid(unsafe_code)\]" crates/aegis-disasm/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}No hay en todo el crate una llamada que lance un proceso, cargue una${FIN}"
    echo "    ${GRIS}biblioteca, proyecte memoria ejecutable o reinterprete bytes como${FIN}"
    echo "    ${GRIS}codigo, y unsafe esta prohibido. Entra un &[u8] y sale una estructura${FIN}"
    echo "    ${GRIS}de datos. No es que este desactivado: es que no esta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: hay un camino que podria ejecutar lo que se analiza"
    echo "$PROHIBIDO" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisDisasm: lo que esta fase NO cierra"
echo "    ${GRIS}AUSENTE${FIN}: la carga de un binario empaquetado. Estas reglas se evaluan"
echo "    ${GRIS}sobre codigo desensamblado, y un empaquetado no ensena el suyo hasta que${FIN}"
echo "    ${GRIS}se ejecuta: sobre el se vera el desempaquetador y no la carga. Sale en la${FIN}"
echo "    ${GRIS}cobertura, y es el trabajo de aegis-unpacker y de la detonacion.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: a que API se resuelve un hash de nombre. Haria falta el"
echo "    ${GRIS}diccionario de exportaciones de la maquina objetivo; adivinarlo produciria${FIN}"
echo "    ${GRIS}nombres inventados con aspecto de hechos. Se declara que hay resolucion${FIN}"
echo "    ${GRIS}por hash, con que algoritmo y desde donde.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: destinos indirectos que vienen de memoria. Un"
echo "    ${GRIS}call [rip+0x2f10] lee un puntero que el analisis estatico no conoce. Se${FIN}"
echo "    ${GRIS}cuentan y se dicen con su motivo en vez de fingir que no estan.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisDisasm verificado${FIN}"
else
    echo "${ROJO}==> AegisDisasm: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
