#!/usr/bin/env bash
#
# Verificacion de AegisMemForensics (analisis forense de memoria, FASE 86).
#
# LA INVARIANTE QUE DEFINE ESTE CRATE, Y QUE SE COMPRUEBA POR AUSENCIA.
#
# Un adquiridor de memoria forense lee la memoria de procesos ajenos con
# privilegios. La diferencia entre esa herramienta y una de ataque no esta en la
# intencion de quien la use: esta en QUE OPERACIONES EXISTEN. Un adquiridor que
# pudiera escribir seria una primitiva de inyeccion con otro nombre, y la tendria
# cualquiera que se hiciera con el agente.
#
# Por eso `Lectura` tiene un metodo, devuelve bytes, y no hay ningun camino de
# escritura en todo el crate: ni process_vm_writev, ni ptrace, ni un OpenOptions
# que pida escritura. No es que este desactivado: es que no esta.
#
# Una ausencia solo se puede comprobar de una forma: buscando lo que no deberia
# estar y fallando si aparece. Es la invariante 9 del encargo.
#
# LA OTRA TESIS. Lo que distingue el codigo de un implante del codigo del sistema
# no es como es, es DE DONDE VIENE: el codigo legitimo llega al espacio de
# direcciones mapeado desde un fichero que sigue en disco y se puede volver a
# leer. Codigo ejecutable sin ese fichero detras lo escribio alguien ahi en
# ejecucion.
#
# Esta puerta comprueba cinco cosas:
#
#   1. NO HAY CAMINO DE ESCRITURA. Ni de ejecucion.
#   2. EL MAPA DE UN PROCESO REAL SE LEE ENTERO. Se lee /proc/self/maps de este
#      mismo proceso de pruebas: si el lector no entiende el formato de esta
#      maquina, todo lo demas esta construido sobre un mapa mal leido.
#   3. EL ANALISIS NO PRODUCE RUIDO EN UN PROCESO NORMAL. Un analisis forense que
#      senale algo en cada proceso de cada maquina no sirve para nada.
#   4. UN MAPA HOSTIL NO CUELGA NI AGOTA LA MEMORIA. El mapa lo escribe la
#      herramienta que hizo el volcado, y esa herramienta puede estar rota o
#      mentir: una region que diga ocupar todo el espacio de direcciones no puede
#      hacer reservar por su tamano declarado.
#   5. LA AUSENCIA SOLO SIGNIFICA ALGO SI SE MIRO TODO.
#
# EL MURO, declarado: este crate NO adquiere memoria de un proceso vivo y NO
# reconstruye las estructuras del nucleo. Lo primero exige privilegios y
# mecanismos que dependen del sistema y lo hace `aegis-memhunter`; lo segundo
# depende de la version exacta del nucleo, y hacerlo a medias produce listas de
# procesos inventadas.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisMemForensics: no hay camino de escritura ni de ejecucion"
# La comprobacion central del crate, y la unica forma de comprobar una ausencia.
# Se busca en el CODIGO, no en la prosa: la documentacion de este crate nombra
# `ptrace` y `process_vm_writev` precisamente para decir que no estan, y un
# filtro que no distinguiera las dos cosas haria imposible explicar la
# invariante sin romperla.
ESCRITURA=$(grep -rnE "process_vm_writev|ptrace|POKEDATA|OpenOptions|\.write\(|write_all|create\(true\)|std::process|Command::new|mmap|PROT_EXEC|transmute|asm!" \
    crates/aegis-volcado/src/ | grep -vE "^[^:]+:[0-9]+: *//" || true)
if [ -z "$ESCRITURA" ] && grep -q "#!\[forbid(unsafe_code)\]" crates/aegis-volcado/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}El rasgo Lectura tiene un metodo y devuelve bytes. No hay en todo el${FIN}"
    echo "    ${GRIS}crate una escritura a memoria ajena, ni un fichero abierto para${FIN}"
    echo "    ${GRIS}escribir, ni un proceso lanzado, ni unsafe. Un adquiridor que pudiera${FIN}"
    echo "    ${GRIS}escribir seria una primitiva de inyeccion con otro nombre, y la tendria${FIN}"
    echo "    ${GRIS}cualquiera que se hiciera con el agente.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: ha aparecido un camino que no deberia existir"
    echo "$ESCRITURA" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMemForensics: el modelo de regiones y el analisis"
if cargo test -q -p aegis-volcado --lib > /tmp/aegis-volcado-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-volcado-lib.log | head -1))"
    echo "    ${GRIS}Una lectura no cruza de una region a la siguiente: devolveria bytes de${FIN}"
    echo "    ${GRIS}otra parte del espacio de direcciones como si fueran contiguos, y el${FIN}"
    echo "    ${GRIS}desensamblador los leeria como codigo seguido — instrucciones que el${FIN}"
    echo "    ${GRIS}programa no tiene. Y una direccion sin mapear da error en vez de ceros.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-volcado-lib.log)"
    tail -30 /tmp/aegis-volcado-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMemForensics: contra el mapa de memoria de este mismo proceso"
if cargo test -q -p aegis-volcado --test memoria_real -- --nocapture \
        > /tmp/aegis-volcado-real.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-volcado-real.log | head -1))"
    grep -oE "/proc/self/maps: [0-9]+ regiones leidas" /tmp/aegis-volcado-real.log \
        | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    grep -oE "mapa de [0-9]+ regiones: .*" /tmp/aegis-volcado-real.log \
        | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    grep -oE "[0-9]+ regiones ejecutables, [0-9]+ de ellas sin respaldo de fichero" \
        /tmp/aegis-volcado-real.log | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    echo "    ${GRIS}Llegar a cero costo una correccion medida: [vdso] y [vsyscall] son${FIN}"
    echo "    ${GRIS}ejecutables y no vienen de ningun fichero, asi que encajaban en la${FIN}"
    echo "    ${GRIS}definicion de «codigo que alguien escribio ahi». Y no lo son: las pone${FIN}"
    echo "    ${GRIS}el nucleo en cada proceso que arranca. Sin esa exclusion, el analisis${FIN}"
    echo "    ${GRIS}senalaba dos hallazgos en TODOS los procesos de todas las maquinas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-volcado-real.log)"
    tail -30 /tmp/aegis-volcado-real.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMemForensics: la ausencia solo significa algo si se miro todo"
if grep -q "pub fn la_ausencia_significa_algo" crates/aegis-volcado/src/hallazgos.rs \
   && grep -q "regiones_miradas == self.regiones_candidatas" crates/aegis-volcado/src/hallazgos.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Hacen falta las dos cosas: que ninguna region con codigo se quedara sin${FIN}"
    echo "    ${GRIS}desensamblar por el tope, y que el desensamblado no se cortara por el${FIN}"
    echo "    ${GRIS}plazo. Con cualquiera a medias, una lista vacia significa «no dio${FIN}"
    echo "    ${GRIS}tiempo a mirar», y en un informe forense esas dos frases no son la${FIN}"
    echo "    ${GRIS}misma.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: la condicion de cobertura cambio o desaparecio"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisMemForensics: lo que esta fase NO cierra"
echo "    ${GRIS}AUSENTE${FIN}: la adquisicion de memoria de un proceso vivo. Exige"
echo "    ${GRIS}privilegios y mecanismos que dependen del sistema, y la hace${FIN}"
echo "    ${GRIS}aegis-memhunter con otras garantias. Aqui entra memoria ya volcada.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: la reconstruccion de las estructuras del nucleo. Listar"
echo "    ${GRIS}procesos a partir de memoria fisica depende de la version exacta del${FIN}"
echo "    ${GRIS}nucleo, y hacerlo a medias produce listas de procesos inventadas.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: un volcado de memoria de verdad en las pruebas. No hay uno"
echo "    ${GRIS}en esta maquina, asi que lo que se ejercita contra lo real es el MAPA de${FIN}"
echo "    ${GRIS}este mismo proceso, que si lo es. El camino del fichero se prueba con${FIN}"
echo "    ${GRIS}memoria construida, y se dice cual es cual.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisMemForensics verificado${FIN}"
else
    echo "${ROJO}==> AegisMemForensics: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
