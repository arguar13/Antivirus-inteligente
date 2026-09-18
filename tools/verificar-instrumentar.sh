#!/usr/bin/env bash
#
# Verificacion de AegisInstrument (instrumentacion confinada, FASE 87).
#
# LA INVARIANTE, Y POR QUE ES DE TIPOS Y NO DE BANDERA.
#
# Instrumentar un proceso vivo tiene dos modos que se parecen mucho por fuera:
# observar y intervenir. El primero lee; el segundo escribe en el espacio de
# direcciones de otro proceso, que es exactamente lo que hace una inyeccion de
# codigo.
#
# La forma habitual de separarlos es una bandera. Esa separacion no resiste nada:
# una bandera se pone mal, se lee de configuracion, se invierte en un refactor, y
# el dia que falle nadie se entera porque el codigo compila igual.
#
# Aqui la separacion es de TIPOS. `Observador` existe siempre y no tiene ninguna
# operacion de escritura. `Interventor` necesita una `&Jaula` para construirse, y
# `Jaula` solo se obtiene MIDIENDO que se esta dentro del confinamiento. Fuera de
# la jaula no se puede escribir la llamada — no porque una comprobacion lo impida
# en ejecucion, sino porque el programa no compila.
#
# Y nadie puede fabricar su propia prueba: `PruebaDeJaula` depende de un rasgo
# privado del modulo, asi que ningun otro crate puede implementarlo.
#
# Esta puerta comprueba seis cosas:
#
#   1. LOS DOS EJEMPLOS QUE NO COMPILAN, con su codigo de error atado. Un
#      `compile_fail` sin codigo de error pasa igual con una errata dentro, y no
#      comprueba nada.
#   2. `Jaula::medir` FALLA EN ESTA MAQUINA. Una comprobacion de confinamiento que
#      dijera que si en la maquina de desarrollo no comprobaria nada en ninguna
#      parte, y todo lo demas seria decorado.
#   3. EL OBSERVADOR NO TIENE OPERACION DE ESCRITURA.
#   4. EL PLAN DE INSTRUMENTACION ES UN DATO INERTE. No tiene `aplicar`.
#   5. EL PLAN SALE DE LO QUE EL ANALISIS ESTATICO NO PUDO RESOLVER, y no
#      instrumenta lo que ya sabia: instrumentar todo es inservible.
#   6. LOS SIMBOLOS SE RESUELVEN EN ORDEN DE FIABILIDAD, y lo deducido se declara
#      como deduccion.
#
# EL MURO, declarado: aqui NO se engancha un proceso de verdad. Poner un uprobe
# de eBPF exige privilegios que esta maquina de integracion no da, y fingirlo con
# un enganche simulado seria exactamente el tipo de prueba que pasa siempre y no
# comprueba nada. Lo que SI se ejerce entero es la parte que decide donde
# enganchar, que es la que tiene la logica.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisInstrument: los dos ejemplos que NO compilan"
if cargo test -q -p aegis-instrumentar --doc > /tmp/aegis-instr-doc.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-instr-doc.log | head -1))"
    echo "    ${GRIS}Uno intenta implementar PruebaDeJaula desde fuera y falla con E0277,${FIN}"
    echo "    ${GRIS}que es exactamente «no cumple el rasgo sellado»; el otro intenta${FIN}"
    echo "    ${GRIS}construir un Interventor sin jaula y falla con E0308. Los codigos van${FIN}"
    echo "    ${GRIS}atados a proposito: un compile_fail sin codigo pasa igual con una${FIN}"
    echo "    ${GRIS}errata dentro y no comprueba nada.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-instr-doc.log)"
    tail -30 /tmp/aegis-instr-doc.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisInstrument: la jaula, los planes y los simbolos"
if cargo test -q -p aegis-instrumentar --lib > /tmp/aegis-instr-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-instr-lib.log | head -1))"
    echo "    ${GRIS}Jaula::medir falla en ESTA maquina, y hay una prueba que lo comprueba.${FIN}"
    echo "    ${GRIS}Se exigen tres senales independientes: un marcador a secas lo crea${FIN}"
    echo "    ${GRIS}cualquiera, y correr bajo un hipervisor lo hace media nube. Y una${FIN}"
    echo "    ${GRIS}senal que no se puede medir NO cuenta a favor del confinamiento — si${FIN}"
    echo "    ${GRIS}contara, un entorno donde no se puede medir nada pareceria el mas${FIN}"
    echo "    ${GRIS}confinado de todos.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-instr-lib.log)"
    tail -30 /tmp/aegis-instr-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisInstrument: el plan sale de lo que el analisis estatico no supo"
if cargo test -q -p aegis-instrumentar --test instrumentar_real -- --nocapture \
        > /tmp/aegis-instr-real.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-instr-real.log | head -1))"
    grep -oE "/bin/[a-z]+: [0-9]+ llamadas directas, ninguna instrumentada; [0-9]+ puntos de destino" \
        /tmp/aegis-instr-real.log | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
    echo "    ${GRIS}Instrumentar todo es inservible: tarda mil veces mas, produce una traza${FIN}"
    echo "    ${GRIS}que nadie lee y va tan lenta que la muestra lo nota. Lo que escala es${FIN}"
    echo "    ${GRIS}dejar que el analisis estatico diga donde se rindio, y preguntarle a la${FIN}"
    echo "    ${GRIS}ejecucion SOLO eso. Es la razon de que la FASE 85 vaya antes que esta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-instr-real.log)"
    tail -30 /tmp/aegis-instr-real.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisInstrument: el observador no puede escribir, y el plan no se aplica"
# Se comprueba por AUSENCIA, en el codigo y no en la prosa.
ESCRITURA=$(grep -nE "fn (escribir|aplicar|inyectar|parchear)" \
    crates/aegis-instrumentar/src/jaula.rs crates/aegis-instrumentar/src/plan.rs \
    | grep -v "impl<'j> Interventor" || true)
# El unico `fn escribir` permitido esta en Interventor; en Observador y en Plan no
# puede haber ninguno.
EN_OBSERVADOR=$(awk '/^impl Observador \{/,/^\}/' crates/aegis-instrumentar/src/jaula.rs \
    | grep -cE "fn (escribir|aplicar|inyectar|parchear)" || true)
EN_PLAN=$(grep -cE "fn (aplicar|escribir|inyectar)" crates/aegis-instrumentar/src/plan.rs || true)
if [ "${EN_OBSERVADOR:-0}" -eq 0 ] && [ "${EN_PLAN:-0}" -eq 0 ] \
   && grep -q "#!\[forbid(unsafe_code)\]" crates/aegis-instrumentar/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Observador no tiene ni un metodo que escriba, y Plan no tiene aplicar:${FIN}"
    echo "    ${GRIS}un plan es una lista de direcciones con sus razones, y lo unico que se${FIN}"
    echo "    ${GRIS}puede hacer con el es leerlo. Quien lo aplica es la microVM — otro${FIN}"
    echo "    ${GRIS}crate, otra maquina virtual, otro espacio de direcciones.${FIN}"
    echo "    ${GRIS}Si este crate tuviera un aplicar(pid), cualquiera que se hiciera con el${FIN}"
    echo "    ${GRIS}agente tendria una primitiva de inyeccion escrita, probada y firmada${FIN}"
    echo "    ${GRIS}por el fabricante.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: ha aparecido una operacion de escritura donde no puede haberla"
    echo "$ESCRITURA" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisInstrument: lo que esta fase NO cierra"
echo "    ${GRIS}AUSENTE${FIN}: el enganche real por uprobe de eBPF. Exige privilegios que"
echo "    ${GRIS}esta maquina de integracion no da, y fingirlo con un enganche simulado${FIN}"
echo "    ${GRIS}seria el tipo de prueba que pasa siempre y no comprueba nada. Lo que SI${FIN}"
echo "    ${GRIS}se ejerce entero es la parte que decide donde enganchar, que es la que${FIN}"
echo "    ${GRIS}tiene la logica, y se ejerce contra /bin/ls y /bin/bash de verdad.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: la lectura de DWARF. Es un formato grande y hacerlo a medias"
echo "    ${GRIS}produce direcciones plausibles y equivocadas. Queda DECLARADO en el${FIN}"
echo "    ${GRIS}modelo —la via existe— y sin resolver, que es la diferencia entre un${FIN}"
echo "    ${GRIS}hueco declarado y uno escondido.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisInstrument verificado${FIN}"
else
    echo "${ROJO}==> AegisInstrument: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
