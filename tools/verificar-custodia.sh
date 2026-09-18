#!/usr/bin/env bash
#
# Verificacion de AegisArtifact (forense de flota con cadena de custodia, FASE 82).
#
# LA TESIS, dicha sin adornos: `aegis-forensics` ya recoge lo que hay que recoger
# antes de que desaparezca, y eso basta para INVESTIGAR. No basta para SOSTENER.
# En cuanto alguien discute la prueba —el cliente, su aseguradora, un regulador,
# un juez, o el propio analista seis meses despues— las preguntas que llegan no
# son sobre el contenido: como se sabe que estos bytes salieron de esa maquina,
# como se sabe que son los mismos que salieron, quien los ha tenido en las manos
# desde entonces, y si la hora del informe es la hora en que ocurrio. Un fichero
# suelto no contesta ninguna, y «confie en nuestro producto» es exactamente la
# respuesta que un forense no puede dar.
#
# Esta puerta comprueba las cinco propiedades que separan evidencia de ficheros:
#
#   1. EL FORMATO CANONICO NO SE MUEVE. Una firma cubre bytes, y JSON no tiene
#      forma canonica: el orden de las claves, el escapado y el formato de los
#      numeros cambian entre bibliotecas sin cambiar el significado. Firmar JSON
#      es firmar algo que dejara de reverificar dentro de unos anos, y fallara
#      justo cuando haga falta. Hay un vector dorado que congela el formato.
#   2. LA MANIPULACION SE DETECTA, UNA POR UNA. Cambiar un byte, recortar el
#      final, reetiquetar la evidencia para otro caso, borrar un paso de la
#      custodia, pegarle la cadena de otra. Cada una tiene su prueba y su error
#      con nombre propio.
#   3. LO QUE NO CONSTA NO SE APRUEBA. Una cadena vacia no es una cadena intacta:
#      no dice «nadie toco esto», dice «nadie anoto nada». Un firmante que no
#      esta en la PKI no se da por bueno por defecto.
#   4. EL VEREDICTO DICE LO QUE NO PRUEBA. «Custodia verificada: SI» induce a
#      entender cuatro cosas que la criptografia no establece. La lista de
#      limites viaja en la estructura de datos, no en una nota al pie.
#   5. UNA RECOGIDA INCOMPLETA NO SE PRESENTA COMO COMPLETA. Noventa y siete
#      piezas impecables de cien endpoints no son la evidencia del caso: los tres
#      que faltan son el sitio mas probable donde esta lo que se busca.
#
# EL MURO, declarado en vez de disimulado: esto prueba la CUSTODIA, no la
# recogida. Que un artefacto este intacto no dice que se recogiera todo, ni que
# la maquina no estuviera ya manipulada cuando el agente miro. Las dos cosas
# tienen su propia puerta —la recogida anota sus huecos, y `aegis-kintegrity`
# responde por el kernel— y este crate lo DICE en cada veredicto en vez de
# dejar que quien lea el informe suponga lo contrario.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisArtifact: el sello, la cadena y el veredicto"
if cargo test -q -p aegis-custodia --lib > /tmp/aegis-custodia-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-custodia-lib.log | head -1))"
    echo "    ${GRIS}La codificacion canonica es la base de todo lo demas y por eso se${FIN}"
    echo "    ${GRIS}prueba primero: sin longitud delante de cada campo, «ab»+«c» y${FIN}"
    echo "    ${GRIS}«a»+«bc» producen los mismos bytes, y una firma sobre el primero${FIN}"
    echo "    ${GRIS}valdria para el segundo. Se podria mover el limite entre dos campos${FIN}"
    echo "    ${GRIS}de la evidencia sin invalidar nada.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-custodia-lib.log)"
    tail -30 /tmp/aegis-custodia-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: evidencia REAL por las cuatro manos, y cada manipulacion"
if cargo test -q -p aegis-custodia --test custodia > /tmp/aegis-custodia-e2e.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-custodia-e2e.log | head -1))"
    echo "    ${GRIS}La evidencia de estas pruebas no esta inventada: son los bytes reales${FIN}"
    echo "    ${GRIS}de /proc/self/maps y del propio binario de la prueba, megabytes con${FIN}"
    echo "    ${GRIS}bytes no imprimibles. Un artefacto de mentira comprueba la aritmetica${FIN}"
    echo "    ${GRIS}de la firma; uno real comprueba tambien que el camino aguanta lo que${FIN}"
    echo "    ${GRIS}de verdad se recoge.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-custodia-e2e.log)"
    tail -30 /tmp/aegis-custodia-e2e.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: el formato canonico esta congelado por un vector dorado"
if grep -q "el_formato_canonico_no_puede_cambiar_sin_que_esto_falle" \
        crates/aegis-custodia/tests/custodia.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Es el seguro de vida de toda la evidencia ya sellada. Si alguien${FIN}"
    echo "    ${GRIS}cambia el orden de un campo, un prefijo de longitud o la etiqueta de${FIN}"
    echo "    ${GRIS}un documento, lo sellado con la version anterior deja de verificar${FIN}"
    echo "    ${GRIS}para siempre y sin aviso. Con el vector, ese cambio rompe la${FIN}"
    echo "    ${GRIS}compilacion hoy en vez de romper un caso dentro de tres anos.${FIN}"
    echo "    ${GRIS}El resumen del artefacto se coteja ademas contra sha256sum, que es${FIN}"
    echo "    ${GRIS}una implementacion de fuera: el vector no se autovalida.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: no hay vector dorado del formato canonico"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: ninguna ausencia se aprueba por defecto"
FALTAN=""
for prueba in \
    una_cadena_vacia_no_es_una_cadena_intacta \
    un_actor_que_no_consta_no_se_aprueba_por_defecto \
    una_evidencia_sin_ningun_paso_registrado_no_se_da_por_buena \
    un_conjunto_sin_ordenar_a_nadie_no_esta_completo_por_vacio ; do
    if ! grep -rq "fn $prueba" crates/aegis-custodia/; then
        FALTAN="$FALTAN $prueba"
    fi
done
if [ -z "$FALTAN" ]; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Las cuatro formas de aprobar por vacuidad, cada una con su prueba: una${FIN}"
    echo "    ${GRIS}cadena sin eslabones, un firmante que no consta, un sello sin custodia${FIN}"
    echo "    ${GRIS}y un conjunto de flota al que no se le ordeno nada a nadie. Esta${FIN}"
    echo "    ${GRIS}ultima la encontro la propia prueba al escribirla: con la lista de${FIN}"
    echo "    ${GRIS}endpoints vacia, las otras tres condiciones se cumplian por vacuidad y${FIN}"
    echo "    ${GRIS}el conjunto se declaraba completo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: falta la prueba de$FALTAN"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: el veredicto enumera lo que NO prueba"
if grep -q "pub no_demuestra: Vec<LimiteDeLaPrueba>" crates/aegis-custodia/src/verificar.rs \
   && grep -q "ClaveNoEsPersona" crates/aegis-custodia/src/verificar.rs \
   && grep -q "ElFinalSePuedePodar" crates/aegis-custodia/src/verificar.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Cinco limites, y uno de ellos es una limitacion REAL del metodo que${FIN}"
    echo "    ${GRIS}esta implementacion no puede cerrar: podar la cadena por el final deja${FIN}"
    echo "    ${GRIS}un prefijo valido, y ninguna cadena puede detectarlo por si sola. Lo${FIN}"
    echo "    ${GRIS}detecta la copia que conserva la contraparte que firmo el eslabon${FIN}"
    echo "    ${GRIS}podado. Esta escrito como prueba, con ese nombre, para que no se${FIN}"
    echo "    ${GRIS}olvide y para que si algun dia deja de ser cierto, falle y se mire.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el veredicto no enumera sus limites"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: la custodia no escribe unsafe"
if grep -q '#!\[forbid(unsafe_code)\]' crates/aegis-custodia/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Las dos llamadas al sistema que hacen falta —los dos relojes— viven${FIN}"
    echo "    ${GRIS}en aegis-scal, que es donde el producto concentra el unsafe. Anadir un${FIN}"
    echo "    ${GRIS}crate mas a la linea base habria sido lo comodo; el propio fichero de${FIN}"
    echo "    ${GRIS}linea base dice que lo correcto es lo contrario.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: aegis-custodia tendria que prohibir unsafe"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: el reloj que no se puede mover, medido de verdad"
if cargo test -q -p aegis-scal --lib reloj > /tmp/aegis-custodia-reloj.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-custodia-reloj.log | head -1))"
    echo "    ${GRIS}No basta con que el reloj de arranque avance: una prueba comprueba que${FIN}"
    echo "    ${GRIS}mide una espera REAL de veinte milisegundos, y otra que no es el mismo${FIN}"
    echo "    ${GRIS}reloj que el de pared. Sin eso, cablear los dos al mismo clockid${FIN}"
    echo "    ${GRIS}pasaria desapercibido y la deteccion de saltos de reloj —que es toda${FIN}"
    echo "    ${GRIS}la defensa contra un atacante que mueve la hora— no detectaria nada.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-custodia-reloj.log)"
    tail -20 /tmp/aegis-custodia-reloj.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisArtifact: lo que esta fase NO prueba"
echo "    ${GRIS}AUSENTE${FIN}: que la evidencia sea COMPLETA. Esta fase responde por lo"
echo "    ${GRIS}recogido, no por lo que el agente no pudo leer: eso son los huecos que${FIN}"
echo "    ${GRIS}anota aegis-forensics, y una evidencia integra de una recogida${FIN}"
echo "    ${GRIS}incompleta sigue siendo una recogida incompleta.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: que la maquina fuera de fiar ANTES de la recogida. El sello"
echo "    ${GRIS}cubre desde que el agente miro en adelante; si habia un rootkit alterando${FIN}"
echo "    ${GRIS}lo que el agente veia, la evidencia sera autentica y contara algo falso.${FIN}"
echo "    ${GRIS}Por eso existe la verificacion cruzada del kernel, que es otra puerta.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: que la clave la tuviera quien debia. Una clave robada de un"
echo "    ${GRIS}endpoint comprometido firma evidencia perfecta. Lo que acota ese riesgo${FIN}"
echo "    ${GRIS}esta fuera de aqui: claves de vida corta que nunca tocan el disco, y${FIN}"
echo "    ${GRIS}revocacion. Los tres salen impresos en cada veredicto.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisArtifact verificado${FIN}"
else
    echo "${ROJO}==> AegisArtifact: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
