#!/usr/bin/env bash
#
# Verificacion de AegisSwarm (enjambre autonomo, FASE 68).
#
# LA PREGUNTA QUE DECIDE ESTA FASE: si un agente puede decirle al enjambre
# "aisla al equipo X", que consigue el atacante que comprometa UN endpoint?
# Consigue un boton de denegacion de servicio sobre toda la organizacion, y
# puede aislar precisamente las maquinas que lo habrian detectado. Una malla de
# ordenes mal disenada no es una defensa: es movimiento lateral regalado.
#
# La respuesta del diseno es una frase —el enjambre TRANSPORTA autoridad, no la
# CONCEDE— y este script la ejerce entera, porque todo el nucleo es sans-io y no
# hay nada que declarar como muro:
#
#   1. Una orden solo vale con la firma del plano de control, cuya clave no esta
#      en ningun agente. Se prueba con claves hibridas Ed25519 + ML-DSA-65 DE
#      VERDAD, firmando y verificando.
#   2. Reproducir una orden ANTIGUA Y AUTENTICA durante el corte no cuela. Este
#      es el ataque central y no se puede demostrar con una firma falsa: la
#      gracia del ataque es que la firma es buena. Lo para la epoca monotona.
#   3. Levantar un aislamiento, desactivar una regla o degradar la proteccion NO
#      viajan por el enjambre ni con la firma perfecta del plano de control:
#      quedan fuera por CLASE. Es la doctrina de la FASE 23 —solo se anade
#      proteccion, jamas se quita— llevada de los indicadores a las ordenes.
#   4. Una observacion no manda: es evidencia. Hacen falta K pares DISTINTOS.
#      Un equipo comprometido gritando mil veces no mueve nada. Y DISTINTOS por
#      identidad AUTENTICADA —la credencial que el plano de control firmo al
#      matricular—, nunca por el nombre que declare el mensaje (H-04).
#
# Y LO QUE NO ES UN MURO AUNQUE LO PARECIA: el transporte libp2p. No se da por
# bueno porque compile; se levantan DOS NODOS REALES por loopback, con Noise,
# Yamux y gossipsub autenticos, y se comprueban las dos mitades del contrato: que
# una orden legitima cruza y se aplica, y que una orden de un impostor cruza
# igual y el nucleo la rechaza. Esa segunda es la que ensena donde esta la
# seguridad: no en el transporte, que no juzga nada.
#
# Lo unico no ejercido es el descubrimiento por mDNS, que necesita multicast en
# la red local y un contenedor de CI no tiene.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisSwarm: las cotas que impiden que la propia malla sea el ataque"
if cargo test -p aegis-swarm --quiet --lib >/tmp/aegis-swarm-nucleo.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el que inunda se corta ANTES de tocar criptografia, que es lo que"
    echo "    ${VERDE}  ${FIN} impide convertir la malla en un amplificador de CPU; su cuota no"
    echo "    ${VERDE}  ${FIN} silencia a los vecinos honestos; el mismo mensaje por dos caminos se"
    echo "    ${VERDE}  ${FIN} procesa una vez aunque le cambien los saltos; los saltos se agotan; y"
    echo "    ${VERDE}  ${FIN} ni los vistos ni los corroboros ni los reensamblados crecen sin limite)"
else
    echo "    ${ROJO}FALLO${FIN}: las cotas del nucleo no se sostienen"
    sed 's/^/    | /' /tmp/aegis-swarm-nucleo.log | tail -30
    exit 1
fi

echo "==> AegisSwarm: el quorum (una maquina comprometida no mueve a la flota)"
if cargo test -p aegis-swarm --quiet quorum:: >/tmp/aegis-swarm-quorum.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (un solo testigo repitiendo mil veces, o declarando mil nombres,"
    echo "    ${VERDE}  ${FIN} se queda en UNO; dos"
    echo "    ${VERDE}  ${FIN} comprometidos tampoco bastan; los testigos tienen que coincidir en la"
    echo "    ${VERDE}  ${FIN} ventana, porque tres equipos que vieron algo en marzo, junio y octubre"
    echo "    ${VERDE}  ${FIN} no son tres testigos del mismo incidente; y una inundacion de"
    echo "    ${VERDE}  ${FIN} indicadores nuevos NO borra un corroboro a punto de cerrarse)"
else
    echo "    ${ROJO}FALLO${FIN}: el quorum no aguanta"
    sed 's/^/    | /' /tmp/aegis-swarm-quorum.log | tail -30
    exit 1
fi

echo "==> AegisSwarm: el Sybil de H-04 (un nodo no fabrica testigos), con claves reales"
if cargo test -p aegis-swarm --quiet --test sybil >/tmp/aegis-swarm-sybil.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (un testigo es una credencial que firmo el plano de control: un nodo"
    echo "    ${VERDE}  ${FIN} que declara N nombres se queda en UNO y cada suplantacion queda"
    echo "    ${VERDE}  ${FIN} identificada; credenciales acunadas fuera del plano o copiadas de la"
    echo "    ${VERDE}  ${FIN} red no suman; una observacion autentica reinyectada fuera de su"
    echo "    ${VERDE}  ${FIN} ventana no cuenta y rejuvenecerla rompe la firma; y la credencial"
    echo "    ${VERDE}  ${FIN} de un par no firma ordenes)"
else
    echo "    ${ROJO}FALLO${FIN}: el quorum cuenta identidades que no estan autenticadas (H-04)"
    sed 's/^/    | /' /tmp/aegis-swarm-sybil.log | tail -30
    exit 1
fi

echo "==> AegisSwarm: la confianza, con criptografia hibrida de verdad"
if cargo test -p aegis-swarm --quiet --test circuito >/tmp/aegis-swarm-circuito.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (una orden firmada llega y se aplica con el plano de control caido;"
    echo "    ${VERDE}  ${FIN} REPRODUCIR una orden antigua y AUTENTICA no cuela, la corta la epoca;"
    echo "    ${VERDE}  ${FIN} un endpoint comprometido no puede fabricar ordenes; un reenviador no"
    echo "    ${VERDE}  ${FIN} puede cambiar el sujeto en transito; y levantar el aislamiento NO"
    echo "    ${VERDE}  ${FIN} viaja ni con la firma perfecta del plano de control)"
else
    echo "    ${ROJO}FALLO${FIN}: el modelo de confianza no se sostiene con claves reales"
    sed 's/^/    | /' /tmp/aegis-swarm-circuito.log | tail -30
    exit 1
fi

echo "==> AegisSwarm: reglas YARA por trozos sobre un descriptor firmado"
if cargo test -p aegis-swarm --quiet artefacto:: >/tmp/aegis-swarm-artefacto.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (un paquete de reglas viaja troceado y vuelve identico; un trozo"
    echo "    ${VERDE}  ${FIN} envenenado se rechaza AL LLEGAR y se sabe cual repedir; y un trozo que"
    echo "    ${VERDE}  ${FIN} miente su tamano no reserva memoria, porque el tamano lo fija el"
    echo "    ${VERDE}  ${FIN} descriptor FIRMADO y no el trozo)"
else
    echo "    ${ROJO}FALLO${FIN}: el reparto de artefactos no pasa"
    sed 's/^/    | /' /tmp/aegis-swarm-artefacto.log | tail -30
    exit 1
fi

# El transporte vive en un workspace APARTE (swarm-net/), fuera del workspace del
# agente. No es un capricho de organizacion: son 340 crates transitivos y un
# runtime tokio, y el agente corre con privilegios en cada endpoint con un
# presupuesto de memoria por clase de host (48 MiB en reposo en una pasarela) y
# el arbol de dependencias tratado como superficie
# de ataque.
echo "==> AegisSwarm: el transporte libp2p, con DOS NODOS REALES por loopback"
if [ ! -d swarm-net ]; then
    echo "    ${ROJO}FALLO${FIN}: falta swarm-net/"
    exit 1
fi
if (cd swarm-net && cargo test --quiet) >/tmp/aegis-swarm-net.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (Noise, Yamux y gossipsub autenticos: una orden firmada CRUZA la malla"
    echo "    ${VERDE}  ${FIN} y se aplica en el otro extremo; una orden de un impostor cruza igual y"
    echo "    ${VERDE}  ${FIN} el nucleo la rechaza —ahi se ve que la seguridad no esta en el"
    echo "    ${VERDE}  ${FIN} transporte—; publicar sin vecinos no rompe el nodo, y la caida de un"
    echo "    ${VERDE}  ${FIN} vecino no tumba al que queda)"
    echo "    ${GRIS}NO ejercido: el descubrimiento por mDNS, que necesita multicast en la red${FIN}"
    echo "    ${GRIS}local y un contenedor de CI no tiene. Los vecinos se marcan por direccion.${FIN}"
    DEPS=$(grep -c '^\[\[package\]\]' swarm-net/Cargo.lock 2>/dev/null || echo '?')
    echo "    ${GRIS}Ese arbol son ${DEPS} paquetes y vive FUERA del agente, a proposito.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: el transporte libp2p no pasa"
    sed 's/^/    | /' /tmp/aegis-swarm-net.log | tail -30
    exit 1
fi

# Y la propiedad que justifica la separacion, comprobada y no prometida.
echo "==> AegisSwarm: el nucleo NO arrastra libp2p al agente"
if cargo tree -p aegis-swarm --edges normal 2>/dev/null | grep -qiE 'libp2p|tokio'; then
    echo "    ${ROJO}FALLO${FIN}: el nucleo del enjambre arrastra libp2p o tokio al agente."
    echo "    ${ROJO}     ${FIN} Eso mete cientos de crates que analizan entrada hostil de red en un"
    echo "    ${ROJO}     ${FIN} proceso privilegiado que corre en cada endpoint, y revienta el"
    echo "    ${ROJO}     ${FIN} presupuesto de memoria por clase de host."
    cargo tree -p aegis-swarm --edges normal 2>/dev/null | grep -iE 'libp2p|tokio' | head -5
    exit 1
fi
echo "    ${VERDE}OK${FIN} (el nucleo depende solo de aegis-sync, aegis-update, sha2 y thiserror;"
echo "    ${VERDE}  ${FIN} ni libp2p ni tokio entran en el binario del agente)"
exit 0
