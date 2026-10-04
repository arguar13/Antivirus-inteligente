#!/usr/bin/env bash
#
# Verificacion de AegisAttest (atestacion continua, FASE 105).
#
# CONTRA QUIEN COMPITE: Keylime y tpm2-tools. Lo distintivo, y lo que se prueba
# aqui como logica pura:
#  - POLITICA DE PCR COMO TIPO: una contradiccion no llega a existir (se rechaza al
#    construir), en vez de desincronizarse en un fichero de texto.
#  - IMA UNIDO A LA PROCEDENCIA: una medida que ningun paquete (FASE 81) ni la
#    linea base (FASE 104) avala es SinProcedencia. Keylime mide; esto responde.
#  - REVOCACION QUE HACE ALGO: baja autoridad en la malla y tope de confianza en el
#    arbitro; y la revocacion masiva la corta la degradacion pegajosa (FASE 71).
#  - UNA SOLA CADENA de linaje firmware->arranque->kernel->agente->proceso, con un
#    hueco detectado como eslabon roto.
#  - MALLA: un par no acepta autoridad de un nodo no atestado.
#
# LA FRONTERA: emitir el quote y sellar/des-sellar de verdad hablan con el chip por
# /dev/tpmrm0. Esa fontaneria vive tras la feature `tpm-hardware` y NO se compila
# aqui; donde no hay chip, se declara swtpm. Aqui se prueba el lado que VERIFICA y
# DECIDE, que es Rust portable, con firmas reales.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisAttest: politica como tipo, IMA con procedencia, revocacion, cadena, malla"
if cargo test -p aegis-attest >/tmp/aegis-attest.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (una politica de PCR no puede contradecirse; una medida IMA sin"
    echo "    ${VERDE}  ${FIN} procedencia se ve; una atestacion fallida baja autoridad y confianza,"
    echo "    ${VERDE}  ${FIN} y revocar media flota lo corta el freno pegajoso; un hueco en la cadena"
    echo "    ${VERDE}  ${FIN} de linaje es un eslabon roto; y un par no obedece a un nodo no atestado)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-attest.log | tail -30; exit 1
fi

echo "==> AegisAttest: la fontaneria del chip TPM esta GATED (no se compila sin hardware)"
# La emision del quote y el acceso a /dev/tpmrm0 viven en emisor.rs, tras la
# feature tpm-hardware. Se comprueba que el modulo esta gated: el build por defecto
# —el de produccion en este entorno— no abre el chip.
if grep -B1 'pub mod emisor;' crates/aegis-attest/src/lib.rs | grep >/dev/null 'feature = "tpm-hardware"'; then
    echo "    ${VERDE}OK${FIN} (emisor esta tras la feature tpm-hardware: la parte que VERIFICA es"
    echo "    ${VERDE}  ${FIN} Rust portable y se prueba con firmas reales; la que habla con el chip"
    echo "    ${VERDE}  ${FIN} se declara y no se compila donde no hay TPM, en vez de fingir que si)"
else
    echo "    ${ROJO}FALLO${FIN}: el modulo emisor no esta gated tras tpm-hardware."; exit 1
fi
exit 0
