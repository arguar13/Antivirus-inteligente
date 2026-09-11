#!/usr/bin/env bash
#
# Verificacion de la resiliencia empresarial (FASE 60): los contratos de ABI de
# ELAM/PPL y el guardian de detencion con OTP criptografico. Informa SIEMPRE de
# que se pudo ejercer y que no, como el resto de fases con muro fisico.
#
# El NUCLEO —lo que puede estar MAL de forma peligrosa— se prueba de verdad en
# "Rust · tests" (cargo test), con firmas hibridas REALES y cero mocks:
#   - el guardian de detencion: traducir una senal del SO (SIGTERM, control del
#     SCM, peticion de desinstalar) a su operacion protegida, verificar y CONSUMIR
#     el OTP del Control Plane (firma Ed25519+ML-DSA-65, atado a host/operacion/
#     ventana, anti-replay) y decidir permitir/denegar;
#   - los contratos de ABI de Windows (BDCB_* de ELAM y el byte PS_PROTECTION de
#     PPL): tamano, offsets y codigos REALES del WDK, verificados EN COMPILACION.
#
# Aqui se re-ejercita ese nucleo y se DECLARA el muro: la puesta EN VIVO de la
# autodefensa necesita cosas que este runner no tiene y que NO se fingen.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> Resiliencia: el nucleo (guardian de detencion + ABI ELAM/PPL) se prueba con firmas reales"
if cargo test -p aegis-selfdefense --quiet resiliencia:: >/tmp/aegis-resiliencia.log 2>&1 \
   && cargo test -p aegis-selfdefense --quiet abi:: >>/tmp/aegis-resiliencia.log 2>&1 \
   && cargo test -p aegis-selfdefense --quiet elam:: >>/tmp/aegis-resiliencia.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (rechazo de detencion sin OTP, autorizacion del dueno con OTP, y ABI del WDK verificada en compilacion)"
else
    echo "    ${ROJO}FALLO${FIN}: el nucleo de la resiliencia no pasa"
    sed 's/^/    | /' /tmp/aegis-resiliencia.log | tail -30
    exit 1
fi

echo "==> Resiliencia: la puesta EN VIVO de la autodefensa (muro) en esta maquina"
so="$(uname -s 2>/dev/null || echo desconocido)"
echo "    ${GRIS}sistema operativo del runner: ${so}${FIN}"
echo "    ${GRIS}NO ejercido aqui (necesita Windows + WDK + certificado AM firmado por Microsoft):${FIN}"
echo "    ${GRIS}  - registrar el callback ELAM en el arranque (IoRegisterBootDriverCallback);${FIN}"
echo "    ${GRIS}  - que el kernel conceda PPL-Antimalware (PS_PROTECTION=0x31) al proceso;${FIN}"
echo "    ${GRIS}  - imponer el rechazo de un SIGKILL/SIGSTOP, que NINGUN proceso de usuario${FIN}"
echo "    ${GRIS}    puede interceptar: eso solo lo hace el kernel (PPL), y el guardian lo DECLARA${FIN}"
echo "    ${GRIS}    en cada resultado (interceptable_en_usuario), nunca lo finge.${FIN}"
echo "    ${VERDE}La DECISION (permitir/denegar, verificacion del OTP, ABI) SI se prueba arriba.${FIN}"
exit 0
