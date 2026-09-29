#!/usr/bin/env bash
#
# Verificacion de AegisIntegrity (integridad sin carrera y por significado, FASE
# 104). Sustituye a aegis-fim.
#
# CONTRA QUIEN COMPITE: Wazuh FIM, AIDE, Tripwire (ficheros) y OpenEDR (agente).
# Lo distintivo, y lo que se prueba aqui como logica pura:
#  - SIN CARRERA Y CON AUTOR: el cambio nace del gancho LSM (FASE 103) y lleva
#    quien lo hizo —proceso, credenciales, linaje— capturado en el kernel. No hay
#    relectura de /proc (invariante 9), y se comprueba POR AUSENCIA.
#  - POR SIGNIFICADO: los ficheros de configuracion se parsean; un comentario no
#    es una alerta, una puerta trasera si.
#  - LINEA BASE FIRMADA Y SELLADA CONTRA EL TPM: root puede reescribirla pero no
#    volver a firmarla. Es el fallo clasico de AIDE/Tripwire, cerrado.
#  - VIGILANCIA MUTUA A TRES BANDAS y clasificacion de la manipulacion, con el
#    camino de desinstalacion autorizado INTACTO (invariante 10).
#
# LA FRONTERA: el programa LSM-BPF que se engancha en security_file_open/
# path_rename/... y lee task->cred para el autor es trabajo nuevo en
# drivers/linux/aegis-bpf (hoy solo hay tracepoints sys_enter_*, que solo VEN y
# tienen carrera). BPF LSM esta ACTIVO en este entorno (FASE 103), asi que ese
# gancho se puede enganchar; aqui se prueba el lado que DECIDE, race-free por
# construccion.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisIntegrity: autor sin carrera, semantica, linea base firmada+sellada"
if cargo test -p aegis-integridad -p aegis-selfdefense >/tmp/aegis-integridad.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el cambio lleva su autor del kernel; un comentario no es alerta y"
    echo "    ${VERDE}  ${FIN} una puerta trasera si; root reescribe la linea base y la firma no"
    echo "    ${VERDE}  ${FIN} verifica; la vigilancia mutua a tres bandas avisa al matar a uno; y"
    echo "    ${VERDE}  ${FIN} la desinstalacion autorizada del dueno sigue funcionando tras todo)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-integridad.log | tail -30; exit 1
fi

echo "==> AegisIntegrity: sin relectura de /proc ni del disco (sin carrera, por ausencia)"
# El lado que decide no relee el sistema: el autor y el objeto vienen del evento
# del kernel (FASE 103). Se comprueba que el crate no abre /proc ni el sistema de
# ficheros para "enriquecer" un cambio despues del hecho (invariante 9).
FUGAS=$(grep -rnE '/proc/|std::fs::(read|File)|fs::read_to_string|std::fs::metadata' crates/aegis-integridad/src/ 2>/dev/null | grep -v '^\s*//' | wc -l)
if [ "$FUGAS" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (cero relecturas del sistema: las decisiones usan lo capturado en el"
    echo "    ${VERDE}  ${FIN} gancho LSM, no un estado que el atacante pudo cambiar tras la syscall)"
else
    echo "    ${ROJO}FALLO${FIN}: hay $FUGAS relectura(s) del sistema en aegis-integridad:"; \
        grep -rnE '/proc/|std::fs::(read|File)|fs::read_to_string|std::fs::metadata' crates/aegis-integridad/src/ | sed 's/^/    | /'; exit 1
fi

echo "==> AegisIntegrity: aegis-fim SUSTITUIDO (ausente del arbol y sin uso)"
# La prueba de que la fase sustituyo de verdad: aegis-fim desaparece del arbol del
# agente, y nadie lo importa.
USOS_FIM=$( { grep -rn "aegis_fim" --include=*.rs crates/ server/ 2>/dev/null; grep -rn '^aegis-fim' --include=Cargo.toml . 2>/dev/null; } | wc -l)
if [ ! -d crates/aegis-fim ] && [ "$USOS_FIM" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (crates/aegis-fim no existe y ningun crate lo declara ni lo usa:"
    echo "    ${VERDE}  ${FIN} aegis-integridad es el sucesor, no un anadido al lado)"
else
    echo "    ${ROJO}FALLO${FIN}: aegis-fim sigue presente o en uso ($USOS_FIM referencia(s))."; exit 1
fi
exit 0
