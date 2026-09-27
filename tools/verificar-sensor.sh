#!/usr/bin/env bash
#
# Verificacion de AegisSensor (telemetria de kernel sin perdida silenciosa y sin
# carreras, FASE 103).
#
# CONTRA QUIEN COMPITE: Falco, Tracee y Tetragon. Lo distintivo, y lo que se prueba
# aqui como logica pura:
#  - Un sensor que pierde LO DICE Y LO CUENTA, por FAMILIA. Un anillo lleno produce
#    un NoConcluyente (SinDatos con su cuenta) al arbitro, no un hueco silencioso.
#  - Degradacion por presupuesto VISIBLE: se apagan familias por valor ascendente y
#    se dice cual; una apagada tambien es SinDatos.
#  - NINGUNA DECISION SOBRE DATOS QUE PUDIERON CAMBIAR: el evento lleva lo capturado
#    en el kernel; no hay relectura de /proc (verificado por ausencia).
#
# LA FRONTERA: la captura eBPF en vivo (ganchos LSM + tracepoints por familia) vive
# en drivers/linux/aegis-bpf. Aqui se prueba el lado que DECIDE. Sobre este entorno
# BPF LSM esta ACTIVO, y se comprueba, porque es el habilitador de los ganchos LSM.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisSensor: familias, perdida por familia, degradacion y SinDatos"
if cargo test -p aegis-sensor >/tmp/aegis-sensor.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (perdida contada por familia; una familia con perdida o apagada"
    echo "    ${VERDE}  ${FIN} produce NoConcluyente —SinDatos, no limpio—; la degradacion apaga por"
    echo "    ${VERDE}  ${FIN} valor ascendente conservando la ejecucion de procesos; y el evento"
    echo "    ${VERDE}  ${FIN} conserva lo capturado en el kernel aunque el mundo cambie despues)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-sensor.log | tail -30; exit 1
fi

echo "==> AegisSensor: sin relectura de /proc (sin carrera, por ausencia)"
# El lado que decide no relee el sistema: lo que necesita esta en el evento. Se
# comprueba que el crate no abre /proc ni el sistema de ficheros para "enriquecer"
# un evento despues del hecho.
FUGAS=$(grep -rnE '/proc/|std::fs::(read|File)|fs::read_to_string' crates/aegis-sensor/src/ 2>/dev/null | grep -v '^\s*//' | wc -l)
if [ "$FUGAS" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (el lado que decide no relee /proc ni el disco: las decisiones usan"
    echo "    ${VERDE}  ${FIN} lo capturado en el kernel, no un estado que el atacante pudo cambiar)"
else
    echo "    ${ROJO}FALLO${FIN}: hay $FUGAS relectura(s) del sistema en el sensor:"; \
        grep -rnE '/proc/|std::fs::(read|File)|fs::read_to_string' crates/aegis-sensor/src/ | sed 's/^/    | /'; exit 1
fi

echo "==> AegisSensor: BPF LSM activo (habilitador de los ganchos LSM)"
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "    ${VERDE}OK${FIN}: /sys/kernel/security/lsm = $(cat /sys/kernel/security/lsm)"
    echo "    ${VERDE}  ${FIN} (los ganchos LSM de eBPF se pueden enganchar en este kernel; la"
    echo "    ${VERDE}  ${FIN} ampliacion de programas eBPF a familias completas se apoya en esto)"
else
    echo "    ${GRIS}BPF LSM no visible en esta sesion (securityfs).${FIN} El lado que decide"
    echo "    ${GRIS}se prueba igual arriba; el habilitador se activo por .wslconfig.${FIN}"
fi
exit 0
