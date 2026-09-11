#!/usr/bin/env bash
#
# Verificacion de la introspeccion de Ring -1 (VMI + EPT, FASE 54). Informa
# SIEMPRE de que se pudo ejercer y que no, como el resto de fases con muro fisico.
#
# El NUCLEO —el diseno de las estructuras EPT (tamano/ABI verificados en
# compilacion), el recorrido de las cuatro tablas, la clasificacion de una EPT
# violation (ejecucion oculta, parcheo de kernel), el parser de task_struct/
# EPROCESS desde memoria fisica y la deteccion de procesos ocultos por vista
# cruzada— se prueba de verdad en "Rust · tests" (cargo test), con memoria y
# estructuras reales. Aqui, ademas, se comprueba que la FONTANERIA en vivo sobre
# KVM COMPILA (feature kvm) y se declara si esta maquina podria arrancar el
# hipervisor de verdad.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> VMI Ring -1: la fontaneria en vivo sobre KVM COMPILA (feature kvm)"
if cargo check -p aegis-vmi --features kvm >/tmp/aegis-vmi.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (estructuras EPT y KVM con ABI verificada en compilacion)"
else
    echo "    ${ROJO}FALLO${FIN}: la fontaneria gated no compila"
    sed 's/^/    | /' /tmp/aegis-vmi.log | tail -20
    exit 1
fi

echo "==> VMI Ring -1: soporte de virtualizacion (VT-x/AMD-V y /dev/kvm) en esta maquina"
vmx=0
grep -qwE 'vmx|svm' /proc/cpuinfo 2>/dev/null && vmx=1
if [ "$vmx" -eq 1 ] && [ -e /dev/kvm ]; then
    echo "    ${VERDE}virtualizacion PRESENTE${FIN} (/dev/kvm existe): el hipervisor PODRIA arrancar aqui con privilegios."
else
    echo "    ${GRIS}sin VT-x/AMD-V accesible o sin /dev/kvm${FIN}: ejecucion del hipervisor NO ejercida aqui."
    echo "    ${GRIS}El nucleo (EPT, clasificacion, parser del kernel, deteccion de ocultos) SI se prueba en 'Rust · tests'.${FIN}"
fi
exit 0
