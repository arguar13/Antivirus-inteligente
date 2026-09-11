#!/usr/bin/env bash
#
# Verificacion de AegisCloudNative (deteccion de escape de contenedor, FASE 62).
# Informa SIEMPRE de que se pudo ejercer y que no, como el resto de fases con muro
# de kernel.
#
# El NUCLEO —lo que puede estar MAL de forma peligrosa— se prueba de verdad en
# "Rust · tests" (cargo test), con secuencias reales de escape y cero mocks: la
# escritura de release_agent/core_pattern/modprobe, el montaje del disco del host,
# el setns a un namespace del host, la carga de eBPF desde un contenedor y la
# secuencia unshare(CLONE_NEWUSER)+mount; y los casos que NO son escape (las
# mismas syscalls en el host).
#
# Aqui se re-ejercita ese nucleo y se DECLARA el muro: enganchar esas syscalls en
# vivo es un programa eBPF en el kernel, que necesita BTF, privilegios y el
# bytecode cargado (la via del agente). No se finge.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisCloudNative: el decisor de escape de contenedor se prueba con secuencias reales"
if cargo test -p aegis-cloudnative --quiet deteccion:: >/tmp/aegis-cloudnative.log 2>&1 \
   && cargo test -p aegis-cloudnative --quiet eventos:: >>/tmp/aegis-cloudnative.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (release_agent/core_pattern, montaje del host, setns al host, bpf en contenedor y userns+mount; y lo que NO es escape)"
else
    echo "    ${ROJO}FALLO${FIN}: el decisor de AegisCloudNative no pasa"
    sed 's/^/    | /' /tmp/aegis-cloudnative.log | tail -30
    exit 1
fi

echo "==> AegisCloudNative: enganche eBPF de syscalls (setns/unshare/capset/bpf/mount) en vivo"
echo "    ${GRIS}NO ejercido aqui: el enganche en vivo es un programa eBPF en el kernel, que necesita${FIN}"
echo "    ${GRIS}BTF, privilegios y el bytecode cargado (la via de aegis-agent). El CONTRATO del evento${FIN}"
echo "    ${GRIS}(EventoBpf, con su ABI verificada en compilacion) y la DECISION SI se prueban arriba.${FIN}"
# Pista honesta de si esta maquina siquiera expone BTF (condicion necesaria del enganche).
if [ -r /sys/kernel/btf/vmlinux ]; then
    echo "    ${GRIS}BTF del kernel presente (/sys/kernel/btf/vmlinux): el enganche PODRIA cargarse con privilegios.${FIN}"
else
    echo "    ${GRIS}sin BTF del kernel accesible aqui: el enganche eBPF no podria cargarse en este runner.${FIN}"
fi
exit 0
