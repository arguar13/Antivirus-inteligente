#!/usr/bin/env bash
#
# Verificacion de AegisInline (reensamblado y corte resistentes a evasion, FASE
# 106).
#
# CONTRA QUIEN COMPITE: Suricata, Snort, Zeek y CrowdSec. Lo distintivo, y lo que se
# prueba aqui como logica pura:
#  - PERFIL DE REENSAMBLADO POR DESTINO REAL: Suricata ADIVINA el sistema del
#    destino; AegisCore lo SABE (el endpoint es suyo) y elige el perfil con ese
#    dato. La misma evasion se reensambla distinto segun el destino, y AegisCore ve
#    lo que ve el destino.
#  - LA AMBIGUEDAD SE RESUELVE PREGUNTANDO AL ENDPOINT: cuando dos interpretaciones
#    son posibles —lo que busca el evasor—, el destino DICE que entrego. Nadie sin
#    agente puede hacer esto.
#  - LATENCIA ANADIDA MEDIDA Y PUBLICADA (p50/p99), no la media, que esconde la
#    cola. Un IPS que no publica su latencia esconde su coste.
#  - EL REENSAMBLADO NO SE AGOTA: cotas duras; millones de segmentos a medio abrir
#    se rechazan.
#
# LA FRONTERA: la diseccion semantica del flujo (HTTP, DNS, TLS...) vive en
# aegis-wire (FASE 70) y NO se duplica; aqui esta la capa de PERFIL (target-based)
# que cierra el margen de evasion que aegis-wire dejaba (politica global, sin perfil
# por destino ni desambiguacion por el endpoint).
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisInline: perfil por destino, desambiguacion por endpoint, cotas"
if cargo test -p aegis-net perfil_reensamblado >/tmp/aegis-inline-net.log 2>&1 \
    && cargo test -p aegis-net --test autoataque >>/tmp/aegis-inline-net.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (la misma evasion se reensambla distinto segun el OS del destino;"
    echo "    ${VERDE}  ${FIN} un flujo ambiguo se resuelve preguntando al endpoint por lo que"
    echo "    ${VERDE}  ${FIN} entrego; y el reensamblado no se agota: cotas duras, sin OOM)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-inline-net.log | tail -30; exit 1
fi

echo "==> AegisInline: latencia anadida del corte medida como p50/p99 (no la media)"
if cargo test -p aegis-ips latencia >/tmp/aegis-inline-ips.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (la latencia se publica como percentiles: el p99 —la cola que"
    echo "    ${VERDE}  ${FIN} duele— no lo esconde la media; el calculo es determinista sobre las"
    echo "    ${VERDE}  ${FIN} muestras, no depende del reloj de la maquina)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-inline-ips.log | tail -30; exit 1
fi

echo "==> AegisInline: la diseccion semantica NO se duplica (vive en aegis-wire)"
# La capa de perfil no reimplementa HTTP/DNS/TLS: eso es aegis-wire (FASE 70). Se
# comprueba por ausencia de esos parsers en el modulo de perfil.
DUP=$(grep -rniE 'fn .*(parsear_http|parsear_dns|parsear_tls|http_|dns_)' crates/aegis-net/src/perfil_reensamblado.rs 2>/dev/null | wc -l)
if [ "$DUP" = "0" ]; then
    echo "    ${VERDE}OK${FIN} (el perfil es target-based reassembly puro; la semantica de"
    echo "    ${VERDE}  ${FIN} protocolos se apoya en aegis-wire, no se reescribe al lado)"
else
    echo "    ${ROJO}FALLO${FIN}: el modulo de perfil duplica diseccion semantica ($DUP)."; exit 1
fi
exit 0
