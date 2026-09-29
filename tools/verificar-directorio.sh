#!/usr/bin/env bash
#
# Verificacion de AegisDirectory (el grafo completo del directorio, FASE 95).
#
# QUE MODELA, Y CONTRA QUIEN COMPITE: es el modelo de exposicion de identidad al
# nivel de BloodHound/Adalanche —pertenencia anidada, ACL del ntSecurityDescriptor,
# delegacion, derechos de ejecucion, GPO, confianzas y plantillas de certificado—
# MAS dos cosas que BloodHound no tiene: la CADUCIDAD de la sesion en cada arista y
# el ALCANCE POR RED. Se lee en solo lectura y se entrega como inventario de
# exposiciones con su remediacion.
#
# EL NUCLEO —parsear el ntSecurityDescriptor byte a byte, resolver los grupos
# anidados con ciclos, derivar las aristas y las exposiciones, y proyectar el grafo
# a la prediccion respetando la vigencia de las sesiones— es logica pura y se
# prueba entera, sin red, con SID y descriptores de seguridad binarios REALES,
# igual que el nucleo Kerberos se prueba con tickets DER reales.
#
# LO QUE ES UN MURO: la captura EN VIVO por LDAP necesita un Active Directory real
# al que ligarse. Se declara, y se ejerce si hay un directorio local; si no lo hay,
# se dice —no se finge—. El lector en vivo COMPILA siempre, para que no se pudra.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisDirectory: el modelo del directorio y sus exposiciones (nucleo puro)"
if (cd server && cargo test -q -p aegis-itdr directorio::) >/tmp/aegis-directorio.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (SID y descriptor de seguridad NT parseados byte a byte; grupos"
    echo "    ${VERDE}  ${FIN} anidados con ciclos resueltos; ACL peligrosas de raso a privilegiado;"
    echo "    ${VERDE}  ${FIN} delegacion sin restricciones / restringida / basada en recursos;"
    echo "    ${VERDE}  ${FIN} plantillas de certificado ESC; exposiciones con remediacion y"
    echo "    ${VERDE}  ${FIN} tri-estado —lo que no se pudo mirar es un hueco, no un vacio—)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-directorio.log | tail -30
    exit 1
fi

echo "==> AegisDirectory: el grafo completo NO sale del plano de control"
if (cd server && cargo test -q -p aegis-itdr --test autoataque_directorio && \
    cargo test -q -p aegis-itdr --doc) >/tmp/aegis-directorio-salida.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el grafo es el mapa que un atacante querria; no sale por ningun"
    echo "    ${VERDE}  ${FIN} canal hacia fuera de la organizacion, el enjambre no lo transporta,"
    echo "    ${VERDE}  ${FIN} y armar el documento sin pasar por el juez de difusion NO COMPILA)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-directorio-salida.log | tail -30
    exit 1
fi

echo "==> AegisDirectory: el puente a la prediccion y la caducidad de la sesion"
if (cd server && cargo test -q -p aegis-predict directorio::) >/tmp/aegis-directorio-puente.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (la MISMA consulta, antes y despues de caducar una sesion, da un"
    echo "    ${VERDE}  ${FIN} camino distinto —lo que BloodHound no puede—; y los cinco frenos de"
    echo "    ${VERDE}  ${FIN} la contencion siguen funcionando sobre el grafo enriquecido)"
else
    echo "    ${ROJO}FALLO${FIN}"
    sed 's/^/    | /' /tmp/aegis-directorio-puente.log | tail -30
    exit 1
fi

echo "==> AegisDirectory: el lector LDAP en vivo compila y pasa clippy"
# Clippy y no solo `build`: el codigo tras una caracteristica opcional no lo ve
# el clippy de la tanda general, y aqui se acumulo un aviso sin que nadie lo
# viera hasta subir ldap3 (FASE 0 del MP-15).
if (cd server && cargo clippy -q -p aegis-itdr --features live-ldap --all-targets -- -D warnings) \
    >/tmp/aegis-directorio-live.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el colector de solo lectura sobre ldap3 compila con su cadena TLS)"
else
    echo "    ${ROJO}FALLO${FIN}: el lector en vivo no compila"
    sed 's/^/    | /' /tmp/aegis-directorio-live.log | tail -30
    exit 1
fi

echo "==> AegisDirectory: captura en vivo contra un directorio real"
# Se ejerce si hay un directorio al que ligarse (AEGIS_AD_URL), como Samba AD en
# 127.0.0.1. Si no lo hay, se DECLARA el muro —no se finge un directorio—.
if [ -n "${AEGIS_AD_URL:-}" ] && [ -n "${AEGIS_AD_BASE:-}" ]; then
    if (cd server && cargo run -q -p aegis-itdr --features live-ldap --example leer_directorio) \
        >/tmp/aegis-directorio-vivo.log 2>&1; then
        echo "    ${VERDE}OK${FIN}: $(grep -m1 '^OK:' /tmp/aegis-directorio-vivo.log)"
    else
        echo "    ${ROJO}FALLO${FIN}: no se pudo leer el directorio real declarado"
        sed 's/^/    | /' /tmp/aegis-directorio-vivo.log | tail -20
        exit 1
    fi
else
    echo "    ${GRIS}sin Active Directory / LDAP aqui (AEGIS_AD_URL no fijado): captura en vivo NO ejercida.${FIN}"
    echo "    ${GRIS}El modelo que DECIDE (parseo del descriptor, grupos anidados, exposiciones,${FIN}"
    echo "    ${GRIS}proyeccion a la prediccion) SI se prueba arriba, sin red y con estructuras reales.${FIN}"
fi
exit 0
