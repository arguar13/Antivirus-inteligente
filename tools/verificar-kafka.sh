#!/usr/bin/env bash
#
# Verificacion de EXTREMO A EXTREMO del destino Kafka del firehose (FASE 46).
#
# POR QUE ESTE SCRIPT EXISTE Y NO ES UNA PRUEBA MAS
# ------------------------------------------------
# Las pruebas de `crates/aegis-firehose/tests/kafka.rs` comprueban la propiedad
# cuya rotura seria catastrofica —que un destino inalcanzable nunca devuelve
# exito— contra la biblioteca y el sistema reales. Lo que NO pueden comprobar
# sin un corredor es lo que ocurre cuando el corredor SI esta: que el registro
# llega, que llega una sola vez por lote confirmado, y que el orden se conserva.
#
# El entorno de desarrollo en el que se escribio esta fase no tiene salida hacia
# los archivos de Apache y no hay corredor accesible. En vez de dar la
# verificacion por hecha, se deja escrita y ejecutable: en cuanto haya un
# corredor, esto la ejecuta.
#
# Uso:
#   AEGIS_KAFKA=localhost:9092 ./tools/verificar-kafka.sh
#
# Levantar un corredor de un solo nodo (KRaft, sin ZooKeeper):
#   KAFKA_CLUSTER_ID="$(bin/kafka-storage.sh random-uuid)"
#   bin/kafka-storage.sh format -t "$KAFKA_CLUSTER_ID" -c config/kraft/server.properties
#   bin/kafka-server-start.sh config/kraft/server.properties
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'

CORREDORES="${AEGIS_KAFKA:-}"
if [ -z "$CORREDORES" ]; then
    printf '%sOMITIDA%s: exporta AEGIS_KAFKA=host:puerto con un corredor accesible.\n' \
        "$GRIS" "$FIN"
    printf '        La verificacion de extremo a extremo del destino Kafka NO se ha ejecutado.\n'
    exit 0
fi

TEMA="aegis-verificacion-$(date +%s)"
printf '%s==>%s corredor=%s tema=%s\n' "$GRIS" "$FIN" "$CORREDORES" "$TEMA"

export AEGIS_KAFKA_CORREDORES="$CORREDORES"
export AEGIS_KAFKA_TEMA="$TEMA"

if cargo test -p aegis-firehose --features kafka --test kafka_extremo -- --nocapture; then
    printf '    %sOK%s  el destino Kafka entrega y el corredor lo acusa\n' "$VERDE" "$FIN"
    exit 0
else
    printf '    %sFALLO%s\n' "$ROJO" "$FIN"
    exit 1
fi
