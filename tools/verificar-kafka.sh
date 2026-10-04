#!/usr/bin/env bash
#
# Verificacion de EXTREMO A EXTREMO del destino Kafka del firehose (FASE 46),
# contra un corredor de Apache Kafka REAL (FASE 48).
#
# QUE COMPRUEBA Y POR QUE NO LO PUEDEN COMPROBAR LAS OTRAS PRUEBAS
# ---------------------------------------------------------------
# `crates/aegis-firehose/tests/kafka.rs` comprueba, contra la librdkafka real,
# la propiedad cuya rotura seria catastrofica: que un destino inalcanzable NUNCA
# devuelve exito (un exito falso hace que la bomba borre evidencia que no
# llego). Lo que ESO no puede comprobar sin un corredor es lo que pasa cuando el
# corredor SI esta: que el registro llega, que llega UNA sola vez por lote
# confirmado, y que el orden dentro de una particion se conserva —que es lo que
# mantiene una linea de tiempo forense como una linea de tiempo—.
#
# COMO SE CIERRA EL HUECO AQUI (FASE 48)
# --------------------------------------
# En la primera version esto se dejaba OMITIDO porque no habia corredor. Ahora,
# si no se pasa uno externo, este script levanta un Apache Kafka de un solo nodo
# (KRaft) de VERDAD con `tools/kafka-broker.sh` —un proceso Java real, sin Docker
# y sin mocks— corre la verificacion contra el, y lo apaga. Solo se OMITE, con
# aviso ruidoso y sin fingir exito, si de verdad no se puede levantar (sin Java o
# sin salida hacia el archivo de releases).
#
# Uso:
#   ./tools/verificar-kafka.sh                 # levanta un corredor real y verifica
#   AEGIS_KAFKA=host:puerto ./tools/verificar-kafka.sh   # usa uno ya existente
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'

PROPIO=""            # ¿lo levantamos nosotros? -> hay que apagarlo al salir
CORREDORES="${AEGIS_KAFKA:-}"

limpiar() {
    [ -n "$PROPIO" ] && ./tools/kafka-broker.sh down >/dev/null 2>&1 || true
}
trap limpiar EXIT

if [ -z "$CORREDORES" ]; then
    printf '%s==>%s sin AEGIS_KAFKA externo: levantando un corredor Apache Kafka real\n' "$GRIS" "$FIN"
    SALIDA="$(./tools/kafka-broker.sh up 2>/dev/null || true)"
    if printf '%s' "$SALIDA" | grep >/dev/null '^export AEGIS_KAFKA='; then
        eval "$SALIDA"
        CORREDORES="$AEGIS_KAFKA"
        PROPIO=1
    else
        printf '%sOMITIDA%s: no se pudo levantar un corredor (sin Java o sin salida a archive.apache.org).\n' "$GRIS" "$FIN"
        printf '        La verificacion de extremo a extremo del destino Kafka NO se ha ejecutado.\n'
        printf '        En un runner con Docker, exporta AEGIS_KAFKA=host:puerto de un corredor real.\n'
        # Se CUENTA (hallazgos H-10/H-20): antes la tanda salia verde sin haber
        # ejercido el destino Kafka. Sin declarar en tools/config/omisiones.toml,
        # la tanda completa falla al final; y si se exige kafka, falla aqui.
        case ",${AEGIS_EXIGIR:-}," in
            *,todo,*|*,kafka,*|*,red,*)
                printf '%sFALLO%s: AEGIS_EXIGIR exige kafka\n' "$ROJO" "$FIN"
                exit 1
                ;;
        esac
        if [ -n "${AEGIS_OMISIONES:-}" ]; then
            printf 'kafka\ttools/verificar-kafka.sh\t%s\tverificar-kafka\t%s\n' "$LINENO" \
                'no se pudo levantar un corredor de Kafka (sin Java o sin salida a archive.apache.org)' \
                >> "$AEGIS_OMISIONES" || exit 1
        fi
        exit 0
    fi
fi

TEMA="aegis-verificacion-$$-${RANDOM}"
printf '%s==>%s corredor=%s tema=%s\n' "$GRIS" "$FIN" "$CORREDORES" "$TEMA"

export AEGIS_KAFKA_CORREDORES="$CORREDORES"
export AEGIS_KAFKA_TEMA="$TEMA"
# Con corredor, la prueba no puede omitirse: se EXIGE (aegis_prueba, H-10/H-20).
export AEGIS_EXIGIR="${AEGIS_EXIGIR:+$AEGIS_EXIGIR,}kafka"

if cargo test -p aegis-firehose --features kafka --test kafka_extremo -- --nocapture; then
    printf '    %sOK%s  el destino Kafka entrega, conserva el orden y no duplica; el corredor lo acusa\n' "$VERDE" "$FIN"
    exit 0
else
    printf '    %sFALLO%s\n' "$ROJO" "$FIN"
    exit 1
fi
