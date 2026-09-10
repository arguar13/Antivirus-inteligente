#!/usr/bin/env bash
#
# Levanta un corredor de Apache Kafka REAL de un solo nodo (KRaft, sin
# ZooKeeper) para la verificacion de extremo a extremo del firehose (FASE 46).
#
# POR QUE ESTO Y NO TESTCONTAINERS
# --------------------------------
# La primera version de este proyecto dejo la verificacion de Kafka como un
# hueco documentado porque el entorno no tenia corredor. La forma "de libro" de
# cerrarlo es un contenedor Docker via testcontainers. Pero este contenedor de
# integracion no tiene demonio de Docker, asi que testcontainers seria un hueco
# distinto con el mismo resultado: la verificacion no correria.
#
# Lo que SI hay es una JVM y salida hacia archive.apache.org. Kafka en modo
# KRaft es un unico proceso Java: se puede levantar aqui mismo, sin Docker y sin
# fingir nada. Es un corredor de Apache Kafka de verdad, con su log replicado y
# su protocolo real. En un runner que SI tenga Docker, este script se puede
# sustituir por testcontainers sin tocar las pruebas; la interfaz es la variable
# AEGIS_KAFKA.
#
# Uso:
#   eval "$(tools/kafka-broker.sh up)"   # exporta AEGIS_KAFKA=host:puerto
#   ...                                   # correr pruebas
#   tools/kafka-broker.sh down
#
# `up` es idempotente: si ya hay un corredor de este script vivo, reimprime su
# direccion en vez de arrancar otro.
set -uo pipefail

VER="${AEGIS_KAFKA_VER:-3.9.0}"
SCALA="2.13"
CACHE="${AEGIS_KAFKA_CACHE:-$HOME/.cache/aegis/kafka}"
DIR="$CACHE/kafka_${SCALA}-${VER}"
TGZ="$CACHE/kafka_${SCALA}-${VER}.tgz"
URL="https://archive.apache.org/dist/kafka/${VER}/kafka_${SCALA}-${VER}.tgz"
RUN="${AEGIS_KAFKA_RUN:-$CACHE/run}"        # log.dirs + pid + puerto, efimero
ESTADO="$RUN/broker.env"

log() { printf '%s\n' "$*" >&2; }

# Un puerto libre elegido por el kernel: se abre un socket, se lee el puerto y
# se cierra. Hay una ventana de carrera minima antes de que Kafka lo tome; para
# una unica maquina de CI es despreciable.
puerto_libre() {
    python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
}

asegurar_release() {
    [ -x "$DIR/bin/kafka-server-start.sh" ] && return 0
    mkdir -p "$CACHE"
    if [ ! -s "$TGZ" ]; then
        log "==> descargando Apache Kafka ${VER} real (archive.apache.org)"
        if ! timeout 300 curl -sSL --retry 3 -o "$TGZ" "$URL"; then
            log "    no se pudo descargar el corredor (sin salida a archive.apache.org)"
            return 1
        fi
    fi
    # Es un gzip de verdad? (evita extraer una pagina de error 4xx guardada)
    if [ "$(head -c2 "$TGZ" | od -An -tx1 | tr -d ' ')" != "1f8b" ]; then
        log "    el fichero descargado no es un .tgz valido"; rm -f "$TGZ"; return 1
    fi
    tar -xzf "$TGZ" -C "$CACHE"
}

up() {
    command -v java >/dev/null 2>&1 || { log "SIN-JAVA"; return 3; }
    asegurar_release || return 3

    if [ -f "$ESTADO" ]; then
        # shellcheck disable=SC1090
        . "$ESTADO"
        if kill -0 "${KAFKA_PID:-0}" 2>/dev/null; then
            echo "export AEGIS_KAFKA=$AEGIS_KAFKA"
            return 0
        fi
    fi

    rm -rf "$RUN"; mkdir -p "$RUN"
    local pb pc logdir props
    pb="$(puerto_libre)"; pc="$(puerto_libre)"
    logdir="$RUN/logs"; mkdir -p "$logdir"
    props="$RUN/server.properties"

    # Config KRaft de un solo nodo: el mismo proceso es broker y controlador.
    cat > "$props" <<PROP
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:${pc}
listeners=PLAINTEXT://127.0.0.1:${pb},CONTROLLER://127.0.0.1:${pc}
inter.broker.listener.name=PLAINTEXT
advertised.listeners=PLAINTEXT://127.0.0.1:${pb}
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
log.dirs=${logdir}
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
auto.create.topics.enable=true
PROP

    local cid
    cid="$("$DIR/bin/kafka-storage.sh" random-uuid)"
    "$DIR/bin/kafka-storage.sh" format -t "$cid" -c "$props" --ignore-formatted >/dev/null 2>&1

    export KAFKA_HEAP_OPTS="${KAFKA_HEAP_OPTS:--Xmx512m -Xms256m}"
    "$DIR/bin/kafka-server-start.sh" "$props" >"$RUN/broker.log" 2>&1 &
    local pid=$!

    # Esperar a que el corredor responda de verdad (no solo a que el puerto
    # este abierto): se le pide la lista de temas hasta que contesta.
    local i ok=""
    for i in $(seq 1 60); do
        if ! kill -0 "$pid" 2>/dev/null; then
            log "    el corredor murio al arrancar; ultimas lineas:"; tail -5 "$RUN/broker.log" >&2; return 1
        fi
        if "$DIR/bin/kafka-topics.sh" --bootstrap-server "127.0.0.1:${pb}" --list >/dev/null 2>&1; then
            ok=1; break
        fi
        sleep 1
    done
    [ -n "$ok" ] || { log "    el corredor no quedo listo a tiempo"; tail -5 "$RUN/broker.log" >&2; return 1; }

    cat > "$ESTADO" <<ENV
KAFKA_PID=$pid
AEGIS_KAFKA=127.0.0.1:${pb}
ENV
    log "==> corredor Kafka ${VER} listo en 127.0.0.1:${pb} (pid $pid)"
    echo "export AEGIS_KAFKA=127.0.0.1:${pb}"
}

down() {
    [ -f "$ESTADO" ] || { log "no hay corredor de este script"; pkill -f "$RUN/server.properties" 2>/dev/null; rm -rf "$RUN"; return 0; }
    # shellcheck disable=SC1090
    . "$ESTADO"
    if kill -0 "${KAFKA_PID:-0}" 2>/dev/null; then
        kill "$KAFKA_PID" 2>/dev/null
        local i; for i in $(seq 1 20); do kill -0 "$KAFKA_PID" 2>/dev/null || break; sleep 1; done
        kill -9 "$KAFKA_PID" 2>/dev/null || true
    fi
    # Respaldo robusto: kafka-server-start.sh engendra un `java` hijo cuyo pid no
    # es el que capturamos. Se mata por la ruta UNICA de config de ESTE corredor
    # —no toca ningun otro java de la maquina—.
    pkill -f "$RUN/server.properties" 2>/dev/null || true
    local i; for i in $(seq 1 20); do pgrep -f "$RUN/server.properties" >/dev/null 2>&1 || break; sleep 1; done
    pkill -9 -f "$RUN/server.properties" 2>/dev/null || true
    log "==> corredor detenido"
    rm -rf "$RUN"
}

case "${1:-up}" in
    up) up ;;
    down) down ;;
    *) log "uso: $0 {up|down}"; exit 2 ;;
esac
