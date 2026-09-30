#!/bin/sh
#
# Se ejecuta DENTRO de cada microVM de la matriz de kernels, como root, lanzado
# por cloud-init. No decide nada: ejecuta lo que dice plan.txt y lo cuenta en
# lineas AEGIS-* que cloud-init deja en el disco de salida (resultado.txt), y
# `cargo xtask kernels ejecutar` lo recoge en el anfitrion y lo juzga.
#
#   AEGIS-MATRIZ|inicio|<kernel>|<arquitectura>
#   AEGIS-MATRIZ|distro|<nombre>
#   AEGIS-CAP|...  AEGIS-DEG|...                  (de aegis-agent --capacidades)
#   AEGIS-MATRIZ|bpf|<objeto>|pasa|falla|no-aplica|<motivo>
#   AEGIS-MATRIZ|prueba|<id>|pasa|falla|<detalle>
#   AEGIS-MEDIDA|<crate>|<nombre>|<valor>|<unidad>
#   AEGIS-LOG|<linea>                              (diagnostico de un fallo)
#   AEGIS-MATRIZ|fin
#
# POSIX sh a proposito: tiene que correr igual en Debian 11 que en Fedora 44.

C="${1:-/mnt/aegis}"
T="$(mktemp -d)"

linea() { printf '%s\n' "$*"; }
volcar() { sed 's/^/AEGIS-LOG|/' "$1" | tail -n "${2:-30}"; }

linea "AEGIS-MATRIZ|inicio|$(uname -r)|$(uname -m)"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    linea "AEGIS-MATRIZ|distro|${PRETTY_NAME:-desconocida}"
fi

# ── 1. Capacidades del kernel ────────────────────────────────────────────────
# Salida 3 = no habria telemetria de kernel; se registra, no se interrumpe: el
# resto de la matriz dice por que. La carga de `kernels btf` no lleva agente.
if [ -x "$C/bin/aegis-agent" ]; then
    "$C/bin/aegis-agent" --capacidades --maquina < /dev/null
    linea "AEGIS-MATRIZ|capacidades|salida=$?"
fi

# ── 2. El agente en vivo ─────────────────────────────────────────────────────
# Engancha las sondas del binario PUBLICADO, genera actividad real de cada
# familia (ejecucion, ficheros, escrituras, renombrados, red, salida de
# procesos) y para con SIGTERM, como lo pararia systemd.
agente_en_vivo() {
    id="$1"
    # Se ejecuta COMO SE INSTALA: binario en /usr/local/bin con su etiqueta
    # restaurada, y como servicio de systemd. Lanzado desde aqui directamente
    # correria en el dominio de cloud-init, que SELinux confina (Rocky, Fedora)
    # y no deja enganchar tracepoints: se estaria probando cloud-init, no el
    # agente tal y como lo arranca una instalacion real.
    install -m 0755 "$C/bin/aegis-agent" /usr/local/bin/aegis-agent
    command -v restorecon > /dev/null 2>&1 && restorecon /usr/local/bin/aegis-agent
    : > "$T/agente.log"
    if command -v systemd-run > /dev/null 2>&1; then
        # La salida va al journal, como en produccion. Un fichero en /tmp no
        # sirve: con SELinux, systemd no puede abrir para el servicio un fichero
        # creado por cloud-init y la unidad muere con 209/STDOUT (Rocky, Fedora).
        systemd-run --quiet --unit=aegis-prueba \
            --property=RemainAfterExit=yes \
            /usr/local/bin/aegis-agent --stats-interval 2
        sleep 1
        P="$(systemctl show -p MainPID --value aegis-prueba)"
    else
        /usr/local/bin/aegis-agent --stats-interval 2 > "$T/agente.log" 2>&1 < /dev/null &
        P=$!
    fi
    sleep 3
    i=0
    while [ "$i" -lt 40 ]; do
        /bin/true
        cat /etc/os-release > /dev/null
        head -c 8192 /dev/urandom > "$T/f$i"
        mv "$T/f$i" "$T/g$i"
        i=$((i + 1))
    done
    # Un intento de conexion TCP (rechazado) basta para cambiar el estado de un
    # socket. Si no hay cliente HTTP en la imagen, la familia de red se queda sin
    # actividad provocada, y el recuento lo refleja.
    if command -v curl > /dev/null 2>&1; then
        curl -s -m 1 http://127.0.0.1:9/ > /dev/null 2>&1
    elif command -v wget > /dev/null 2>&1; then
        wget -q -T 1 -O /dev/null http://127.0.0.1:9/ > /dev/null 2>&1
    fi
    rss="$(awk '/^VmRSS:/ { print $2 }' "/proc/$P/status" 2> /dev/null)"
    sleep 3
    if command -v systemd-run > /dev/null 2>&1; then
        # La parada de systemd: SIGTERM y espera, como en un apagado real.
        systemctl stop aegis-prueba
        rc="$(systemctl show -p ExecMainStatus --value aegis-prueba)"
        journalctl -u aegis-prueba --no-pager -o cat > "$T/agente.log" 2>&1
        systemctl reset-failed aegis-prueba > /dev/null 2>&1
    else
        kill -TERM "$P"
        wait "$P"
        rc=$?
    fi

    emitidos="$(sed -n 's/.*parada limpia\. kernel: emitidos=\([0-9]*\) .*/\1/p' "$T/agente.log")"
    perdidos="$(sed -n 's/.*parada limpia\. kernel: emitidos=[0-9]* perdidos=\([0-9]*\) .*/\1/p' "$T/agente.log")"
    grep "DEGRADADO" "$T/agente.log" | sed 's/^aegis-agent: /AEGIS-LOG|/'

    linea "AEGIS-MEDIDA|aegis-agent|eventos_emitidos|${emitidos:-0}|eventos"
    linea "AEGIS-MEDIDA|aegis-agent|eventos_perdidos|${perdidos:-?}|eventos"
    linea "AEGIS-MEDIDA|aegis-agent|rss_en_vivo|${rss:-?}|KiB"
    # El camino caliente, por kernel: lo que tarda el arbitro entero por evento
    # y cada motor por evaluacion, percentil 99 en nanosegundos, del ultimo
    # informe del agente. Una linea por crate: es lo que la matriz de
    # capacidades lee como su medida.
    linea "AEGIS-MEDIDA|aegis-motor|p99_camino_caliente|$(p99_de "$T/agente.log" 'aegis-agent: arbitro:')|ns"
    linea "AEGIS-MEDIDA|aegis-agent|p99_triaje|$(p99_de "$T/agente.log" 'aegis-agent: motor triaje:')|ns"
    linea "AEGIS-MEDIDA|aegis-behavior|p99_evaluacion|$(p99_de "$T/agente.log" 'aegis-agent: motor conducta:')|ns"
    linea "AEGIS-MEDIDA|aegis-ransom|p99_evaluacion|$(p99_de "$T/agente.log" 'aegis-agent: motor secuestro:')|ns"

    if [ "$rc" -eq 0 ] && [ "${emitidos:-0}" -gt 0 ] && [ "${perdidos:-1}" -eq 0 ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|emitidos=$emitidos perdidos=$perdidos"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|salida=$rc emitidos=${emitidos:-?} perdidos=${perdidos:-?}"
        volcar "$T/agente.log"
    fi
}

# El p99 (ns) de la ultima linea de un informe del agente que empieza por $2.
p99_de() {
    v="$(grep -- "$2" "$1" | tail -n 1 | sed -n 's/.* p99_ns=\([0-9]*\).*/\1/p')"
    printf '%s' "${v:-?}"
}

# Eventos que lleva el arbitro segun el ultimo informe del agente vigilado.
eventos_arbitro() {
    if command -v systemd-run > /dev/null 2>&1; then
        journalctl -u aegis-vigilado --no-pager -o cat 2> /dev/null
    else
        cat "$T/vigilado.log"
    fi | grep 'aegis-agent: arbitro:' | tail -n 1 | sed -n 's/.* eventos=\([0-9]*\) .*/\1/p'
}

# ── El trabajador confinado muere y el agente sigue ──────────────────────────
# El agente PUBLICADO, bajo el watchdog publicado, como en produccion. Se mata a
# su trabajador confinado varias veces —SIGKILL, lo mismo que le pasa cuando un
# parser revienta con un fichero— mientras se ejecutan ELF malformados, y se
# exige: que el watchdog NO reinicie al agente (su latido no se paro), que el
# agente cuente las muertes, y que siga consumiendo eventos DESPUES de la ultima.
trabajador_en_vivo() {
    id="$1"
    for b in aegis-agent aegis-watchdog; do
        install -m 0755 "$C/bin/$b" "/usr/local/bin/$b"
        command -v restorecon > /dev/null 2>&1 && restorecon "/usr/local/bin/$b"
    done
    rm -rf /run/aegiscore
    : > "$T/vigilado.log"
    vigilar="/usr/local/bin/aegis-watchdog --program /usr/local/bin/aegis-agent \
        --arg --stats-interval --arg 2 --heartbeat /run/aegiscore/agent.heartbeat \
        --max-age-ms 15000"
    if command -v systemd-run > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        systemd-run --quiet --unit=aegis-vigilado --property=RemainAfterExit=yes $vigilar
    else
        # shellcheck disable=SC2086
        $vigilar > "$T/vigilado.log" 2>&1 < /dev/null &
    fi

    # Bajo emulacion completa el agente tarda en enganchar sus sondas: se espera
    # a su primer latido, que sale del bucle ya en marcha.
    i=0
    while [ "$i" -lt 300 ] && [ ! -s /run/aegiscore/agent.heartbeat ]; do
        sleep 1
        i=$((i + 1))
    done
    # Los ELF malformados van donde un agente instalado los puede leer: con
    # SELinux en enforcing, lo que cloud-init crea en su /tmp lleva una etiqueta
    # que el dominio del agente no lee, y el analista los daba por ilegibles sin
    # llegar a pedirle nada al trabajador (Rocky 9).
    malos=/usr/local/lib/aegis-prueba
    mkdir -p "$malos"
    muertes=0
    k=0
    while [ "$k" -lt 4 ]; do
        f="$malos/malo$k"
        { printf '\177ELF\002\001\001'; head -c 2048 /dev/urandom; } > "$f"
        chmod +x "$f"
        command -v restorecon > /dev/null 2>&1 && restorecon "$f"
        # El exec falla (no es un ELF valido), pero el evento llega igual y el
        # analista se lo manda al trabajador, que asi se relanza si estaba muerto.
        "$f" > /dev/null 2>&1
        j=0
        w=""
        while [ "$j" -lt 60 ] && [ -z "$w" ]; do
            w="$(pgrep -f -- 'aegis-agent --trabajador' | head -n 1)"
            [ -z "$w" ] && sleep 1
            j=$((j + 1))
        done
        if [ -n "$w" ] && kill -KILL "$w" 2> /dev/null; then
            muertes=$((muertes + 1))
        fi
        sleep 1
        k=$((k + 1))
    done

    # Despues de la ultima muerte, actividad que el agente tiene que ver.
    sleep 3
    antes="$(eventos_arbitro)"
    i=0
    while [ "$i" -lt 40 ]; do
        /bin/true
        i=$((i + 1))
    done
    sleep 5
    despues="$(eventos_arbitro)"

    # Parada autorizada: con la marca, el watchdog para al agente y termina.
    : > /run/aegiscore/agent.shutdown
    sleep 5
    if command -v systemd-run > /dev/null 2>&1; then
        systemctl stop aegis-vigilado
        journalctl -u aegis-vigilado --no-pager -o cat > "$T/vigilado.log" 2>&1
        systemctl reset-failed aegis-vigilado > /dev/null 2>&1
    fi

    rm -rf "$malos"
    reinicios="$(grep -c -- '-> reiniciado' "$T/vigilado.log")"
    ultima="$(grep 'aegis-agent: trabajador:' "$T/vigilado.log" | tail -n 1)"
    contadas="$(printf '%s' "$ultima" | sed -n 's/.* muertes=\([0-9]*\) .*/\1/p')"
    grep -E "DEGRADADO|trabajador confinado" "$T/vigilado.log" | sed 's/^aegis-agent: /AEGIS-LOG|/'

    linea "AEGIS-MEDIDA|aegis-trabajador|muertes_sin_interrupcion|$muertes|muertes"
    linea "AEGIS-MEDIDA|aegis-trabajador|p99_analisis|$(p99_de "$T/vigilado.log" 'aegis-agent: trabajador:')|ns"
    linea "AEGIS-MEDIDA|aegis-watchdog|reinicios_del_agente|$reinicios|reinicios"

    if [ "$muertes" -eq 4 ] && [ "$reinicios" -eq 0 ] && [ "${contadas:-0}" -ge 4 ] \
        && [ -n "$antes" ] && [ -n "$despues" ] && [ "$despues" -ge $((antes + 40)) ] \
        && grep -q 'parada limpia' "$T/vigilado.log"; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|muertes=$muertes reinicios=0 eventos_tras_la_ultima=$((despues - antes))"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|muertes=$muertes contadas=${contadas:-?} reinicios=$reinicios eventos=${antes:-?}->${despues:-?}"
        volcar "$T/vigilado.log" 60
    fi
}

# ── 3. El plan ───────────────────────────────────────────────────────────────
while IFS='|' read -r tipo a b c; do
    case "$tipo" in
    btf)
        # `cargo xtask kernels btf`: el BTF de este kernel, para compilar las
        # sondas de otra arquitectura. Va al disco de salida (montado por
        # cloud-init en /mnt/salida), que el anfitrion lee con debugfs.
        if cp /sys/kernel/btf/vmlinux /mnt/salida/vmlinux.btf; then
            linea "AEGIS-MATRIZ|btf|copiado|$(uname -r)"
        else
            linea "AEGIS-MATRIZ|btf|falla"
        fi
        ;;
    bpf)
        args=""
        for k in $(printf '%s' "$b" | tr ',' ' '); do
            args="$args --requiere-kfunc $k"
        done
        # shellcheck disable=SC2086
        "$C/bin/aegis_bpf_verify" $args "$C/bpf/$a.bpf.o" > "$T/bpf-$a.log" 2>&1 < /dev/null
        case $? in
        0) linea "AEGIS-MATRIZ|bpf|$a|pasa" ;;
        77) linea "AEGIS-MATRIZ|bpf|$a|no-aplica|$(grep NO-APLICA "$T/bpf-$a.log" | head -n 1)" ;;
        *)
            linea "AEGIS-MATRIZ|bpf|$a|falla"
            volcar "$T/bpf-$a.log" 40
            ;;
        esac
        ;;
    prueba)
        case "$b" in
        instalable)
            case "$a" in
            agente-en-vivo) agente_en_vivo "$a" ;;
            trabajador-en-vivo) trabajador_en_vivo "$a" ;;
            *) linea "AEGIS-MATRIZ|prueba|$a|falla|prueba sin arnes: $a ($c)" ;;
            esac
            ;;
        cargo-test)
            "$C/pruebas/$a" --test-threads=1 > "$T/prueba-$a.log" 2>&1 < /dev/null
            if [ $? -eq 0 ]; then
                linea "AEGIS-MATRIZ|prueba|$a|pasa|$(grep 'test result' "$T/prueba-$a.log" | tail -n 1)"
            else
                linea "AEGIS-MATRIZ|prueba|$a|falla"
                volcar "$T/prueba-$a.log" 40
            fi
            ;;
        esac
        ;;
    esac
done < "$C/plan.txt"

rm -rf "$T"
linea "AEGIS-MATRIZ|fin"
