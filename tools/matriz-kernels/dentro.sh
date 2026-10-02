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
    # Lo suyo, al salir: un latido que sobrevive a su agente engaña a la
    # siguiente prueba que espere uno.
    rm -rf /run/aegiscore
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

# ── Arrancar el agente publicado y esperar a ESE agente ─────────────────────
# Uso: agente_listo <unidad> [argumentos del agente...]
#
# El agente se instala como se instala de verdad y corre como servicio. Late en
# un fichero PROPIO de esta prueba, creado ahora: esperar a «algun latido» en la
# ruta comun dejaba pasar el de un agente anterior, y la prueba actuaba antes de
# que el suyo tuviera las sondas enganchadas y la linea base tomada. Devuelve 1
# si el agente no late en 300 s.
agente_listo() {
    unidad="$1"
    shift
    install -m 0755 "$C/bin/aegis-agent" /usr/local/bin/aegis-agent
    command -v restorecon > /dev/null 2>&1 && restorecon /usr/local/bin/aegis-agent
    mkdir -p /run/aegiscore
    latido="/run/aegiscore/$unidad.heartbeat"
    rm -f "$latido"
    systemd-run --quiet --unit="$unidad" --property=RemainAfterExit=yes \
        /usr/local/bin/aegis-agent --latido "$latido" "$@"
    i=0
    while [ "$i" -lt 300 ] && [ ! -s "$latido" ]; do
        sleep 1
        i=$((i + 1))
    done
    [ -s "$latido" ]
}

# ── Integridad: una puerta trasera en sshd_config ───────────────────────────
# (Funcion para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 2, ola A.)
#
# La condicion de verdad del megaprompt: una puerta trasera en un fichero de
# configuracion. Con el agente publicado en marcha se añade `PermitRootLogin yes`
# a /etc/ssh/sshd_config (con copia y restauracion), y se exige que el agente
# emita un veredicto sobre ese fichero que DIGA que cambio y quien lo cambio.
# Solo-auditoria: el agente señala; restaurar el fichero lo hace la prueba.
integridad_en_vivo() {
    id="$1"
    cfg=/etc/ssh/sshd_config
    if [ ! -f "$cfg" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|no aplica: la imagen no trae sshd_config"
        return
    fi
    cp -p "$cfg" "$T/sshd_config.orig"
    # El agente toma la linea base al arrancar: se espera a que ESTE lata.
    agente_listo aegis-integridad --stats-interval 1
    # La puerta trasera va ARRIBA, como la pondria quien quiere que surta efecto:
    # sshd aplica el primer valor de cada directiva, asi que una linea al final
    # no cambia nada si antes hay otra o un Include que la fija.
    #
    # Y tiene que CAMBIAR algo: hay imagenes que ya traen `PermitRootLogin yes`
    # (openSUSE Leap), y ahi añadirlo no cambia lo que sshd aplica —el motor
    # acierta al callar—. `PermitEmptyPasswords yes` no lo trae activo ninguna
    # distribucion, asi que con las dos lineas siempre hay un cambio real.
    t0="$(date +%s)"
    { printf 'PermitRootLogin yes\nPermitEmptyPasswords yes\n'; cat "$T/sshd_config.orig"; } > "$cfg"
    # En emulacion (TCG) el agente va decenas de veces mas lento: el plazo se
    # ajusta a la maquina, la exigencia no.
    plazo=30
    [ "$(systemd-detect-virt 2> /dev/null)" = "kvm" ] || plazo=120
    visto=""
    i=0
    while [ "$i" -lt "$plazo" ] && [ -z "$visto" ]; do
        sleep 1
        visto="$(journalctl -u aegis-integridad --no-pager -o cat 2> /dev/null \
            | grep '^\[SEÑAL\] .* conductual ' | grep -iE 'PermitRootLogin|permitemptypasswords' \
            | head -n 1)"
        i=$((i + 1))
    done
    t_det=$(( $(date +%s) - t0 ))
    cp -p "$T/sshd_config.orig" "$cfg"
    systemctl stop aegis-integridad
    journalctl -u aegis-integridad --no-pager -o cat > "$T/integridad.log" 2>&1
    systemctl reset-failed aegis-integridad > /dev/null 2>&1
    rm -rf /run/aegiscore

    linea "AEGIS-MEDIDA|aegis-integridad|segundos_hasta_veredicto|${t_det}|s"
    if [ -n "$visto" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|$(printf '%s' "$visto" | cut -c1-160)"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|ningun veredicto sobre sshd_config en $plazo s"
        grep -nE '^[[:space:]]*(PermitRootLogin|PermitEmptyPasswords|Include|Match)' "$T/sshd_config.orig" \
            > "$T/sshd.diag" 2>&1
        volcar "$T/sshd.diag" 10
        {
            grep -aE 'integridad: vigila|motor [a-z]+ registrado$|DEGRADADO|SEÑAL|VEREDICTO' "$T/integridad.log"
            grep -a 'motor integridad:' "$T/integridad.log" | tail -n 3
        } > "$T/integridad.diag"
        volcar "$T/integridad.diag" 30
    fi
}

# ── Nucleo: un proceso escondido de /proc ───────────────────────────────────
# (Funcion para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 2, ola A.)
#
# Dos condiciones, y las dos cuentan:
#   1. En reposo, NINGUNA señal del motor nucleo durante dos barridos: un
#      detector de rootkits que acusa a una maquina limpia es peor que ninguno.
#   2. Un `sleep` escondido montando un directorio vacio encima de su
#      /proc/<pid> —la tecnica de ocultacion en espacio de usuario mas simple
#      que existe, sin modulo de kernel— sale como oculto-en-userland.
#
# Donde el kernel no declara los kfuncs de tareas, el agente deja el motor
# DEGRADADO con el motivo y la prueba lo comprueba en vez de fingir.
nucleo_en_vivo() {
    id="$1"
    agente_listo aegis-nucleo --stats-interval 5
    log() { journalctl -u aegis-nucleo --no-pager -o cat 2> /dev/null; }

    if log | grep -q 'DEGRADADO motor=nucleo'; then
        motivo="$(log | grep 'DEGRADADO motor=nucleo' | head -n 1)"
        systemctl stop aegis-nucleo
        systemctl reset-failed aegis-nucleo > /dev/null 2>&1
        rm -rf /run/aegiscore
        linea "AEGIS-MATRIZ|prueba|$id|pasa|no aplica, declarado: $(printf '%s' "$motivo" | cut -c1-140)"
        return
    fi

    # 1. Reposo: el motor barre cada 30 s; se esperan dos barridos.
    sleep 65
    falsos="$(log | grep -c '^\[SEÑAL\] .* nucleo ')"
    linea "AEGIS-MEDIDA|aegis-kintegrity|falsos_en_reposo|${falsos}|veredictos"

    # Si la sonda dio el motor por disponible (kfuncs declarados y privilegios
    # de un programa tracing) y aun asi el kernel rechaza el verificador, la
    # sonda prometio de mas: es un FALLO, no una degradacion. Asi se vio en
    # Ubuntu 24.04 (6.8) cuando los programas eran de tipo `syscall`; ahora son
    # iteradores `iter.s/task` (tipo tracing), para los que el kernel permite
    # estas kfunc desde que existen, y esta rama no deberia volver a verse.
    rechazo="$(log | grep 'motor nucleo:' | grep -o 'ultimo_sin_datos=«no se cargo el verificador[^»]*' | tail -n 1)"
    if [ -n "$rechazo" ]; then
        systemctl stop aegis-nucleo
        systemctl reset-failed aegis-nucleo > /dev/null 2>&1
        rm -rf /run/aegiscore
        linea "AEGIS-MATRIZ|prueba|$id|falla|la sonda prometio el motor y el kernel rechazo el verificador: $(printf '%s' "${rechazo#ultimo_sin_datos=«}" | cut -c1-200)"
        return
    fi

    # 2. Ocultacion, en el espacio de montaje del SISTEMA (el de PID 1), que es
    # donde lo haria quien quiere esconderse de todos y donde vive el agente:
    # esta prueba corre dentro de cloud-init, que puede tener el suyo propio, y
    # un montaje hecho ahi no lo ve nadie mas. El directorio vacio va en /run,
    # compartido, y no en $T, que puede ser un /tmp privado.
    sistema() { nsenter --mount=/proc/1/ns/mnt "$@"; }
    sleep 600 &
    victima=$!
    sistema mkdir -p /run/aegis-prueba-vacio
    # Si el kernel o la politica (SELinux) impiden montar sobre /proc/<pid>, la
    # tecnica no funciona en esta maquina: no hay nada que detectar y se dice.
    if ! error="$(sistema mount --bind /run/aegis-prueba-vacio "/proc/$victima" 2>&1)"; then
        kill "$victima" 2> /dev/null
        sistema rmdir /run/aegis-prueba-vacio 2> /dev/null
        systemctl stop aegis-nucleo
        systemctl reset-failed aegis-nucleo > /dev/null 2>&1
        rm -rf /run/aegiscore
        linea "AEGIS-MATRIZ|prueba|$id|pasa|no aplica: esta maquina impide la ocultacion por montaje sobre /proc: $(printf '%s' "$error" | tr '\n' ' ' | cut -c1-160)"
        return
    fi
    # La prueba comprueba su propia premisa: si el directorio del proceso sigue
    # legible para el sistema, no hay nada escondido y fallar seria culpar al
    # detector de un montaje que no ocurrio.
    if sistema ls "/proc/$victima/task" > /dev/null 2>&1; then
        sistema umount "/proc/$victima" 2> /dev/null
        kill "$victima" 2> /dev/null
        systemctl stop aegis-nucleo
        systemctl reset-failed aegis-nucleo > /dev/null 2>&1
        rm -rf /run/aegiscore
        linea "AEGIS-MATRIZ|prueba|$id|falla|el montaje no escondio /proc/$victima en el espacio del sistema: la prueba no pudo plantear la ocultacion"
        return
    fi
    visto=""
    i=0
    while [ "$i" -lt 100 ] && [ -z "$visto" ]; do
        sleep 1
        visto="$(log | grep '^\[SEÑAL\] .* nucleo ' | grep 'oculto-en-userland' | grep "tid $victima" | head -n 1)"
        i=$((i + 1))
    done
    sistema umount "/proc/$victima"
    sistema rmdir /run/aegis-prueba-vacio 2> /dev/null
    kill "$victima" 2> /dev/null
    wait "$victima" 2> /dev/null
    systemctl stop aegis-nucleo
    log > "$T/nucleo.log" 2>&1
    systemctl reset-failed aegis-nucleo > /dev/null 2>&1
    rm -rf /run/aegiscore

    if [ "$falsos" -ne 0 ]; then
        linea "AEGIS-MATRIZ|prueba|$id|falla|${falsos} veredictos de nucleo con la maquina en reposo"
        grep -aE 'nucleo|SEÑAL|DEGRADADO' "$T/nucleo.log" | tail -n 30 > "$T/nucleo.diag"
        volcar "$T/nucleo.diag" 30
    elif [ -z "$visto" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|falla|el proceso $victima escondido de /proc no se señalo en 100 s"
        grep -aE 'nucleo|SEÑAL|DEGRADADO' "$T/nucleo.log" | tail -n 30 > "$T/nucleo.diag"
        volcar "$T/nucleo.diag" 30
    else
        linea "AEGIS-MATRIZ|prueba|$id|pasa|$(printf '%s' "$visto" | cut -c1-160)"
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
            integridad-en-vivo) integridad_en_vivo "$a" ;;
            nucleo-en-vivo) nucleo_en_vivo "$a" ;;
            *) linea "AEGIS-MATRIZ|prueba|$a|falla|prueba sin arnes: $a ($c)" ;;
            esac
            ;;
        cargo-test)
            # Dentro de la VM no hay tanda que cuente omisiones: root y la
            # telemetria eBPF se EXIGEN, o una prueba e2e sin sondas saldria
            # «pasa» sin haber visto un evento (aegis_prueba, H-10/H-20).
            AEGIS_EXIGIR=privilegios,ebpf "$C/pruebas/$a" --test-threads=1 \
                > "$T/prueba-$a.log" 2>&1 < /dev/null
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
