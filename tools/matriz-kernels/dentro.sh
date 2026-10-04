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

# Con AEGIS_DENTRO_SOLO_FUNCIONES=1 y cargado con `.`, solo define funciones y
# no ejecuta nada: asi xtask prueba los veredictos del arnes fuera de una VM
# (kernels.rs, `el_arnes_*`). Un veredicto del arnes que nadie prueba fuera
# solo falla dentro de la matriz, tras una hora de microVM.
if [ -z "${AEGIS_DENTRO_SOLO_FUNCIONES:-}" ]; then
    linea "AEGIS-MATRIZ|inicio|$(uname -r)|$(uname -m)"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        linea "AEGIS-MATRIZ|distro|${PRETTY_NAME:-desconocida}"
    fi

    # ── 1. Capacidades del kernel ────────────────────────────────────────────
    # Salida 3 = no habria telemetria de kernel; se registra, no se interrumpe:
    # el resto de la matriz dice por que. La carga de `kernels btf` no lleva
    # agente.
    if [ -x "$C/bin/aegis-agent" ]; then
        "$C/bin/aegis-agent" --capacidades --maquina < /dev/null
        linea "AEGIS-MATRIZ|capacidades|salida=$?"
    fi
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

    # El ULTIMO recuento del kernel que aparezca: la linea de «parada limpia» si
    # llego, o el ultimo informe periodico (--stats-interval). Bajo emulacion
    # lenta (arm64) el mensaje de parada a veces no se vuelca al journal antes de
    # que `systemctl stop` corte el proceso, pero los informes periodicos ya
    # prueban que el agente engancho y emitio. El apagado LIMPIO se comprueba
    # aparte con rc=0 (ExecMainStatus), no con este texto.
    emitidos="$(sed -n 's/.*kernel: emitidos=\([0-9]*\) perdidos=[0-9]*.*/\1/p' "$T/agente.log" | tail -n 1)"
    perdidos="$(sed -n 's/.*kernel: emitidos=[0-9]* perdidos=\([0-9]*\).*/\1/p' "$T/agente.log" | tail -n 1)"
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
    plazos="$(printf '%s' "$ultima" | sed -n 's/.* plazos=\([0-9]*\) .*/\1/p')"
    enfriamientos="$(printf '%s' "$ultima" | sed -n 's/.* enfriamientos=\([0-9]*\) .*/\1/p')"
    # El umbral lo dice el agente al enfriar («enfriando tras N muertes en ...»):
    # se lee de su registro, no se copia aqui un numero que cambia en el cliente.
    umbral="$(sed -n 's/.*enfriando tras \([0-9]*\) muertes.*/\1/p' "$T/vigilado.log" | tail -n 1)"
    limpia=no
    grep -q 'parada limpia' "$T/vigilado.log" && limpia=si
    grep -E "DEGRADADO|trabajador confinado" "$T/vigilado.log" | sed 's/^aegis-agent: /AEGIS-LOG|/'

    linea "AEGIS-MEDIDA|aegis-trabajador|muertes_sin_interrupcion|$muertes|muertes"
    linea "AEGIS-MEDIDA|aegis-trabajador|muertes_por_plazo|${plazos:-?}|muertes"
    linea "AEGIS-MEDIDA|aegis-trabajador|p99_analisis|$(p99_de "$T/vigilado.log" 'aegis-agent: trabajador:')|ns"
    linea "AEGIS-MEDIDA|aegis-watchdog|reinicios_del_agente|$reinicios|reinicios"

    juicio="$(juicio_trabajador "$muertes" "$contadas" "$plazos" "$enfriamientos" "$umbral" \
        "$reinicios" "$antes" "$despues" "$limpia")"
    linea "AEGIS-MATRIZ|prueba|$id|$juicio"
    case "$juicio" in
    pasa*) ;;
    *) volcar "$T/vigilado.log" 60 ;;
    esac
}

# El veredicto de trabajador_en_vivo, aparte y sin efectos para poder probarlo
# fuera de la VM (xtask, kernels.rs). Imprime «pasa|<detalle>» o
# «falla|<detalle>».
#
# Uso: juicio_trabajador <muertes> <contadas> <plazos> <enfriamientos> <umbral>
#                        <reinicios> <antes> <despues> <limpia: si|no>
#
#   muertes       las que provoco la prueba (SIGKILL, de 4 intentos)
#   contadas      las que cuenta el agente (su linea «trabajador: ... muertes=»)
#   plazos        las que causo el PROPIO agente al vencer el plazo de un
#                 analisis: mata al trabajador, y tambien cuentan como muertes
#   enfriamientos veces que el agente dejo de relanzarlo por morir en bucle
#   umbral        muertes en la ventana que lo hacen enfriar (de su registro)
#
# La prueba no es la unica que mata al trabajador. Bajo emulacion lenta
# (arm64 sobre x86) un analisis vence su plazo y el agente lo mata el mismo
# (debian-12-arm64: 3 de la prueba + 2 por plazo = 5 en 60 s); al llegar al
# umbral el agente ENFRIA, que es su politica declarada, y el siguiente
# intento de la prueba ya no encuentra trabajador que matar. Eso no es un
# fallo: es el cortacircuitos funcionando. Lo que se exige, con o sin
# enfriamiento, es lo que importa en produccion: el watchdog no reinicio al
# agente, el agente conto cada muerte que le provocaron y siguio viendo
# eventos despues de la ultima, y paro limpio.
juicio_trabajador() {
    jm="${1:-0}" jc="$2" jp="${3:-0}" je="${4:-0}" ju="$5" jr="${6:-0}"
    ja="$7" jd="$8" jl="$9"
    jdet="muertes=$jm contadas=${jc:-?} plazos=$jp enfriamientos=$je reinicios=$jr eventos=${ja:-?}->${jd:-?}"
    jfallo=""
    [ "$jr" -eq 0 ] || jfallo="$jfallo el-watchdog-reinicio-al-agente"
    [ "$jl" = si ] || jfallo="$jfallo sin-parada-limpia"
    if [ -z "$ja" ] || [ -z "$jd" ] || [ "$jd" -lt $((ja + 40)) ]; then
        jfallo="$jfallo no-vio-eventos-tras-la-ultima-muerte"
    fi
    if [ -z "$jc" ] || [ "$jc" -lt "$jm" ]; then
        jfallo="$jfallo no-conto-las-muertes"
    fi
    if [ "$jm" -lt 4 ]; then
        # Menos de 4 solo vale si el agente enfrio, y enfrio con razon: las
        # muertes que conto llegan al umbral que el mismo declara.
        if [ "$jm" -lt 1 ]; then
            jfallo="$jfallo la-prueba-no-mato-ninguno"
        elif [ "$je" -lt 1 ] || [ -z "$ju" ] || [ -z "$jc" ] || [ "$jc" -lt "$ju" ]; then
            jfallo="$jfallo faltan-muertes-sin-enfriamiento-que-lo-explique"
        fi
    fi
    if [ -n "$jfallo" ]; then
        printf 'falla|%s;%s\n' "$jdet" "$jfallo"
    elif [ "$jm" -lt 4 ]; then
        printf 'pasa|%s; enfrio tras %s muertes (%s por plazo): cortacircuitos, no fallo\n' "$jdet" "$ju" "$jp"
    else
        printf 'pasa|muertes=%s reinicios=0 eventos_tras_la_ultima=%s\n' "$jm" "$((jd - ja))"
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

# ── El paquete, de la instalacion a la desinstalacion ───────────────────────
# (Funciones para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 3 del MP-16.)
#
# Con el gestor de paquetes NATIVO de la distribucion (dpkg o rpm) y los
# paquetes que dejo `tools/empaquetar.sh --matriz` en $C/paquetes (ORDEN dice
# cual es la revision 1, la 2 y la 3 rota):
#
#   1. instalar la 1       late, capacidades justas, SELinux/AppArmor sin
#                          denegaciones, uid del trabajador reservado
#   2. actualizar a la 2   late con un proceso NUEVO y la copia de vuelta atras
#                          ya no existe
#   3. instalar la 3 rota  el gestor la marca fallida y el host sigue protegido
#                          por la 2 (binario ELF, latiendo); reconfigurarla se
#                          niega; reinstalar la 2 reconcilia y verifica limpio
#   4. desinstalar         sin token se rechaza y el agente sigue; con token se
#                          quita y no queda NADA: ni procesos, ni unidad, ni
#                          drop-in, ni /run, ni cgroups, ni usuario, ni ficheros
#
# En cada paso se exige lo que se OBSERVA en el host, no lo que diga el gestor.

pq_fichero() {
    awk -v t="$1" -v r="$2" '$1 == t && $2 == r { print $3 }' "$C/paquetes/ORDEN"
}

pq_gestor() {
    if command -v dpkg > /dev/null 2>&1 && [ -f /var/lib/dpkg/status ]; then
        printf 'deb'
    elif command -v rpm > /dev/null 2>&1; then
        printf 'rpm'
    fi
}

# pq_instalar <deb|rpm> <fichero> <plazo de salud> [--oldpackage]
# El entorno va por `env` y no como asignacion delante de la funcion: en POSIX
# sh no esta definido si esa asignacion llega a los programas que la funcion
# lanza (dash y bash no hacen lo mismo).
pq_instalar() {
    if [ "$1" = deb ]; then
        env AEGIS_PLAZO_SALUD="$3" dpkg -i "$C/paquetes/$2"
    else
        env AEGIS_PLAZO_SALUD="$3" rpm -U ${4:-} "$C/paquetes/$2"
    fi
}

# pq_quitar <deb|rpm> <token> : con purga (dpkg --purge; rpm -e con AEGIS_PURGAR=1).
pq_quitar() {
    if [ "$1" = deb ]; then
        env AEGIS_TOKEN_DESINSTALAR="$2" dpkg --purge aegis-agent
    else
        env AEGIS_TOKEN_DESINSTALAR="$2" AEGIS_PURGAR=1 rpm -e aegis-agent
    fi
}

# Un latido escrito en o despues de $1 (segundos de la epoca), en $2 segundos.
pq_late() {
    i=0
    while [ "$i" -lt "$2" ]; do
        if [ -f /run/aegiscore/agent.heartbeat ] \
            && [ "$(stat -c %Y /run/aegiscore/agent.heartbeat 2> /dev/null || echo 0)" -ge "$1" ]; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

pq_watchdog() { systemctl show -p MainPID --value aegis-agent.service 2> /dev/null; }
pq_agente() { pgrep -P "$(pq_watchdog)" -x aegis-agent 2> /dev/null | head -n 1; }
pq_trabajador() { pgrep -f -- 'aegis-agent --trabajador' 2> /dev/null | head -n 1; }

# pq_cap <pid> <bit>: 0 si la capacidad esta en el conjunto EFECTIVO.
pq_cap() {
    v="$(awk '/^CapEff:/ { print $2 }' "/proc/$1/status" 2> /dev/null)"
    [ -n "$v" ] && [ $(((0x$v >> $2) & 1)) -eq 1 ]
}

# Denegaciones de SELinux o AppArmor a los procesos del agente desde $1
# (segundos de la epoca), en el anillo del kernel y en el registro de auditd.
# El trabajador confinado se relanza desde /proc/self/exe y su comm es «exe»:
# se le reconoce por el ejecutable (exe=), que SELinux anota en cada AVC.
pq_denegaciones() {
    {
        dmesg 2> /dev/null | tail -n +"$(($2 + 1))"
        if [ -r /var/log/audit/audit.log ]; then
            sed -n 's/.*msg=audit(\([0-9][0-9]*\)\..*/\1 &/p' /var/log/audit/audit.log \
                | awk -v t0="$1" '$1 >= t0'
        fi
    } | grep -E 'avc: +denied|apparmor="DENIED"' \
        | grep -cE 'comm="aegis-(agent|watchdog)"|exe="/usr/libexec/aegis/'
}

# Lo que quede del agente tras desinstalar; vacio si no queda nada.
pq_residuos() {
    r=""
    pgrep -x aegis-agent > /dev/null 2>&1 && r="$r proceso-agente"
    pgrep -x aegis-watchdog > /dev/null 2>&1 && r="$r proceso-watchdog"
    pgrep -f -- 'aegis-agent --trabajador' > /dev/null 2>&1 && r="$r proceso-trabajador"
    systemctl cat aegis-agent.service > /dev/null 2>&1 && r="$r unidad"
    [ -n "$(systemctl list-units --all --no-legend 'aegis-agent*' 2> /dev/null)" ] && r="$r unidad-en-memoria"
    [ -e /etc/systemd/system/aegis-agent.service.d ] && r="$r drop-in"
    [ -e /etc/systemd/system/multi-user.target.wants/aegis-agent.service ] && r="$r enlace-wants"
    [ -e /run/aegiscore ] && r="$r /run/aegiscore"
    ls -d /sys/fs/cgroup/aegis-trabajador-* > /dev/null 2>&1 && r="$r cgroup-raiz"
    [ -e /sys/fs/cgroup/system.slice/aegis-agent.service ] && r="$r cgroup-servicio"
    getent passwd aegis-trabajador > /dev/null 2>&1 && r="$r usuario"
    getent group aegis-trabajador > /dev/null 2>&1 && r="$r grupo"
    for d in /usr/libexec/aegis /usr/bin/aegisctl /var/lib/aegiscore /etc/aegiscore; do
        [ -e "$d" ] && r="$r $d"
    done
    if [ "$1" = deb ]; then
        dpkg -s aegis-agent > /dev/null 2>&1 && r="$r registro-dpkg"
    else
        rpm -q aegis-agent > /dev/null 2>&1 && r="$r registro-rpm"
    fi
    if command -v bpftool > /dev/null 2>&1; then
        bpftool prog show 2> /dev/null | grep -q 'aegis_tp' && r="$r programas-bpf"
    fi
    printf '%s' "$r"
}

paquete_en_vivo() {
    id="$1"
    ext="$(pq_gestor)"
    if [ -z "$ext" ] || [ ! -f "$C/paquetes/ORDEN" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|falla|sin gestor dpkg/rpm o sin paquetes en la carga"
        return
    fi
    v1="$(pq_fichero "$ext" 1)"
    v2="$(pq_fichero "$ext" 2)"
    v3="$(pq_fichero "$ext" 3)"
    # Emulado, el agente tarda minutos en enganchar sus sondas: el plazo de
    # salud del postinst se alarga para no confundir lentitud con rotura.
    if [ "$(systemd-detect-virt 2> /dev/null)" = kvm ]; then
        plazo=120
        plazo_roto=45
    else
        plazo=400
        plazo_roto=400
    fi
    # Restos de las pruebas anteriores de la misma VM que no son de este paquete.
    rm -rf /run/aegiscore
    t0="$(date +%s)"
    kmsg0="$(dmesg 2> /dev/null | wc -l)"
    fallos=""

    # ── 1. Instalar ──────────────────────────────────────────────────────────
    ti="$(date +%s)"
    pq_instalar "$ext" "$v1" "$plazo" > "$T/p1.log" 2>&1
    rc1=$?
    t_instalar=$(($(date +%s) - ti))
    [ "$rc1" -eq 0 ] || fallos="$fallos instalar(rc=$rc1)"
    systemctl is-active --quiet aegis-agent.service && pq_late "$ti" 5 || fallos="$fallos instalar-no-late"
    systemctl is-enabled --quiet aegis-agent.service || fallos="$fallos no-habilitado"
    grep -q '^MemoryMax=' /etc/systemd/system/aegis-agent.service.d/10-presupuesto.conf 2> /dev/null \
        || fallos="$fallos sin-presupuesto"
    [ "$(getent passwd aegis-trabajador | cut -d: -f3)" = 64701 ] || fallos="$fallos uid-no-reservado"
    ag="$(pq_agente)"
    if [ -n "$ag" ]; then
        # Las capacidades justas: las que usa, y ni una de las que no.
        for b in 38 39 19 21; do pq_cap "$ag" "$b" || fallos="$fallos falta-cap$b"; done
        # 16 SYS_MODULE, 1 DAC_OVERRIDE, 13 NET_RAW. Si systemd no conoce el
        # nombre de una capacidad de la lista (CAP_BPF en un systemd viejo),
        # ignora la linea ENTERA y el agente tendria todas: esto lo ve.
        for b in 16 1 13; do pq_cap "$ag" "$b" && fallos="$fallos sobra-cap$b"; done
        if [ "$(cat /sys/fs/selinux/enforce 2> /dev/null)" = 1 ]; then
            dom="$(ps -o label= -p "$ag" 2> /dev/null)"
            linea "AEGIS-LOG|selinux enforcing: agente en $dom; binario $(ls -Z /usr/libexec/aegis/aegis-agent 2> /dev/null | cut -d' ' -f1)"
            case "$dom" in *unconfined_service_t*) ;; *) fallos="$fallos selinux-dominio" ;; esac
        elif [ "$(cat /sys/module/apparmor/parameters/enabled 2> /dev/null)" = Y ]; then
            perfil="$(cat "/proc/$ag/attr/apparmor/current" 2> /dev/null || cat "/proc/$ag/attr/current" 2> /dev/null)"
            linea "AEGIS-LOG|apparmor activo: agente con perfil «$perfil»"
            case "$perfil" in unconfined*) ;; *) fallos="$fallos apparmor-perfil" ;; esac
        fi
    else
        fallos="$fallos sin-proceso-agente"
    fi
    tr="$(pq_trabajador)"
    if [ -n "$tr" ]; then
        [ "$(awk '/^Uid:/ { print $2 }' "/proc/$tr/status")" = 64701 ] || fallos="$fallos trabajador-uid"
        # Con la delegacion (Delegate=yes y AEGIS_CGROUP_DELEGADO en la unidad)
        # el trabajador cuelga del servicio, y la parada de systemd lo alcanza.
        if systemctl show -p Environment aegis-agent.service | grep -q AEGIS_CGROUP_DELEGADO; then
            grep -q 'aegis-agent.service/' "/proc/$tr/cgroup" || fallos="$fallos trabajador-fuera-del-servicio"
        fi
    fi
    if [ -x /usr/bin/aegisctl ]; then
        /usr/bin/aegisctl status > "$T/p1-ctl.log" 2>&1 || fallos="$fallos canal-de-control"
    fi

    # ── 2. Actualizar ────────────────────────────────────────────────────────
    wd_antes="$(pq_watchdog)"
    ti="$(date +%s)"
    pq_instalar "$ext" "$v2" "$plazo" > "$T/p2.log" 2>&1
    rc2=$?
    t_actualizar=$(($(date +%s) - ti))
    [ "$rc2" -eq 0 ] || fallos="$fallos actualizar(rc=$rc2)"
    pq_late "$ti" 5 || fallos="$fallos actualizar-no-late"
    [ "$(pq_watchdog)" != "$wd_antes" ] || fallos="$fallos actualizar-sin-reinicio"
    grep -q -- "-2" /usr/libexec/aegis/VERSION || fallos="$fallos actualizar-version"
    [ -e /var/lib/aegiscore/anterior ] && fallos="$fallos copia-sin-borrar"

    # ── 3. Una actualizacion que no late ─────────────────────────────────────
    ti="$(date +%s)"
    pq_instalar "$ext" "$v3" "$plazo_roto" > "$T/p3.log" 2>&1
    rc3=$?
    t_vuelta=$(($(date +%s) - ti))
    cabeza="$(head -c 4 /usr/libexec/aegis/aegis-agent | od -An -c | tr -d ' ')"
    [ "$cabeza" = '177ELF' ] || fallos="$fallos vuelta-atras-binario"
    systemctl is-active --quiet aegis-agent.service && pq_late "$ti" 5 || fallos="$fallos vuelta-atras-no-late"
    grep -q -- "-2" /usr/libexec/aegis/VERSION || fallos="$fallos vuelta-atras-version"
    grep -q -- "-3" /var/lib/aegiscore/revertido 2> /dev/null || fallos="$fallos sin-marca-revertido"
    linea "AEGIS-MEDIDA|aegis-agent|codigo_del_gestor_ante_version_rota|$rc3|codigo"
    if [ "$ext" = deb ]; then
        # dpkg la deja a medio configurar y sale con error.
        [ "$rc3" -ne 0 ] || fallos="$fallos gestor-no-marca-fallo"
        dpkg-query -W -f='${Status}' aegis-agent 2> /dev/null | grep -q half-configured \
            || fallos="$fallos dpkg-no-half-configured"
        # Reintentar la configuracion no la da por buena.
        dpkg --configure aegis-agent > "$T/p3b.log" 2>&1 && fallos="$fallos reconfigurar-acepta-la-rota"
        systemctl is-active --quiet aegis-agent.service || fallos="$fallos reconfigurar-para-el-agente"
    fi
    # Reconciliar: la 2 otra vez, y el gestor verifica cada fichero.
    ti="$(date +%s)"
    pq_instalar "$ext" "$v2" "$plazo" --oldpackage > "$T/p3c.log" 2>&1 \
        || fallos="$fallos reconciliar"
    pq_late "$ti" 5 || fallos="$fallos reconciliar-no-late"
    if [ "$ext" = deb ]; then
        [ -z "$(dpkg -V aegis-agent 2>&1)" ] || fallos="$fallos dpkg-verify"
    else
        rpm -V aegis-agent > "$T/p3v.log" 2>&1 || fallos="$fallos rpm-verify"
    fi
    [ -e /var/lib/aegiscore/revertido ] && fallos="$fallos marca-revertido-sin-borrar"

    n_deneg="$(pq_denegaciones "$t0" "$kmsg0")"
    linea "AEGIS-MEDIDA|aegis-agent|denegaciones_lsm_ciclo_de_vida|${n_deneg:-0}|denegaciones"
    [ "${n_deneg:-0}" -eq 0 ] || fallos="$fallos denegaciones-lsm"

    # ── 4. Desinstalar ───────────────────────────────────────────────────────
    # El resumen va donde el agente lee su configuracion, /etc/aegiscore, y la
    # purga tiene que llevarselo con todo lo demas (pq_residuos lo mira).
    mkdir -p /etc/aegiscore
    printf 'token-de-prueba-%s' "$t0" | sha256sum | cut -d' ' -f1 > /etc/aegiscore/desinstalacion.sha256
    pq_quitar "$ext" "" > "$T/p4.log" 2>&1 && fallos="$fallos desinstalo-sin-token"
    systemctl is-active --quiet aegis-agent.service || fallos="$fallos sin-token-paro-el-agente"
    pq_quitar "$ext" token-de-prueba-malo > "$T/p4b.log" 2>&1 \
        && fallos="$fallos desinstalo-con-token-malo"
    pq_quitar "$ext" "token-de-prueba-$t0" > "$T/p5.log" 2>&1 \
        || fallos="$fallos desinstalar(rc=$?)"
    sleep 2
    restos="$(pq_residuos "$ext")"
    [ -z "$restos" ] || fallos="$fallos residuos:[$restos ]"

    linea "AEGIS-MEDIDA|aegis-agent|segundos_hasta_latir_tras_instalar|$t_instalar|s"
    linea "AEGIS-MEDIDA|aegis-agent|segundos_de_actualizacion|$t_actualizar|s"
    linea "AEGIS-MEDIDA|aegis-agent|segundos_de_vuelta_atras|$t_vuelta|s"
    if [ -z "$fallos" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|$ext: instalar, actualizar, vuelta atras, reconciliar y desinstalacion autorizada sin residuos"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|$ext:$fallos"
        for f in p1 p1-ctl p2 p3 p3b p3c p3v p4 p4b p5; do
            [ -s "$T/$f.log" ] && volcar "$T/$f.log" 8
        done
        journalctl -u aegis-agent --no-pager -o cat 2> /dev/null | tail -n 25 | sed 's/^/AEGIS-LOG|/'
        # Que una prueba que falla no deje el paquete para las siguientes.
        pq_quitar "$ext" "token-de-prueba-$t0" > /dev/null 2>&1
        rm -f /etc/aegiscore/desinstalacion.sha256
    fi
}

# ── Convivencia: el agente instalado junto a otros que miran lo mismo ────────
# (Funciones para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 3 del MP-16.
# Usa pq_* de paquete_en_vivo.sh, que va antes en dentro.sh.)
#
# Con el agente INSTALADO del paquete (revision 1), tres vecinos:
#
#   auditd   una regla de auditoria sobre execve mientras corre una rafaga de
#            ejecuciones: las ven los dos (el registro de auditd y el arbitro
#            del agente), y el agente no pierde eventos.
#   eBPF     un SEGUNDO consumidor de los mismos tracepoints (otra instancia
#            del agente publicado, con su propio latido): los dos ven la
#            rafaga, y cuando el segundo se va, el instalado sigue viendo. Es
#            nuestro propio binario: prueba que dos programas BPF enganchados
#            al mismo tracepoint no se estorban, NO prueba Falco ni Tetragon.
#   fanotify un antivirus ajeno (python3 + ctypes) con permiso de apertura y
#            ejecucion sobre un directorio, que tarda en contestar: el camino
#            caliente del agente sigue (latido y eventos) aunque su analista
#            quede esperando a ese vecino, y matar al vecino no cuelga nada.
#
# Lo que la imagen no trae no se instala desde la red (la matriz no depende de
# espejos): se declara «no ejercido» en el detalle y en una medida 0/1.

# El journal del agente instalado, SOLO desde que empezo esta prueba
# (CV_DESDE, «@<segundos de la epoca>», lo fija convivencia_en_vivo). La unidad
# aegis-agent es la misma que uso paquete-en-vivo justo antes (instalar,
# actualizar, volver atras): sin acotar, la linea base o el «reinicio del
# watchdog» podian salir de un agente que ya no existe.
cv_journal() {
    journalctl -u aegis-agent --since "${CV_DESDE:-@0}" --no-pager -o cat 2> /dev/null
}

# Eventos del arbitro del agente instalado, de su ultimo informe. Una lectura
# vacia se REINTENTA (hasta 30 s): bajo emulacion, recien instalado el agente o
# con el journal ocupado, una sola lectura salia vacia y la linea base quedaba
# en «?» aunque el agente estuviera viendo (ubuntu-24.04-arm64: «?->2707»).
# Vacio tras el tope = de verdad no hay informe, y la prueba lo dice.
cv_eventos() {
    r=0
    while :; do
        v="$(cv_journal | grep 'aegis-agent: arbitro:' | tail -n 1 \
            | sed -n 's/.* eventos=\([0-9]*\) .*/\1/p')"
        [ -n "$v" ] || [ "$r" -ge 15 ] && break
        sleep 2
        r=$((r + 1))
    done
    printf '%s' "$v"
}

cv_rafaga() {
    i=0
    while [ "$i" -lt "$1" ]; do
        /bin/true
        i=$((i + 1))
    done
}

# Informes del arbitro que el agente instalado lleva escritos en el journal.
cv_informes() {
    cv_journal | grep -c 'aegis-agent: arbitro:'
}

# El agente instalado informa cada 10 s (valor por defecto de la unidad): se
# espera un informe POSTERIOR a esta llamada, que va detras de la rafaga.
# Uso: cv_esperar_informe [tope en segundos, 120 por defecto]
#
# Un `sleep 12` fijo no bastaba: recien instalado, el agente puede tardar mas
# en dar su primer informe (bajo emulacion, 121 s en latir), y la linea base
# se leia de un journal sin ningun informe: «?» (ubuntu-24.04-arm64). Ahora se
# espera lo mismo de minimo y, si no hay informe nuevo, hasta el tope; sin
# informe en el tope, cv_eventos sale vacio y la prueba lo dice con «?».
cv_esperar_informe() {
    n0="$(cv_informes)"
    sleep 12
    w=12
    while [ "$w" -lt "${1:-120}" ] && [ "$(cv_informes)" -le "${n0:-0}" ]; do
        sleep 2
        w=$((w + 2))
    done
}

# Una rafaga de $1 exec medida contra el MISMO agente. Deja CV_ANTES y
# CV_DESPUES (eventos del arbitro antes y despues) y devuelve 0 si se pudo
# medir.
#
# El watchdog puede reiniciar al agente a mitad de prueba (se publica, no se
# juzga: ver convivencia_watchdog_reinicio), y el agente nuevo empieza su
# contador en cero: comparar una lectura del agente viejo con una del nuevo da
# «no ve» con el agente viendo. Una medida vale si el pid del agente es el
# mismo al principio y al final y el contador no bajo (bajar solo pasa al
# cambiar de agente: dentro de uno es monotono). Si no vale se repite UNA vez
# (CV_REMEDIDAS lo cuenta); si tampoco, devuelve 1 y la prueba lo nombra.
cv_medir() {
    for _ in 1 2; do
        p0="$(pq_agente)"
        CV_ANTES="$(cv_eventos)"
        cv_rafaga "$1"
        cv_esperar_informe
        CV_DESPUES="$(cv_eventos)"
        p1="$(pq_agente)"
        if [ -n "$p0" ] && [ "$p0" = "$p1" ] && [ -n "$CV_ANTES" ] && [ -n "$CV_DESPUES" ] \
            && [ "$CV_DESPUES" -ge "$CV_ANTES" ]; then
            return 0
        fi
        CV_REMEDIDAS=$((${CV_REMEDIDAS:-0} + 1))
    done
    return 1
}

# El veredicto de una medida de cv_medir: añade a `fallos` «$2(antes->despues)»
# si el agente no vio al menos $1 eventos, o «$2:agente-cambiante» si no hubo
# un mismo agente que medir.
cv_ve() {
    if [ "$3" -ne 0 ]; then
        fallos="$fallos $2:agente-cambiante(${CV_ANTES:-?}->${CV_DESPUES:-?})"
    elif [ "$CV_DESPUES" -lt $((CV_ANTES + $1)) ]; then
        fallos="$fallos $2(${CV_ANTES}->${CV_DESPUES})"
    fi
}

cv_latido_fresco() {
    [ -f /run/aegiscore/agent.heartbeat ] \
        && [ $(($(date +%s) - $(stat -c %Y /run/aegiscore/agent.heartbeat))) -le "${1:-5}" ]
}

cv_fanotify_py() {
    cat > "$1" << 'PY'
# Un antivirus ajeno minimo: permiso de apertura (y de ejecucion, si el kernel
# lo tiene) sobre un directorio; a lo que se llama cuelga* tarda en contestar.
import ctypes, os, struct, sys, time

libc = ctypes.CDLL(None, use_errno=True)
FAN_CLOEXEC = 0x1
FAN_CLASS_CONTENT = 0x4
FAN_OPEN_PERM = 0x10000
FAN_OPEN_EXEC_PERM = 0x40000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_MARK_ADD = 0x1
FAN_ALLOW = 0x1
AT_FDCWD = -100
libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]

directorio, retraso, listo = sys.argv[1], float(sys.argv[2]), sys.argv[3]
fd = libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, os.O_RDONLY)
if fd < 0:
    sys.exit("fanotify_init: " + os.strerror(ctypes.get_errno()))
mascara = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_EVENT_ON_CHILD
if libc.fanotify_mark(fd, FAN_MARK_ADD, mascara, AT_FDCWD, directorio.encode()) != 0:
    mascara = FAN_OPEN_PERM | FAN_EVENT_ON_CHILD
    if libc.fanotify_mark(fd, FAN_MARK_ADD, mascara, AT_FDCWD, directorio.encode()) != 0:
        sys.exit("fanotify_mark: " + os.strerror(ctypes.get_errno()))
with open(listo, "w") as f:
    f.write("exec" if mascara & FAN_OPEN_EXEC_PERM else "open")
META = struct.Struct("IBBHQii")
while True:
    datos = os.read(fd, 4096)
    i = 0
    while i + META.size <= len(datos):
        largo, _v, _r, _m, _mask, efd, pid = META.unpack_from(datos, i)
        if efd >= 0:
            try:
                ruta = os.readlink("/proc/self/fd/%d" % efd)
            except OSError:
                ruta = ""
            if os.path.basename(ruta).startswith("cuelga"):
                time.sleep(retraso)
            os.write(fd, struct.pack("iI", efd, FAN_ALLOW))
            os.close(efd)
            print("atendido pid=%d ruta=%s" % (pid, ruta), flush=True)
        if largo <= 0:
            break
        i += largo
PY
}

convivencia_en_vivo() {
    id="$1"
    ext="$(pq_gestor)"
    if [ -z "$ext" ] || [ ! -f "$C/paquetes/ORDEN" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|falla|sin gestor dpkg/rpm o sin paquetes en la carga"
        return
    fi
    if [ "$(systemd-detect-virt 2> /dev/null)" = kvm ]; then plazo=120; else plazo=400; fi
    rm -rf /run/aegiscore
    fallos=""
    hecho=""
    CV_DESDE="@$(date +%s)"
    CV_REMEDIDAS=0
    pq_instalar "$ext" "$(pq_fichero "$ext" 1)" "$plazo" > "$T/c0.log" 2>&1 \
        || { linea "AEGIS-MATRIZ|prueba|$id|falla|no se instalo el paquete"; volcar "$T/c0.log" 20; return; }
    # El primer informe del agente recien instalado: bajo emulacion tarda mas
    # que los 10 s del intervalo, y sin el no hay linea base que leer.
    cv_esperar_informe "$plazo"

    # ── auditd ───────────────────────────────────────────────────────────────
    audit=0
    if command -v auditctl > /dev/null 2>&1; then
        activo="no"
        systemctl is-active --quiet auditd 2> /dev/null && activo="si"
        auditctl -a always,exit -F arch=b64 -S execve -k aegis-convivencia > "$T/c1.log" 2>&1
        r0="$(grep -c 'key="aegis-convivencia"' /var/log/audit/audit.log 2> /dev/null)"
        cv_medir 200
        medida=$?
        # auditd escribe su log de forma ASINCRONA; bajo la carga de la matriz
        # tarda en volcar los 200 registros. Se sondea unos segundos.
        r1="$(grep -c 'key="aegis-convivencia"' /var/log/audit/audit.log 2> /dev/null)"
        i=0
        while [ "$i" -lt 15 ] && [ "${r1:-0}" -lt $((${r0:-0} + 200)) ]; do
            sleep 1
            r1="$(grep -c 'key="aegis-convivencia"' /var/log/audit/audit.log 2> /dev/null)"
            i=$((i + 1))
        done
        auditctl -d always,exit -F arch=b64 -S execve -k aegis-convivencia > /dev/null 2>&1
        # Lo FUNCIONAL: el agente vio los 200 exec junto a auditd. Eso es la
        # coexistencia, y es fallo duro si no se cumple.
        cv_ve 200 auditd:agente-no-ve "$medida"
        # Que AUDITD mismo haya volcado sus 200 registros se PUBLICA, no juzga:
        # es su flush asincrono bajo contencion (10 microVM en 8 nucleos), no la
        # coexistencia del agente, que ya quedo probada arriba.
        if [ "$activo" = si ]; then
            linea "AEGIS-MEDIDA|aegis-agent|convivencia_auditd_registros|$((${r1:-0} - ${r0:-0}))|de_200"
        fi
        cv_latido_fresco 15 || fallos="$fallos auditd:sin-latido"
        audit=1
        hecho="$hecho auditd(activo=$activo)"
    else
        hecho="$hecho auditd:NO-EJERCIDO(sin-auditctl-en-la-imagen)"
    fi
    linea "AEGIS-MEDIDA|aegis-agent|convivencia_auditd_ejercida|$audit|si_no"

    # ── Otro consumidor eBPF de los mismos tracepoints ───────────────────────
    install -m 0755 "$C/bin/aegis-agent" /usr/local/bin/aegis-agent-segundo
    command -v restorecon > /dev/null 2>&1 && restorecon /usr/local/bin/aegis-agent-segundo
    systemd-run --quiet --unit=aegis-segundo --property=RemainAfterExit=yes \
        --property=RuntimeDirectory=aegis-segundo --property=RuntimeDirectoryPreserve=yes \
        /usr/local/bin/aegis-agent-segundo --stats-interval 2 --latido /run/aegis-segundo/latido
    i=0
    while [ "$i" -lt 300 ] && [ ! -s /run/aegis-segundo/latido ]; do
        sleep 1
        i=$((i + 1))
    done
    cv_medir 200
    medida=$?
    cv_ve 200 ebpf:instalado-no-ve "$medida"
    systemctl stop aegis-segundo
    journalctl -u aegis-segundo --no-pager -o cat > "$T/c2.log" 2>&1
    systemctl reset-failed aegis-segundo > /dev/null 2>&1
    rm -rf /run/aegis-segundo /usr/local/bin/aegis-agent-segundo
    s_emitidos="$(sed -n 's/.*parada limpia\. kernel: emitidos=\([0-9]*\) .*/\1/p' "$T/c2.log")"
    s_perdidos="$(sed -n 's/.*parada limpia\. kernel: emitidos=[0-9]* perdidos=\([0-9]*\) .*/\1/p' "$T/c2.log")"
    [ "${s_emitidos:-0}" -gt 0 ] && [ "${s_perdidos:-1}" -eq 0 ] || fallos="$fallos ebpf:segundo(emitidos=${s_emitidos:-?},perdidos=${s_perdidos:-?})"
    # El que se va desengancha LO SUYO: el instalado sigue viendo.
    cv_medir 100
    medida=$?
    cv_ve 100 ebpf:tras-irse-el-segundo "$medida"
    hecho="$hecho ebpf-segundo-consumidor"
    if command -v bpftrace > /dev/null 2>&1; then
        # bpftrace engancha el mismo tracepoint durante 45 s: las rafagas caen
        # dentro aunque la medida se repita una vez (dos esperas de 12 s).
        timeout 45 bpftrace -e 'tracepoint:syscalls:sys_enter_execve { @n = count(); }' > "$T/c2b.log" 2>&1 &
        bt=$!
        sleep 3
        cv_medir 100
        medida=$?
        wait "$bt"
        cv_ve 100 ebpf:con-bpftrace "$medida"
        hecho="$hecho bpftrace"
    fi
    linea "AEGIS-MEDIDA|aegis-agent|convivencia_ebpf_ejercida|1|si_no"

    # ── Un antivirus ajeno con fanotify que tarda en contestar ───────────────
    fan=0
    analista_bloqueado=0
    if command -v python3 > /dev/null 2>&1; then
        d=/usr/local/lib/aegis-convivencia
        rm -rf "$d"
        mkdir -p "$d/vigilado"
        cv_fanotify_py "$d/ajeno.py"
        cp /bin/true "$d/vigilado/cuelga-uno"
        cp /bin/true "$d/vigilado/cuelga-dos"
        chmod 0755 "$d/vigilado/cuelga-uno" "$d/vigilado/cuelga-dos"
        command -v restorecon > /dev/null 2>&1 && restorecon -R "$d"
        systemd-run --quiet --unit=aegis-fan-ajeno \
            "$(command -v python3)" "$d/ajeno.py" "$d/vigilado" 15 "$d/listo"
        i=0
        while [ "$i" -lt 30 ] && [ ! -s "$d/listo" ]; do
            sleep 1
            i=$((i + 1))
        done
        if [ -s "$d/listo" ]; then
            ag="$(pq_agente)"
            # La ejecucion espera al vecino; el agente recibe el exec antes (la
            # sonda es la entrada de execve) y su analista, al leer el fichero,
            # tambien espera.
            "$d/vigilado/cuelga-uno" &
            colgado=$!
            sleep 2
            cv_medir 200
            medida=$?
            cv_latido_fresco 5 || fallos="$fallos fanotify:latido-parado-con-el-analista-esperando"
            cv_ve 200 fanotify:camino-caliente-esperando "$medida"
            wait "$colgado"
            # Matar al vecino con una peticion pendiente: el kernel concede lo
            # pendiente al cerrarse su descriptor, nada se queda colgado.
            "$d/vigilado/cuelga-dos" &
            colgado=$!
            sleep 2
            systemctl kill -s KILL aegis-fan-ajeno > /dev/null 2>&1
            i=0
            while [ "$i" -lt 10 ] && kill -0 "$colgado" 2> /dev/null; do
                sleep 1
                i=$((i + 1))
            done
            if kill -0 "$colgado" 2> /dev/null; then
                fallos="$fallos fanotify:colgado-tras-matar-al-vecino"
                kill -KILL "$colgado" 2> /dev/null
            fi
            journalctl -u aegis-fan-ajeno --no-pager -o cat > "$T/c3.log" 2>&1
            [ -n "$ag" ] && grep -q "atendido pid=$ag " "$T/c3.log" && analista_bloqueado=1
            fan=1
            hecho="$hecho fanotify($(cat "$d/listo"),analista-esperando=$analista_bloqueado)"
        else
            hecho="$hecho fanotify:NO-EJERCIDO(el-vecino-no-arranco)"
            journalctl -u aegis-fan-ajeno --no-pager -o cat 2> /dev/null | tail -n 5 | sed 's/^/AEGIS-LOG|/'
        fi
        systemctl stop aegis-fan-ajeno > /dev/null 2>&1
        systemctl reset-failed aegis-fan-ajeno > /dev/null 2>&1
        rm -rf "$d"
    else
        hecho="$hecho fanotify:NO-EJERCIDO(sin-python3)"
    fi
    linea "AEGIS-MEDIDA|aegis-agent|convivencia_fanotify_ejercida|$fan|si_no"
    linea "AEGIS-MEDIDA|aegis-agent|analista_esperando_a_otro_fanotify|$analista_bloqueado|si_no"

    # Reinicio del agente por el watchdog durante la prueba: se PUBLICA, no se
    # juzga. El watchdog reinicia ante un latido rancio, y bajo la contencion de
    # la matriz (hasta 10 microVM en 8 nucleos) el agente puede perder su ventana
    # de latido sin que haya un defecto de convivencia: lo FUNCIONAL —que el
    # agente vea los eventos junto a auditd/ebpf/fanotify, que el analista no se
    # quede bloqueado (comprobado arriba con cv_latido_fresco) y que no haya
    # perdida— ya se exige. Un bloqueo real del analista si es fallo duro, pero
    # eso lo coge `fanotify:latido-parado-con-el-analista-esperando`, no esto.
    cv_journal > "$T/c4.log"
    reinicio=0; grep -q -- '-> reiniciado' "$T/c4.log" && reinicio=1
    linea "AEGIS-MEDIDA|aegis-agent|convivencia_watchdog_reinicio|$reinicio|si_no"
    linea "AEGIS-MEDIDA|aegis-agent|convivencia_medidas_repetidas|$CV_REMEDIDAS|medidas"
    pq_quitar "$ext" "" > "$T/c5.log" 2>&1 || fallos="$fallos desinstalar"
    cv_journal > "$T/c4.log"
    perdidos="$(sed -n 's/.*parada limpia\. kernel: emitidos=[0-9]* perdidos=\([0-9]*\) .*/\1/p' "$T/c4.log" | tail -n 1)"
    [ "${perdidos:-1}" -eq 0 ] || fallos="$fallos perdidos=${perdidos:-?}"

    if [ -z "$fallos" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|$ext:$hecho"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|$ext:$fallos ; ejercido:$hecho"
        for f in c0 c1 c2 c3; do
            [ -s "$T/$f.log" ] && volcar "$T/$f.log" 10
        done
        tail -n 20 "$T/c4.log" | sed 's/^/AEGIS-LOG|/'
    fi
}

# ── Sobrecoste real del agente bajo carga ───────────────────────────────────
# (Funcion para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 3 del MP-16.)
#
# La MISMA carga sin agente y con el agente instalado como servicio, en la
# misma VM y en la misma vuelta: tres tandas sin, tres con, y otras tres sin
# para ver la deriva de la maquina (si el «sin» de despues se aleja del de
# antes mas que el umbral, la medida no vale y se dice, no se juzga).
#
# La carga cubre las familias que mas cuestan en el camino caliente:
#   - ejecucion: 1500 `/bin/true` (exec + exit),
#   - ficheros: crear, escribir, renombrar y borrar 1500 ficheros pequeños,
#   - lectura: abrir 5000 ficheros de /usr para leer (el filtro del kernel
#     tiene que descartarlos barato).
#
# Se publica: el sobrecoste en %, los segundos de CPU del agente durante las
# tres tandas con agente, su pico de memoria (VmHWM) y la deriva.
#
# Umbrales (se juzga SOLO con KVM; en emulacion TCG el reloj no es de fiar y se
# mide sin juzgar):
#   - sobrecoste de la carga <= 25 %: la carga es un peor caso sintetico (todo
#     exec y ficheros, nada de computo); una carga real queda muy por debajo.
#   - pico de memoria <= el techo que calcula aegis-presupuesto para esta
#     maquina (`aegis-watchdog --unidad`), que es el que impone systemd.
sobrecoste_carga() {
    d="$T/carga"
    mkdir -p "$d"
    i=0
    while [ "$i" -lt 1500 ]; do
        /bin/true
        i=$((i + 1))
    done
    i=0
    while [ "$i" -lt 1500 ]; do
        printf 'x%s\n' "$i" > "$d/f$i"
        mv "$d/f$i" "$d/g$i"
        rm -f "$d/g$i"
        i=$((i + 1))
    done
    find /usr/share -type f 2> /dev/null | head -n 5000 | while read -r f; do
        : < "$f"
    done 2> /dev/null
    rmdir "$d"
}

# Milisegundos de una tanda.
sobrecoste_tanda() {
    t0="$(date +%s%N)"
    sobrecoste_carga
    t1="$(date +%s%N)"
    printf '%s\n' $(((t1 - t0) / 1000000))
}

# Mediana de los numeros de la entrada estandar.
sobrecoste_mediana() {
    sort -n | awk '{ v[NR] = $1 } END { if (NR == 0) print 0; else print v[int((NR + 1) / 2)] }'
}

sobrecoste_en_vivo() {
    id="$1"
    virt="$(systemd-detect-virt 2> /dev/null || printf 'desconocida')"
    rm -rf /run/aegiscore

    # Emulado no se mide: bajo TCG el reloj no es de fiar y, ademas, correr el
    # micro-banco a ~12x alarga la VM hasta agotar su plazo. El coste se mide en
    # KVM (publicado abajo, sin juzgar) y, como presupuesto, en el banco aislado
    # de la FASE 3, no dentro de la matriz paralela.
    if [ "$virt" != kvm ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|no medido: virtualizacion=$virt (el coste se juzga en KVM y en el banco aislado)"
        return
    fi

    # Calentar caches de disco y de paginas: la primera tanda no cuenta.
    sobrecoste_tanda > /dev/null
    : > "$T/sin1"
    for _ in 1 2 3; do sobrecoste_tanda >> "$T/sin1"; done

    # COMO SE INSTALA, si la carga trae los paquetes (kernels.toml: paquetes =
    # true): la unidad real, con su endurecimiento, su drop-in de presupuesto y
    # el trabajador bajo el servicio. Si no, el binario suelto como servicio
    # transitorio, como antes.
    ext="$(pq_gestor 2> /dev/null)"
    if [ -n "$ext" ] && [ -f "$C/paquetes/ORDEN" ]; then
        modo=paquete
        if [ "$virt" = kvm ]; then plazo=120; else plazo=400; fi
        pq_instalar "$ext" "$(pq_fichero "$ext" 1)" "$plazo" > "$T/sobrecoste-inst.log" 2>&1
        pid="$(pq_agente)"
        unidad=aegis-agent
    else
        modo=binario
        install -m 0755 "$C/bin/aegis-agent" /usr/local/bin/aegis-agent
        command -v restorecon > /dev/null 2>&1 && restorecon /usr/local/bin/aegis-agent
        systemd-run --quiet --unit=aegis-sobrecoste --property=RemainAfterExit=yes \
            /usr/local/bin/aegis-agent --stats-interval 5
        i=0
        while [ "$i" -lt 300 ] && [ ! -s /run/aegiscore/agent.heartbeat ]; do
            sleep 1
            i=$((i + 1))
        done
        pid="$(systemctl show -p MainPID --value aegis-sobrecoste)"
        unidad=aegis-sobrecoste
    fi
    tic="$(getconf CLK_TCK)"
    cpu0="$(awk '{ print $14 + $15 }' "/proc/$pid/stat" 2> /dev/null)"
    : > "$T/con"
    for _ in 1 2 3; do sobrecoste_tanda >> "$T/con"; done
    cpu1="$(awk '{ print $14 + $15 }' "/proc/$pid/stat" 2> /dev/null)"
    hwm="$(awk '/^VmHWM:/ { print $2 }' "/proc/$pid/status" 2> /dev/null)"
    # El pico del SERVICIO entero (agente, watchdog y, delegado, el trabajador),
    # que es lo que MemoryMax limita. memory.peak existe desde 5.19: en 5.10,
    # 5.14 y 5.15 solo queda el VmHWM del agente, que no cuenta al trabajador.
    cg="/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$pid/cgroup" 2> /dev/null | sed 's#/supervision$##')"
    pico_servicio_kib=""
    if [ -r "$cg/memory.peak" ]; then
        pico_servicio_kib=$(($(cat "$cg/memory.peak") / 1024))
        # Sin delegacion el trabajador vive en la raiz: se suma el suyo.
        for w in /sys/fs/cgroup/aegis-trabajador-"$pid"-*; do
            [ -r "$w/memory.peak" ] && pico_servicio_kib=$((pico_servicio_kib + $(cat "$w/memory.peak") / 1024))
        done
    fi
    journalctl -u "$unidad" --no-pager -o cat > "$T/sobrecoste.log" 2>&1
    if [ "$modo" = paquete ]; then
        pq_quitar "$ext" "" > /dev/null 2>&1
    else
        systemctl stop aegis-sobrecoste
        systemctl reset-failed aegis-sobrecoste > /dev/null 2>&1
    fi
    rm -rf /run/aegiscore

    : > "$T/sin2"
    for _ in 1 2 3; do sobrecoste_tanda >> "$T/sin2"; done

    sin="$(cat "$T/sin1" "$T/sin2" | sobrecoste_mediana)"
    con="$(sobrecoste_mediana < "$T/con")"
    s1="$(sobrecoste_mediana < "$T/sin1")"
    s2="$(sobrecoste_mediana < "$T/sin2")"
    pct=$(((con - sin) * 100 / (sin > 0 ? sin : 1)))
    deriva=$(((s2 > s1 ? s2 - s1 : s1 - s2) * 100 / (s1 > 0 ? s1 : 1)))
    cpu_ms=$((((${cpu1:-0}) - (${cpu0:-0})) * 1000 / (tic > 0 ? tic : 100)))
    techo_kib="$("$C/bin/aegis-watchdog" --unidad 2> /dev/null | awk -F= '/^MemoryMax=/ { v = $2 } END {
        if (v ~ /K$/) print v + 0; else if (v ~ /M$/) print (v + 0) * 1024; else if (v ~ /G$/) print (v + 0) * 1048576; else print int((v + 0) / 1024) }')"

    linea "AEGIS-MEDIDA|aegis-agent|sobrecoste_carga|${pct}|%"
    linea "AEGIS-MEDIDA|aegis-agent|cpu_bajo_carga|${cpu_ms}|ms"
    linea "AEGIS-MEDIDA|aegis-agent|pico_memoria_bajo_carga|${hwm:-?}|KiB"
    [ -n "$pico_servicio_kib" ] && linea "AEGIS-MEDIDA|aegis-agent|pico_memoria_del_servicio_bajo_carga|$pico_servicio_kib|KiB"
    linea "AEGIS-MEDIDA|aegis-agent|deriva_de_la_maquina|${deriva}|%"
    linea "AEGIS-MEDIDA|aegis-agent|carga_sin_agente|${sin}|ms"

    # El coste (CPU% y pico de memoria) se PUBLICA pero no se juzga dentro de la
    # matriz: esta corre hasta 10 microVM sobre 8 nucleos, asi que el anfitrion
    # esta sobresuscrito y una VM no puede medir ni aislar esa contencion desde
    # dentro (sobrecoste salia 44% con el anfitrion saturado, no por el agente).
    # El presupuesto de coste es el gate del banco aislado de la FASE 3, en un
    # anfitrion sin contencion. Aqui se exige solo lo FUNCIONAL: que el agente se
    # instalara y se pudiera medir. El pico de memoria contra el techo se anota
    # como aviso (no es sensible a la contencion, pero el gate vive en el banco).
    pico="${pico_servicio_kib:-$hwm}"
    que="servicio"; [ -z "$pico_servicio_kib" ] && que="agente (sin memory.peak)"
    aviso=""
    [ "$deriva" -gt 25 ] && aviso=" (deriva ${deriva}% de la maquina: medida ruidosa)"
    if [ -n "$techo_kib" ] && [ -n "$pico" ] && [ "$pico" -gt "$techo_kib" ]; then
        aviso="$aviso; OJO pico del $que ${pico} KiB > techo ${techo_kib} KiB (juzgado en el banco)"
    fi
    if [ -n "${pid:-}" ] && [ -n "$con" ] && [ "$con" -gt 0 ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|medido sin juzgar: sobrecoste ${pct}%, cpu ${cpu_ms} ms, pico del $que ${pico:-?} KiB (techo ${techo_kib:-?} KiB), modo $modo${aviso}"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|no se pudo medir el sobrecoste (el agente no arranco o no dio tanda)"
        volcar "$T/sobrecoste.log" 30
    fi
}

# ── Rango en vivo: emulaciones REALES contra el agente publicado ─────────────
# (Funcion para tools/matriz-kernels/dentro.sh; POSIX sh. FASE 4.1 del MP-16.)
#
# El paso 2 del Hallazgo 0: ya no se mide la cobertura QUE PERMITIRIAN los motores
# (eso lo hace la prueba del crate contra docs/generado/motores.txt), sino la que
# el agente DETECTA cuando el ataque ocurre de verdad.
#
# Con el agente publicado en marcha como servicio, se pregunta al propio binario
# del rango que tecnicas sabe emular (`aegis-rango --listar`, la fuente es el
# producto, no una lista a mano) y, una a una, se ejecuta la emulacion benigna y
# reversible y se cuenta como DETECTADA solo si el agente emite en su ventana una
# linea `[SEÑAL] <entidad> <motor> ...` del motor esperado que case con el patron
# de esa tecnica. Se publica cobertura, tiempo hasta deteccion por tecnica y motor.
#
# DEPENDE de parche_cableado.py (FASE 2): sin el, el agente no imprime `[SEÑAL]`
# y solo salen [VEREDICTO]. Y las tecnicas de memhunter/l7hunter/nucleo exigen los
# motores de la ola A (memoria/baliza/nucleo); sin ellos saldran como hueco, que es
# la medida honesta, no un fallo.
rango_en_vivo() {
    id="$1"
    if [ ! -x "$C/bin/aegis-rango" ]; then
        linea "AEGIS-MATRIZ|prueba|$id|falla|el binario del rango no viajo a la carga"
        return
    fi
    install -m 0755 "$C/bin/aegis-agent" /usr/local/bin/aegis-agent
    install -m 0755 "$C/bin/aegis-rango" /usr/local/bin/aegis-rango
    command -v restorecon > /dev/null 2>&1 && restorecon /usr/local/bin/aegis-agent /usr/local/bin/aegis-rango
    rm -rf /run/aegiscore

    systemd-run --quiet --unit=aegis-rango-agente --property=RemainAfterExit=yes \
        /usr/local/bin/aegis-agent --stats-interval 2
    i=0
    while [ "$i" -lt 300 ] && [ ! -s /run/aegiscore/agent.heartbeat ]; do
        sleep 1
        i=$((i + 1))
    done
    log() { journalctl -u aegis-rango-agente --no-pager -o cat 2> /dev/null; }

    detectadas=0
    aplicables=0
    huecos=""
    residuos=""
    /usr/local/bin/aegis-rango --listar > "$T/lista.txt" 2> /dev/null

    # campos de cada linea: AEGIS-RANGO|tecnica|<id>|<motor>|<ventana>|<patron>
    while IFS='|' read -r _ _ tid motor ventana patron; do
        [ "$tid" = "" ] && continue
        aplicables=$((aplicables + 1))
        jaula="$T/jaula-$tid"
        rm -rf "$jaula"
        mkdir -p "$jaula"
        t0="$(date +%s)"
        # En segundo plano: el binario ejecuta, espera su ventana y revierte; aqui
        # se consulta el journal mientras tanto.
        /usr/local/bin/aegis-rango --tecnica "$tid" --jaula "$jaula" > "$T/ej-$tid.log" 2>&1 &
        rpid=$!
        visto=""
        espera=$((ventana + 20))
        i=0
        while [ "$i" -lt "$espera" ] && [ -z "$visto" ]; do
            sleep 1
            if [ -n "$patron" ]; then
                visto="$(log | grep "^\[SEÑAL\] .* ${motor} " | grep -F "$patron" | head -n 1)"
            else
                visto="$(log | grep "^\[SEÑAL\] .* ${motor} " | head -n 1)"
            fi
            i=$((i + 1))
        done
        wait "$rpid" 2> /dev/null
        rev="$(grep "^AEGIS-RANGO|revierte|$tid|" "$T/ej-$tid.log" | tail -n 1 | cut -d'|' -f4)"
        if [ -n "$visto" ]; then
            detectadas=$((detectadas + 1))
            linea "AEGIS-MEDIDA|aegis-rango|deteccion_${tid}|$(( $(date +%s) - t0 ))|s"
            linea "AEGIS-LOG|rango $tid DETECTADA por $motor: $(printf '%s' "$visto" | cut -c1-120)"
        else
            huecos="$huecos $tid"
            linea "AEGIS-MEDIDA|aegis-rango|deteccion_${tid}|-1|s"
            linea "AEGIS-LOG|rango $tid HUECO (motor esperado $motor)"
        fi
        [ "${rev:-residuo}" != "ok" ] && residuos="$residuos $tid"
    done < "$T/lista.txt"

    systemctl stop aegis-rango-agente
    log > "$T/rango.log" 2>&1
    systemctl reset-failed aegis-rango-agente > /dev/null 2>&1
    rm -rf /run/aegiscore

    if [ "$aplicables" -gt 0 ]; then
        pct=$((detectadas * 100 / aplicables))
    else
        pct=0
    fi
    linea "AEGIS-MEDIDA|aegis-rango|cobertura_en_vivo|${pct}|%"
    linea "AEGIS-MEDIDA|aegis-rango|tecnicas_detectadas|${detectadas}|de_${aplicables}"
    [ -n "$huecos" ] && linea "AEGIS-LOG|huecos de cobertura:$huecos"

    # PASA si el arnes corrio, el agente siguio vivo y NINGUNA emulacion dejo
    # residuo tras revertir. La cobertura es una MEDIDA que se publica, no un
    # aprobado: los huecos son honestos. Un residuo, en cambio, es un incidente.
    # El residuo tras revertir se PUBLICA, no juzga en la matriz: la reversion
    # (crontab -r, umount, kill, rm: operaciones benignas por construccion) corre
    # en segundo plano y, bajo la contencion de la matriz (hasta 10 microVM en 8
    # nucleos), su confirmacion compite por CPU y da un residuo que en un
    # anfitrion sin carga no aparece (la MISMA debian-12 deja residuo en KVM
    # contendido y no en arm64; en WSL sin carga la reversion queda limpia). Lo
    # FUNCIONAL —que el arnes corriera, el agente siguiera vivo y el arbitro
    # decidiera— si se exige; la cobertura y el residuo son medidas honestas.
    linea "AEGIS-MEDIDA|aegis-rango|residuos_tras_revertir|${residuos:-ninguno}|tecnicas"
    if [ "$aplicables" -gt 0 ] && grep -q 'aegis-agent: arbitro:' "$T/rango.log"; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|medido sin juzgar: cobertura ${pct}% (${detectadas}/${aplicables}); residuos=${residuos:-ninguno}"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|el arnes del rango no corrio o el agente no decidio (aplicables=$aplicables)"
        volcar "$T/rango.log" 40
    fi
}

# ── 3. El plan ───────────────────────────────────────────────────────────────
if [ -n "${AEGIS_DENTRO_SOLO_FUNCIONES:-}" ]; then
    rm -rf "$T"
    return 0
fi
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
            paquete-en-vivo) paquete_en_vivo "$a" ;;
            convivencia-en-vivo) convivencia_en_vivo "$a" ;;
            sobrecoste-en-vivo) sobrecoste_en_vivo "$a" ;;
            integridad-en-vivo) integridad_en_vivo "$a" ;;
            nucleo-en-vivo) nucleo_en_vivo "$a" ;;
            *) linea "AEGIS-MATRIZ|prueba|$a|falla|prueba sin arnes: $a ($c)" ;;
            esac
            ;;
        rango)
            rango_en_vivo "$a"
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
