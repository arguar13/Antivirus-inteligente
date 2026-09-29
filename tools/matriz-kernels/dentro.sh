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

    if [ "$rc" -eq 0 ] && [ "${emitidos:-0}" -gt 0 ] && [ "${perdidos:-1}" -eq 0 ]; then
        linea "AEGIS-MATRIZ|prueba|$id|pasa|emitidos=$emitidos perdidos=$perdidos"
    else
        linea "AEGIS-MATRIZ|prueba|$id|falla|salida=$rc emitidos=${emitidos:-?} perdidos=${perdidos:-?}"
        volcar "$T/agente.log"
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
            case "$c" in
            aegis-agent) agente_en_vivo "$a" ;;
            *) linea "AEGIS-MATRIZ|prueba|$a|falla|instalable sin arnes: $c" ;;
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
