#!/usr/bin/env bash
#
# Ejecuta localmente EXACTAMENTE las mismas comprobaciones que .github/workflows/ci.yml.
#
# Existe por una razon concreta: GitHub Actions esta bloqueado a nivel de
# repositorio o cuenta en este proyecto (ver docs/07-estado-ci.md), asi que el
# pipeline remoto no corre. Las comprobaciones no dejan de ser obligatorias por
# eso: se ejecutan aqui, y este script es la referencia normativa mientras el
# CI remoto no arranque.
#
# Uso:  ./tools/ci-local.sh            (todo, de una tacada)
#       ./tools/ci-local.sh rust       (solo un grupo)
#       ./tools/ci-local.sh --grupos   (lista los grupos, en su orden)
#       ./tools/ci-local.sh --reanudar (todo, grupo a grupo y retomable)
set -uo pipefail
cd "$(dirname "$0")/.."

# La compilacion incremental se apaga a proposito, y no por gusto: en una tanda
# de CI no acelera nada —cada ejecucion parte de un arbol que nadie acaba de
# tocar— y en cambio deja en `target/debug/incremental` mas bytes que los propios
# binarios. Medido en esta maquina: 5,6 GiB entre los dos espacios de trabajo,
# que se regeneran en cada tanda y acabaron llenando el disco a media puerta.
# Una puerta que falla por falta de sitio no dice nada del codigo, y es peor que
# una que no se ejecuta: parece un veredicto.
export CARGO_INCREMENTAL=0

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0
SOLO="${1:-}"

# Donde van las salidas de cada comprobacion, PRIVADO de esta ejecucion.
#
# POR QUE NO UNA RUTA FIJA EN /tmp
#
# Porque produjo el peor fallo que puede tener una puerta: uno que MIENTE. Las
# salidas iban a rutas fijas en /tmp, una por grupo mas la del helper `paso`.
# Cuando la misma maquina corre la tanda dos veces con usuarios distintos —una
# como usuario normal y otra como root, que es lo que hace falta para las pruebas
# que inspeccionan memoria ajena—, el fichero ya existe y es del otro usuario: la
# redireccion falla con «Permission denied», porque los ficheros ajenos en un
# directorio con sticky bit estan protegidos por `fs.protected_regular`.
#
# Y entonces pasa lo grave: el comando NO se ejecuta, el `if` se va por la rama
# del fallo, y lo que se imprime es el contenido VIEJO del fichero. Una tanda
# entera "fallando" en un segundo con la salida de otra ejecucion, PID incluidos.
# Cuesta mas descubrir el engaño que arreglar el fallo que se estaba buscando.
#
# Con un directorio propio por ejecucion no hay colision posible: ni entre
# usuarios, ni entre dos tandas simultaneas.
LOGS="$(mktemp -d -t aegis-ci-XXXXXXXX)" || {
    printf '%sNo se pudo crear el directorio temporal de salidas.%s\n' "$ROJO" "$FIN"
    exit 1
}

# El directorio se borra al salir SOLO si no hubo fallos.
#
# De lo que falla, en pantalla se ven las ultimas lineas y nada mas. Para un
# fallo corriente basta; para uno INTERMITENTE es inutil: cuando se intenta
# reproducir, el grupo pasa y la unica copia de lo que realmente ocurrio ya se
# borro. Paso de verdad —una prueba de `captura` fallo en una tanda, no se
# reprodujo en diez intentos, y no quedaba forma de saber cual era—.
#
# Conservar la salida completa cuando algo falla no cuesta nada y es la
# diferencia entre diagnosticar y adivinar.
trap '
    if [ "$FALLOS" -eq 0 ]; then
        rm -rf "$LOGS"
    else
        printf "\n%s==> La salida COMPLETA de cada grupo queda en:%s %s\n" \
            "$GRIS" "$FIN" "$LOGS"
        printf "    %sEn pantalla solo se ven las ultimas lineas. Si el fallo no se\n" "$GRIS"
        printf "    reproduce, esto es lo unico que queda de el.%s\n" "$FIN"
    fi
' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Reanudacion
#
# POR QUE EXISTE
#
# La tanda completa dura mas de lo que aguanta de un tiron un contenedor efimero
# de los que se usan para trabajar en este repo: se reinicia a media puerta y se
# pierde TODO, incluido lo que ya habia pasado. El efecto practico es peor que la
# molestia de repetir: como no se llega nunca al final, se acaba dando por bueno
# el codigo sin el veredicto completo, que es justo lo que esta puerta existe para
# impedir.
#
# Con `--reanudar`, la tanda se ejecuta grupo a grupo y va apuntando los que pasan.
# Un reinicio cuesta, como mucho, el grupo en curso.
#
# LA PARTE QUE HAY QUE HACER BIEN
#
# Una reanudacion ingenua es PEOR que no tener ninguna. Si se retoma despues de
# tocar el codigo, el «todo verde» final se arma con medidas tomadas sobre
# arboles distintos: un veredicto que no existio nunca para ningun estado del
# repositorio, presentado como si existiera. Por eso el apunte lleva en su primera
# linea la HUELLA del arbol —commit, cambios sin comitear y ficheros sin seguir— y
# si al retomar no coincide, el apunte se tira entero y se empieza de cero,
# diciendolo en voz alta.
#
# Y por eso tambien la reanudacion es OPCIONAL y nunca la forma por defecto: lo
# normal tiene que seguir siendo una tanda entera y honrada.
APUNTE=target/.ci-reanudar

# Cuanto se le deja a un grupo antes de darlo por colgado.
#
# No sale de medir el mas lento y anadirle un margen: sale de que ningun grupo de
# esta tanda tarda ni de lejos tanto —el mas pesado, la detonacion, ronda los diez
# minutos— asi que cuarenta y cinco no interrumpe a nadie que este trabajando. Es
# un detector de CUELGUES, no un limite de rendimiento, y por eso va holgado: un
# plazo justo convertiria una maquina lenta en un fallo inventado, que es peor que
# no tener plazo.
PLAZO_POR_GRUPO="${PLAZO_POR_GRUPO:-45m}"

# La huella del arbol: lo comiteado, lo modificado y lo que no esta en el indice.
#
# FALLA EN VEZ DE INVENTARSE UN VALOR, Y ESA ES LA PARTE IMPORTANTE
#
# La primera version caia a la cadena "sin-git" cuando `git` no respondia. Parecia
# defensivo y era lo contrario: con git fallando, los tres mandatos devolvian vacio
# y la huella salia SIEMPRE la misma, asi que el apunte no se invalidaba nunca.
#
# Ocurrio de verdad, y en silencio: al correr la tanda como root sobre un
# repositorio de otro usuario, git se niega con "detected dubious ownership". Se
# midieron 48 grupos sobre un arbol y 2 sobre otro, y la tanda lo presento como
# "todos los grupos en verde sobre el mismo arbol". La garantia entera de
# `--reanudar` descansa en esta funcion.
#
# Una funcion que devuelve un valor por defecto cuando NO PUEDE calcular convierte
# una garantia en una suposicion. Si no se puede saber si el arbol cambio, lo
# correcto es decirlo y parar, no seguir con un numero que no significa nada.
huella_del_arbol() {
    # Se comprueba primero que git responde de verdad sobre este arbol.
    if ! git rev-parse HEAD >/dev/null 2>&1; then
        return 1
    fi
    {
        git rev-parse HEAD
        git diff HEAD --binary
        git ls-files --others --exclude-standard | sort | while read -r f; do
            printf '%s ' "$f"
            sha256sum "$f" 2>/dev/null || echo "?"
        done
    } | sha256sum | cut -d' ' -f1
}

# Los grupos, EN SU ORDEN, sacados de este mismo fichero.
#
# Se derivan del codigo y no de una lista escrita a mano porque una lista a mano
# se queda corta el dia que alguien anade una fase —y entonces `--reanudar` se
# saltaria la puerta nueva en silencio, que es la peor forma de fallar: pasando—.
# El orden de aparicion se respeta, y eso importa: las invariantes van las ultimas
# a proposito, porque comprueban lo que se rompe al sumar.
grupos() {
    # Las dos formas en que este fichero nombra un grupo: la comparacion contra
    # `$SOLO` de las puertas de fase, y el primer argumento de `paso`.
    #
    # Las dos expresiones son estrechas a proposito, porque las anchas recogian
    # cosas que no son grupos y el error no se ve hasta que `--reanudar` intenta
    # ejecutar una:
    #
    #   - `paso` tiene que ir al principio de la linea (indentado o no: los de
    #     Windows y eBPF van dentro de un `if`) y llevar DETRAS el titulo
    #     entrecomillado. Sin exigir las comillas, la prosa de los comentarios
    #     —«no paso», «paso por», «porque»— entraba como grupo.
    #   - El nombre empieza por letra o digito, lo que deja fuera las opciones
    #     `--grupos` y `--reanudar` de aqui arriba, que no son grupos.
    # El orden de aparicion se conserva numerando las lineas y ordenando: con una
    # pasada por patron y concatenando, el orden se perdia. Y aqui el orden es del
    # oficio: las invariantes van las ultimas porque comprueban lo que se rompe AL
    # SUMAR, y con `--reanudar` la ultima es ademas la que da el veredicto.
    {
        grep -nE '\$SOLO" (=|!=) "[a-z0-9][a-z0-9-]*"' "$0" \
            | sed -E 's/^([0-9]+):.*\$SOLO" (=|!=) "([a-z0-9][a-z0-9-]*)".*/\1 \3/'
        grep -nE '^[[:space:]]*paso[[:space:]]+[a-z0-9][a-z0-9-]*[[:space:]]+"' "$0" \
            | sed -E 's/^([0-9]+):[[:space:]]*paso[[:space:]]+([a-z0-9][a-z0-9-]*).*/\1 \2/'
    } | sort -n -k1,1 | awk '!visto[$2]++ { print $2 }'
}

if [ "$SOLO" = "--grupos" ]; then
    grupos
    exit 0
fi

if [ "$SOLO" = "--reanudar" ]; then
    # Antes de nada: que la derivacion no se haya quedado corta. Si una puerta
    # existe y su grupo no sale en la lista, `--reanudar` NO la ejecutaria y
    # acabaria diciendo «todo verde» sin haberla mirado — un falso verde, que es
    # peor que un fallo. Se comprueba aqui y se para en seco.
    LISTA=$(grupos)
    SIN_GRUPO=""
    for g in $(grep -oE '\$SOLO" (=|!=) "[a-z0-9][a-z0-9-]*"' "$0" \
                   | grep -oE '"[a-z0-9][a-z0-9-]*"$' | tr -d '"' | sort -u); do
        echo "$LISTA" | grep -qxF "$g" || SIN_GRUPO="$SIN_GRUPO $g"
    done
    if [ -n "$SIN_GRUPO" ]; then
        printf '%s==> La lista de grupos no cubre:%s%s\n' "$ROJO" "$SIN_GRUPO" "$FIN"
        printf '    Arregla `grupos()` antes de reanudar: si no, se saltaria esas\n'
        printf '    puertas y daria un verde que no ha comprobado.\n'
        # LO NECESARIO PARA DISTINGUIR LAS DOS CAUSAS. Las dos derivaciones usan el
        # mismo patron sobre el mismo fichero, asi que solo discrepan si `grupos()`
        # tiene de verdad un hueco —y entonces vuelve a faltar— o si dos lecturas
        # del fichero devolvieron contenido distinto. Paso una vez, en la primera
        # tanda tras arrancar la VM de WSL, sobre un fichero que llevaba horas sin
        # tocarse, y no se reprodujo en 300 vueltas: se deja la huella y la lista
        # de ese instante para que la proxima vez no haya que adivinar.
        printf '    huella de %s: %s\n' "$0" "$(sha256sum "$0" | cut -c1-16)"
        printf '    grupos derivados (%s): %s\n' "$(echo "$LISTA" | wc -l)" "$(echo $LISTA)"
        OTRA=$(grupos)
        if [ "$OTRA" = "$LISTA" ]; then
            printf '    derivada otra vez: IDENTICA, el hueco es de `grupos()`\n'
        else
            printf '    derivada otra vez: DISTINTA (%s grupos): dos lecturas del mismo\n' "$(echo "$OTRA" | wc -l)"
            printf '    fichero no coincidieron; el sistema de ficheros, no la lista\n'
        fi
        exit 1
    fi

    # Sin huella no hay reanudacion posible. Toda la garantia de `--reanudar`
    # —que los grupos verdes se midieron sobre el MISMO arbol— descansa en poder
    # calcularla; sin ella, apuntar un verde seria apuntar cualquier cosa.
    #
    # El caso real que obliga a esto: correr la tanda como root sobre un
    # repositorio de otro usuario. Git se niega con "detected dubious ownership",
    # y antes eso pasaba en silencio.
    if ! HUELLA=$(huella_del_arbol); then
        printf '%s==> No se puede calcular la huella del arbol.%s\n' "$ROJO" "$FIN"
        printf '    `git rev-parse HEAD` no responde en %s.\n' "$(pwd)"
        printf '    Suele ser que git rechaza el repositorio por pertenecer a otro\n'
        printf '    usuario; se arregla con:\n\n'
        printf '        git config --global --add safe.directory %s\n\n' "'$(pwd)'"
        printf '    Sin huella, `--reanudar` armaria un verde con medidas de arboles\n'
        printf '    distintos, que es justo lo que existe para impedir. Usa `make ci`\n'
        printf '    entero mientras tanto: ese no necesita apunte.\n'
        exit 1
    fi
    if [ -f "$APUNTE" ] && [ "$(head -1 "$APUNTE")" != "$HUELLA" ]; then
        printf '%s==>%s El arbol ha cambiado desde el apunte anterior: se empieza de cero.\n' \
            "$GRIS" "$FIN"
        printf '    %sUn verde armado con medidas de arboles distintos no es un verde.%s\n' \
            "$GRIS" "$FIN"
        rm -f "$APUNTE"
    fi
    mkdir -p "$(dirname "$APUNTE")"
    [ -f "$APUNTE" ] || echo "$HUELLA" > "$APUNTE"

    PENDIENTES=0
    for g in $(grupos); do
        if grep -qxF "verde $g" "$APUNTE"; then
            printf '%s==>%s %s %sya verde en esta misma tanda%s\n' "$GRIS" "$FIN" "$g" "$GRIS" "$FIN"
            continue
        fi
        PENDIENTES=$((PENDIENTES + 1))
        # Con plazo. Un grupo que se cuelga —esperando un socket que no contesta,
        # un proceso hijo que no acaba— dejaria la tanda callada para siempre, y
        # desde fuera eso es indistinguible de estar trabajando: se mira el log, no
        # se mueve, y no se sabe si va lento o si esta muerto. Aqui un cuelgue se
        # convierte en un FALLO con nombre, que es lo unico que se puede arreglar.
        timeout "$PLAZO_POR_GRUPO" "$0" "$g"
        SALIDA=$?
        if [ "$SALIDA" -eq 0 ]; then
            echo "verde $g" >> "$APUNTE"
        elif [ "$SALIDA" -eq 124 ]; then
            printf '%s==> %s se ha COLGADO: mas de %s sin terminar.%s\n' \
                "$ROJO" "$g" "$PLAZO_POR_GRUPO" "$FIN"
            printf '    No es lentitud: el plazo es varias veces lo que tarda el grupo\n'
            printf '    mas lento. Mira que espera (`ps`, el log del grupo) y arreglalo;\n'
            printf '    el apunte se conserva y `--reanudar` vuelve por aqui.\n'
            exit 1
        else
            printf '%s==> %s fallo. El apunte se conserva: al arreglarlo, `--reanudar` sigue por aqui.%s\n' \
                "$ROJO" "$g" "$FIN"
            exit 1
        fi
    done

    # Una tanda entera en verde borra el apunte: la siguiente vuelve a ser
    # completa y honrada por defecto.
    rm -f "$APUNTE"
    printf '%s==> Todos los grupos en verde sobre el mismo arbol (%d ejecutados en esta vuelta)%s\n' \
        "$VERDE" "$PENDIENTES" "$FIN"
    exit 0
fi

SALIDA_PASO="$LOGS/paso.log"

paso() {
    local grupo="$1"; shift
    local titulo="$1"; shift
    if [ -n "$SOLO" ] && [ "$SOLO" != "$grupo" ]; then return 0; fi
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$titulo"
    # Se vacia antes de cada paso: si el comando no llega a escribir nada, lo que
    # se muestre tiene que ser vacio y no lo que dejo el paso anterior.
    : > "$SALIDA_PASO"
    if "$@" > "$SALIDA_PASO" 2>&1; then
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' "$SALIDA_PASO" | tail -40
        FALLOS=$((FALLOS + 1))
    fi
}

paso rust  "Rust · formato"            cargo fmt --all --check
paso rust  "Rust · clippy (-D warnings)" cargo clippy --all-targets -- -D warnings
paso rust  "Rust · tests"               cargo test --all

# El plano de control es OTRO espacio de trabajo (server/), y `cargo test --all`
# no lo alcanza. Hasta ahora quedaba fuera de la puerta obligatoria y se
# ejecutaba a mano: es decir, se ejecutaba mientras alguien se acordara. Todo el
# backend —politica, cacerias, cuarentena de enjambre, heuristicas globales—
# vive ahi.
#
# Las pruebas de integracion del servidor hablan con un PostgreSQL y un Redis
# reales y se omiten SOLAS, con un aviso, si no los hay. Por eso se pueden
# ejecutar aqui sin condicionar el grupo a que la maquina tenga bases de datos:
# donde las haya, se comprueban; donde no, se dice.
if [ -d server ]; then
    paso servidor "Servidor · formato"   sh -c 'cd server && cargo fmt --all --check'
    paso servidor "Servidor · clippy (-D warnings)" \
        sh -c 'cd server && cargo clippy --all-targets -- -D warnings'
    paso servidor "Servidor · tests"     sh -c 'cd server && cargo test --all'
else
    printf '%s==>%s Servidor · %somitido (no esta en este arbol)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi

# El destino Kafka del firehose (FASE 46), verificado contra un corredor REAL
# (FASE 48). Si no se pasa AEGIS_KAFKA, verificar-kafka.sh levanta un Apache
# Kafka de un solo nodo (KRaft) de verdad —proceso Java, sin Docker, sin mocks—
# corre la verificacion de extremo a extremo, y lo apaga. El grupo INFORMA
# siempre de si se pudo ejercer o no: la diferencia entre "probado contra un
# corredor real" y "no se pudo levantar aqui" tiene que verse en la puerta de
# calidad, no quedarse en un comentario del codigo. Cuando no hay Java o salida a
# la red, OMITE con aviso (exit 0) en vez de volver fragil la puerta obligatoria.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "kafka" ]; then
    printf '%s==>%s Firehose · destino Kafka de extremo a extremo\n' "$GRIS" "$FIN"
    if ./tools/verificar-kafka.sh > $LOGS/aegis-kafka.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-kafka.log | tail -5
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        sed 's/^/    | /' $LOGS/aegis-kafka.log | tail -20
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        FALLOS=$((FALLOS + 1))
    fi
fi

# Paridad de defensa en Windows (FASE 47). El driver no se compila aqui —hace
# falta el WDK— pero la DECISION si, y es la parte que puede estar mal de forma
# peligrosa. El grupo informa siempre de que se pudo ejercer y que no.
if [ -f tools/verificar-windows.sh ]; then
    paso windows "Windows · politica de auto-defensa y clasificacion ETW-Ti" \
        ./tools/verificar-windows.sh
fi

# Compilacion cruzada del driver de Windows desde Linux (FASE 48). Cierra el
# segundo hueco de FASE 47: la politica real se compila a un objeto Windows x64
# y se enlaza en un .sys PE real con clang -> lld-link, aqui mismo. El .sys de
# PRODUCCION completo queda condicionado a $WDK_ROOT (headers licenciados), y el
# script lo DECLARA en vez de esconderlo.
if [ -f tools/cross-windows.sh ]; then
    paso windows "Windows · cross-compilacion del driver (clang/lld-link)" \
        ./tools/cross-windows.sh
fi

paso abi   "ABI · layout C vs Rust (gcc)"   env CC=gcc   ./tools/abi-check.sh
paso abi   "ABI · layout C vs Rust (clang)" env CC=clang ./tools/abi-check.sh
# Los pasos de eBPF solo aplican en Linux y solo si el subproyecto existe ya.
# Un grupo que no aplica se omite explicitamente en vez de fallar: un CI que
# falla por algo que no es un defecto ensena a la gente a ignorar el CI.
if [ -f drivers/linux/aegis-bpf/Makefile ]; then
    paso bpf   "eBPF · compilacion"            make -C drivers/linux/aegis-bpf build
    if command -v python3 >/dev/null 2>&1; then
        paso bpf   "eBPF · integridad HMAC"    make -C drivers/linux/aegis-bpf check-integrity
    fi
    paso bpf   "eBPF · verificador del kernel" make -C drivers/linux/aegis-bpf verify
else
    printf '%s==>%s eBPF · %somitido (subproyecto aun no creado)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi
# El sandbox (FASE 26) depende de lo que el kernel de la maquina ofrezca.
# Se informa SIEMPRE de que capas se pueden ejercer: la diferencia entre
# "probado" y "no se pudo probar aqui" tiene que verse en la puerta de calidad,
# no quedarse en un comentario del codigo.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "sandbox" ]; then
    printf '%s==>%s Sandbox · capacidades de aislamiento del kernel\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-sandbox --example sandbox_support > $LOGS/aegis-sandbox.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-sandbox.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-sandbox.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

if [ -z "${SOLO:-}" ] || [ "$SOLO" = "firmware" ]; then
    printf '%s==>%s Firmware · capacidades de arranque medido de la maquina\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-firmware --example firmware_support > $LOGS/aegis-firmware.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-firmware.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-firmware.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

if [ -z "${SOLO:-}" ] || [ "$SOLO" = "unpacker" ]; then
    printf '%s==>%s Unpacker · capacidades de desempaquetado dinamico\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-unpacker --example unpacker_support > $LOGS/aegis-unpacker.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-unpacker.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-unpacker.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# SyscallGuard: reporte honesto de las capacidades de hardware (PMU/DRx) y de la
# via de verificacion cruzada. Igual que el sandbox y el firmware, deja
# constancia de lo que ofrece la maquina donde corre.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "syscallguard" ]; then
    printf '%s==>%s SyscallGuard · deteccion de syscalls directas (PMU/DRx)\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-syscallguard --example syscallguard_support > $LOGS/aegis-syscallguard.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-syscallguard.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-syscallguard.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# PTGuard (Intel PT, FASE 51): el nucleo —decodificar la traza, reconstruir el
# flujo, decidir ROP/JOP— se prueba en "Rust · tests" con trazas binarias reales
# y codigo x86-64 real. Aqui se comprueba que la fontaneria de captura en vivo
# COMPILA (feature pt-live) y se declara si esta maquina puede capturar de verdad
# —que sin intel_pt, no—.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "ptguard" ]; then
    printf '%s==>%s PTGuard · trazado Intel PT (nucleo probado; captura gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-ptguard.sh > $LOGS/aegis-ptguard.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-ptguard.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-ptguard.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Honey-tokens / decepcion activa (FASE 52): el nucleo —acunar, renderizar
# credenciales creibles, planificar sobre /proc/maps real, decidir el disparo— se
# prueba en "Rust · tests". Aqui se comprueba que la fontaneria de inyeccion en
# memoria ajena compila y se declara que su ejecucion necesita un proceso victima
# real.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "honeytoken" ]; then
    printf '%s==>%s Honeytoken · decepcion activa (nucleo probado; inyeccion gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-honeytoken.sh > $LOGS/aegis-honeytoken.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-honeytoken.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-honeytoken.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# ITDR (FASE 58): el nucleo —parsear tickets Kerberos, decidir Kerberoasting /
# Golden / Silver y correlacionar el grafo de identidad— se prueba en "Servidor ·
# tests". Aqui se re-ejercita ese nucleo y se DECLARA que la captura EN VIVO de la
# capa de identidad necesita un dominio Active Directory real, que no hay aqui.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "itdr" ]; then
    printf '%s==>%s ITDR · deteccion de identidad (nucleo probado; captura en vivo gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-itdr.sh > $LOGS/aegis-itdr-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-itdr-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-itdr-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Orquestador de remediacion (AI-RO, FASE 64): el nucleo —la maquina de estados
# transaccional que elige el playbook, lanza las acciones en paralelo, sobrevive a
# fallos parciales y es idempotente en el reintento— se prueba en "Servidor ·
# tests". Aqui se re-ejercita y se DECLARA el muro: la ejecucion REAL de cada
# accion (XDP, matar proceso, revocar ticket, volcado) ocurre en el agente contra
# un sistema real, por gRPC/mTLS.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "orchestrator" ]; then
    printf '%s==>%s AI-RO · orquestador de remediacion (nucleo probado; ejecucion en flota gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-orchestrator.sh > $LOGS/aegis-orchestrator-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-orchestrator-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-orchestrator-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisL7Hunter (uprobes de TLS, FASE 66): los nueve programas eBPF ante el
# verificador REAL del kernel, el ABI del evento cotejado C<->Rust con los dos
# compiladores, la resolucion del objetivo del uprobe contra los binarios reales
# de esta maquina y la matematica de balizas con su cota teorica. El muro es
# enganchar en un proceso vivo que hable TLS.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "l7hunter" ]; then
    printf '%s==>%s AegisL7Hunter · inspeccion L7 de TLS por uprobes y caza de balizas C2\n' "$GRIS" "$FIN"
    if ./tools/verificar-l7hunter.sh > $LOGS/aegis-l7hunter-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-l7hunter-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-l7hunter-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisMemHunter (VAD/PTE, FASE 65): a diferencia del resto de fases de hardware,
# esta NO tiene muro en Linux. El contrato con el kernel —la semantica del bit 61
# de pagemap, de la que depende TODA la deteccion de module stomping— se comprueba
# construyendo cada estado de pagina de verdad, y las dos tecnicas (carga reflexiva
# y sobrescritura de codigo de un modulo) se construyen enteras en un proceso vivo
# y se cazan leyendo /proc autentico. Lo unico gated son los VAD de Windows, cuyo
# ABI si se verifica en compilacion.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "memhunter" ]; then
    printf '%s==>%s AegisMemHunter · VAD/PTE contra codigo sin fichero y module stomping\n' "$GRIS" "$FIN"
    if ./tools/verificar-memhunter.sh > $LOGS/aegis-memhunter-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-memhunter-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-memhunter-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisFirmwareAudit (ROM SPI y tablas ACPI, FASE 67): la unica fase donde el
# riesgo no es dejar de detectar sino ESCRIBIR —una escritura en la ROM SPI deja
# la placa inservible sin recuperacion por software—, asi que lo primero que el
# script ejerce no es deteccion, es inocuidad: write, pwrite y ftruncate sobre el
# descriptor que usa el crate tienen que dar EBADF, llamados de verdad al kernel.
# Las tablas ACPI REALES de esta maquina se parsean y sus checksums cuadran; el
# muro es LEER la ROM, que exige que el kernel exponga la flash como MTD.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "fwaudit" ]; then
    printf '%s==>%s AegisFirmwareAudit · auditoria de ROM SPI y ACPI, estrictamente de solo lectura\n' "$GRIS" "$FIN"
    if ./tools/verificar-fwaudit.sh > $LOGS/aegis-fwaudit-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-fwaudit-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-fwaudit-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisSwarm (enjambre autonomo, FASE 68): la pregunta que decide la fase es que
# consigue el atacante que comprometa UN endpoint si un agente puede decirle al
# enjambre "aisla al equipo X". La respuesta del diseno —el enjambre TRANSPORTA
# autoridad, no la CONCEDE— se ejerce entera, incluido el ataque central:
# reproducir una orden ANTIGUA Y AUTENTICA durante el corte, que ninguna firma
# puede distinguir y que corta la epoca monotona. El transporte libp2p no se da
# por bueno porque compile: dos nodos reales por loopback.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "swarm" ]; then
    printf '%s==>%s AegisSwarm · enjambre autonomo con el plano de control caido\n' "$GRIS" "$FIN"
    if ./tools/verificar-swarm.sh > $LOGS/aegis-swarm-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-swarm-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-swarm-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisPredict (prediccion y contencion preventiva, FASE 69): este motor no
# escribe informes, PROPONE AISLAR MAQUINAS DE PRODUCCION, y eso gobierna su
# diseno: nada esta entrenado —las probabilidades y los pesos estan a mano, con
# su razon, para que el resultado se pueda leer y rebatir— y todo es
# determinista. No hay muro: es matematica sobre un grafo y se comprueba entera,
# incluso contra valores analiticos calculados a mano. Los dos peligros de la
# contencion preventiva —que la cura sea la enfermedad, y que el atacante dirija
# la prediccion fabricando aristas— se ejercen los dos.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "predict" ]; then
    printf '%s==>%s AegisPredict · caminos de ataque, radio de explosion y contencion preventiva\n' "$GRIS" "$FIN"
    if ./tools/verificar-predict.sh > $LOGS/aegis-predict-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-predict-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-predict-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisDirectory (FASE 95): el grafo completo del directorio, para exponer y
# remediar. Modela lo que BloodHound —pertenencia anidada, ACL del
# ntSecurityDescriptor byte a byte, delegacion, derechos de ejecucion, GPO,
# confianzas y plantillas de certificado ESC— MAS la caducidad de la sesion en
# cada arista y el alcance por red, que BloodHound no tiene. Lo primero, el
# autoataque: el grafo es el mapa que un atacante querria y no sale del plano de
# control por ningun canal. Despues, el nucleo puro (descriptor real byte a byte,
# grupos anidados con ciclos, exposiciones con remediacion) y el puente a la
# prediccion, donde la caducidad de la sesion cambia el camino. Muro declarado: la
# captura en vivo por LDAP necesita un Active Directory real.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "directorio" ]; then
    printf '%s==>%s AegisDirectory · grafo del directorio con caducidad de sesion y alcance por red\n' "$GRIS" "$FIN"
    if ./tools/verificar-directorio.sh > $LOGS/aegis-directorio-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-directorio-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-directorio-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Diseccion semantica de protocolos (AegisWire, FASE 70): convierte bytes que
# escribe el ATACANTE, sin autenticacion previa y a velocidad de linea, en hechos
# con significado. Es la superficie de ataque mas expuesta del producto. El motor
# es sans-io, asi que cada ataque —evasion por solape TCP, contrabando HTTP,
# bucle de punteros DNS, cadena de extensiones IPv6, fichero disfrazado,
# agotamiento de memoria— se ejerce ENTERO en pruebas, sin red y sin privilegios.
# Muros declarados: no captura de la NIC (eso es aegis-net), no defragmentacion
# IP, y no se mira dentro de lo cifrado (eso es aegis-l7hunter).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "wire" ]; then
    printf '%s==>%s AegisWire · diseccion de protocolos y reensamblado resistente a evasion\n' "$GRIS" "$FIN"
    if ./tools/verificar-wire.sh > $LOGS/aegis-wire-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-wire-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-wire-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# Prevencion en linea (AegisIPS, FASE 71): pasar de DETECTAR a BLOQUEAR. La
# frase que gobierna la fase: un falso positivo en un IDS es una alerta que
# alguien descarta; en un IPS es una INTERRUPCION DE SERVICIO. Por eso las cuatro
# salvaguardas —solo la confianza alta corta, lista de nunca-bloquear, modo por
# defecto Solo Deteccion, y tope de bloqueos con degradacion automatica— no son
# un anadido al motor: son EL diseno. Las dos del medio se comprueban OTRA VEZ en
# el kernel, porque una salvaguarda que depende de que el codigo de decision este
# bien no protege del caso que importa. Plano de datos en TC (no XDP: XDP no
# tiene camino de salida, y el sentido saliente —baliza al C2, exfiltracion,
# movimiento lateral— es el que mas importa cortar en un endpoint).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "ips" ]; then
    printf '%s==>%s AegisIPS · prevencion en linea con veredictos cacheados en el kernel\n' "$GRIS" "$FIN"
    if ./tools/verificar-ips.sh > $LOGS/aegis-ips-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-ips-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-ips-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# La fabrica de contenido (FASE 72): un motor de deteccion sin contenido no
# detecta nada, y el contenido del mundo esta escrito en cuatro formatos por
# gente que NO somos nosotros. Lo que gobierna el crate entero: si un feed se
# compromete, quien escribe lo que entra por aqui es el atacante, y entra en el
# proceso que compila el contenido de seguridad de la flota entera.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "ruleforge" ]; then
    printf '%s==>%s AegisRuleForge · el corpus mundial compilado, con canario y corpus firmado\n' "$GRIS" "$FIN"
    if ./tools/verificar-ruleforge.sh > $LOGS/aegis-ruleforge-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-ruleforge-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-ruleforge-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# Detonacion en microVM (FASE 73): ejecutar malware A PROPOSITO para ver que
# hace. Todo lo demas vale cero si esa ejecucion puede tocar algo real, asi que
# la frontera no es una capa: es la unica razon por la que el resto existe. Y no
# se declara, se COMPRUEBA — hay una prueba que intenta una conexion de verdad a
# una direccion de verdad desde dentro y no la alcanza.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "detonate" ]; then
    printf '%s==>%s AegisDetonate · detonacion con invitado hostil e informe que no puede mentir\n' "$GRIS" "$FIN"
    if ./tools/verificar-detonate.sh > $LOGS/aegis-detonate-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-detonate-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-detonate-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Plano de control para 100.000 agentes (FASE 75): la diferencia entre diez
# agentes y cien mil no es un factor de escala, es un diseno distinto, y los
# sistemas que no se disenaron para ello no se arreglan anadiendo maquinas. Se
# comprueban las cuatro cosas que fallan —el reparto que rebaraja la flota al
# ampliar, la purga que un dia no acaba, la manada que tira al nodo que vuelve, y
# la actualizacion progresiva que rompe en silencio— con numeros y no con
# afirmaciones, incluida una prueba de carga de cien mil agentes.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "scale" ]; then
    printf '%s==>%s AegisScale · plano de control para 100.000 agentes\n' "$GRIS" "$FIN"
    if ./tools/verificar-scale.sh > $LOGS/aegis-scale-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-scale-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-scale-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Ingesta de registros a escala (FASE 74): tragarse lo que ya escribe el resto de
# la casa —syslog, journald, EVTX, ficheros planos y los planos de control de las
# nubes— y correlacionarlo con lo propio. Es la superficie MAS ANCHA del
# producto: un registro lo escribe cualquiera, incluido el atacante, y un puerto
# 514 abierto no tiene autenticacion ni la va a tener. Lo que se comprueba no es
# que los formatos se lean, sino las cuatro cosas que separan una canalizacion de
# un tubo: entrega al-menos-una-vez con punto de control durable, memoria acotada
# de extremo a extremo, orden por OCURRENCIA y no por llegada, y perdida contada.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "ingest" ]; then
    printf '%s==>%s AegisIngest · registros de cualquier origen, sin perder ni inventar\n' "$GRIS" "$FIN"
    if ./tools/verificar-ingest.sh > $LOGS/aegis-ingest-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-ingest-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-ingest-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Ciclo de vida del incidente (FASE 76): un producto que detecta y no da flujo de
# trabajo produce alertas que nadie mira, y no por dejadez —es la respuesta
# racional a una senal en la que cuarenta y ocho de cada cincuenta son ruido—. Se
# comprueban las cuatro formas de fallar EN SILENCIO: fusionar de mas y perder el
# caso distinto que llego en medio de una campana, coser los huecos de la
# cronologia en una cadena causal que no existio, un rastro editable despues, y
# un panel sin ruido POR REGLA, que es lo unico que permite apagar las reglas que
# solo hacen ruido.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "case" ]; then
    printf '%s==>%s AegisCase · de alerta a caso cerrado, con rastro inalterable\n' "$GRIS" "$FIN"
    if ./tools/verificar-case.sh > $LOGS/aegis-case-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-case-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-case-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Enriquecimiento con privacidad (FASE 77): consultar por un resumen le dice al
# proveedor que ese fichero esta en tu red — no es un efecto secundario de la
# consulta, ES la consulta—, y no se puede retirar. Casi siempre compensa, pero
# «casi siempre» es una decision, y una decision que nadie ve es un valor por
# defecto. Se comprueban las cinco cosas que hacen falta para que el marco sirva:
# el corte de un analizador colgado, el modo sin salida cumplido POR
# CONSTRUCCION, el saneado de una respuesta manipulada, la cuota bajo
# concurrencia y una fusion determinista y explicable.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "enrich" ]; then
    printf '%s==>%s AegisEnrich · preguntar a muchas fuentes sin contar lo que no toca\n' "$GRIS" "$FIN"
    if ./tools/verificar-enrich.sh > $LOGS/aegis-enrich-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-enrich-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-enrich-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# Inteligencia con difusion controlada (FASE 78): compartir es IRREVERSIBLE, y
# los errores se propagan. Los dos fallos que importan no son de formato: que
# salga algo que no debia —y basta un filtro que se quedo atras al añadir un
# camino nuevo—, y que entre algo envenenado y no se pueda deshacer. Se comprueba
# que hay UN solo estrangulamiento de salida por el que pasan los cuatro canales,
# que un canal envenenado se revierte por procedencia, que un ciclo de federacion
# no es un bucle pero una correccion si circula, y que la doctrina del enjambre
# de la FASE 68 sigue intacta: transporta autoridad, no la concede.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "share" ]; then
    printf '%s==>%s AegisShare · STIX/TAXII con difusion impuesta en el codigo\n' "$GRIS" "$FIN"
    if ./tools/verificar-share.sh > $LOGS/aegis-share-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-share-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-share-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# EL ESTADO DEL ENDPOINT, entero y consultable (AegisState, FASE 81).
#
# Va aqui, despues de las fases que producen veredictos y antes de las
# invariantes, porque lo que comprueba es una capacidad y no una propiedad del
# conjunto: que AegisQL corre sobre cincuenta y dos tablas en vez de cinco, que
# cada una declara su coste, y que las que no se pueden leer DICEN por que en
# lugar de devolver filas vacias.
#
# Esa ultima parte es la que justifica tener puerta propia. Un producto puede
# equivocarse al detectar y se corrige; un producto que responde «cero» cuando
# no pudo mirar convierte cada informe en una falsa tranquilidad, y eso no lo
# ve ninguna otra puerta del arbol.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "estado" ]; then
    printf '%s==>%s AegisState · el estado del endpoint, con su coste y su motivo\n' "$GRIS" "$FIN"
    if ./tools/verificar-estado.sh > $LOGS/aegis-estado-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-estado-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-estado-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisArtifact (FASE 82): la custodia de la evidencia.
#
# Esta puerta existe porque el resto del arbol comprueba que el producto DETECTA
# y RESPONDE, y ninguna comprueba que lo que recoge se pueda sostener cuando
# alguien lo discuta. Son dos cosas distintas: un volcado autentico del que no se
# puede probar de donde salio, que nadie lo cambio y por cuantas manos paso no es
# evidencia, es un fichero. Y la unica forma de enterarse de que no lo es, sin
# esta puerta, seria el dia que hiciera falta.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "custodia" ]; then
    printf '%s==>%s AegisArtifact · la evidencia, con su procedencia y su cadena\n' "$GRIS" "$FIN"
    if ./tools/verificar-custodia.sh > $LOGS/aegis-custodia-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-custodia-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-custodia-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisWin (FASE 83): el lector de ejecutables de Windows.
#
# Hasta aqui el agente sabia mirar un proceso de Windows por fuera y no sabia
# abrir su fichero, que es de donde sale todo lo que un EDR decide antes de
# dejarlo correr. Esta puerta lo comprueba contra PE reales construidos en esta
# misma maquina con clang y lld-link, y cotejados con llvm-readobj.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "pe" ]; then
    printf '%s==>%s AegisWin · el ejecutable de Windows por dentro, y su huella\n' "$GRIS" "$FIN"
    if ./tools/verificar-pe.sh > $LOGS/aegis-pe-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-pe-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-pe-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisMac + AegisEnforce (FASE 84): macOS, y la pregunta que cierra el proyecto.
#
# Un EDR tiene dos modos que se parecen mucho por fuera: mirar y bloquear. La
# diferencia la nota el cliente el dia del incidente. Esta puerta mide cual de
# los dos es este agente EN ESTA MAQUINA, en vez de creerse la configuracion.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "mac" ]; then
    printf '%s==>%s AegisMac + AegisEnforce · macOS, y que se impone de verdad\n' "$GRIS" "$FIN"
    if ./tools/verificar-mac.sh > $LOGS/aegis-mac-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-mac-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-mac-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisDisasm (FASE 85): desensamblado, grafos y capacidades con evidencia.
#
# Una firma dice «esto es Emotet» y no dice por que; cuando se equivoca no hay
# forma de saberlo sin repetir el analisis a mano. Una capacidad dice «esto
# inyecta codigo en otro proceso» y ensena las instrucciones que lo hacen.
#
# Esta puerta mide ademas lo que casi nunca se mide: lo que el catalogo dice de
# los ficheros que NO son malware, que son el 99,99 % de los que va a ver.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "disasm" ]; then
    printf '%s==>%s AegisDisasm · desensamblado, grafos y capacidades con evidencia\n' "$GRIS" "$FIN"
    if ./tools/verificar-disasm.sh > $LOGS/aegis-disasm-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-disasm-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-disasm-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisDecompile (FASE 100): decompilador determinista a pseudo-C sobre el grafo de
# la FASE 85. Gana a Ghidra en determinismo (nombres por contenido, no por orden),
# en evidencia (cada sentencia cita sus direcciones), en calidad declarada como
# parte de la salida, y en que NO EJECUTA NADA (por tipo). La cifra de la fase es el
# redondeo semantico: se compila un corpus, se decompila, se recompila el pseudo-C
# y se comprueba equivalencia de comportamiento. Alcance honesto: el subconjunto de
# registros (aritmetica entera, -O2) se verifica; la pila de -O0, la destruccion de
# phi y ARM64 son incrementos siguientes y se declaran.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "decompile" ]; then
    printf '%s==>%s AegisDecompile · de bytes a pseudo-C, determinista y con evidencia\n' "$GRIS" "$FIN"
    if ./tools/verificar-decompile.sh > $LOGS/aegis-decompile-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-decompile-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-decompile-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisPattern (FASE 101): el motor de patrones deja de ser prestado. Sustituye a
# yara-x en el arbol del agente con un motor propio de coste acotado por tipo,
# tri-estado, determinista y SIN RETROCESO (Pike VM: sin ReDoS por construccion).
# La prueba de que la fase termino es que la fila de yara-x desaparece del arbol
# del agente, y aqui se comprueba, junto con la paridad con yara-x sobre las 14
# reglas base y el autoataque del compilador y del motor.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "patron" ]; then
    printf '%s==>%s AegisPattern · motor de patrones propio, acotado y sin retroceso (sustituye a yara-x)\n' "$GRIS" "$FIN"
    if ./tools/verificar-patron.sh > $LOGS/aegis-patron-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-patron-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-patron-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisEmulate (FASE 102): emulacion con MMU de permisos reales, ejecucion
# simbolica acotada sobre la IR de la FASE 100 y desempaquetado generico por
# observacion. Lo distintivo: la ausencia es la frontera —el emulador no tiene
# salida al sistema real, verificado por lo que FALTA en el codigo—, la cota de la
# ejecucion simbolica es parte del tipo (angr no acota y explota), y un empaquetador
# nuevo se desempaqueta sin regla nueva.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "emular" ]; then
    printf '%s==>%s AegisEmulate · emulacion, ejecucion simbolica acotada y desempaquetado generico\n' "$GRIS" "$FIN"
    if ./tools/verificar-emular.sh > $LOGS/aegis-emular-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-emular-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-emular-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisSensor (FASE 103): telemetria de kernel sin perdida silenciosa y sin
# carreras. Lo distintivo, probado como logica pura: la perdida se cuenta POR
# FAMILIA y se dice como SinDatos (un anillo lleno no es «limpio»), la degradacion
# por presupuesto apaga por valor ascendente diciendolo, y el evento lleva lo
# capturado en el kernel —sin relectura de /proc, verificado por ausencia—. Sobre
# este entorno BPF LSM esta activo, habilitador de los ganchos LSM.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "sensor" ]; then
    printf '%s==>%s AegisSensor · perdida declarada por familia, degradacion visible y sin carreras\n' "$GRIS" "$FIN"
    if ./tools/verificar-sensor.sh > $LOGS/aegis-sensor-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-sensor-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-sensor-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisIntegrity (FASE 104): integridad sin carrera y por significado, que
# SUSTITUYE a aegis-fim. Lo distintivo, probado como logica pura: el cambio lleva
# su AUTOR del gancho LSM (sin relectura de /proc, por ausencia), la configuracion
# se mira por SIGNIFICADO (un comentario no es alerta), la linea base la FIRMA el
# plano de control y se SELLA contra el TPM (root no basta), y la vigilancia mutua
# a tres bandas protege la capacidad de avisar dejando intacta la desinstalacion
# autorizada del dueno (invariante 10).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "integridad" ]; then
    printf '%s==>%s AegisIntegrity · sin carrera y con autor, por significado, linea base firmada y sellada\n' "$GRIS" "$FIN"
    if ./tools/verificar-integridad.sh > $LOGS/aegis-integridad-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-integridad-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-integridad-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisAttest (FASE 105): atestacion continua que supera a Keylime. Lo distintivo,
# probado como logica pura: la politica de PCR es un TIPO (una contradiccion no
# llega a existir), la medida de IMA se une a la PROCEDENCIA (una medida que ningun
# paquete ni la linea base avala es SinProcedencia), la revocacion HACE algo (baja
# autoridad y tope de confianza) y la revocacion masiva la corta la degradacion
# pegajosa, la cadena de linaje es UNA (un hueco es eslabon roto), y un par no
# acepta autoridad de un nodo no atestado. La fontaneria del chip esta gated.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "atestacion" ]; then
    printf '%s==>%s AegisAttest · politica como tipo, IMA con procedencia, revocacion que actua\n' "$GRIS" "$FIN"
    if ./tools/verificar-attest.sh > $LOGS/aegis-attest-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-attest-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-attest-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisInline (FASE 106): reensamblado y corte resistentes a evasion. Lo
# distintivo, probado como logica pura: el perfil de reensamblado se elige por el
# SISTEMA REAL del destino (que AegisCore SABE, no adivina como Suricata), la
# ambiguedad se resuelve PREGUNTANDO AL ENDPOINT (nadie sin agente puede), la
# latencia anadida del corte se publica como p50/p99 (no la media), y el
# reensamblado no se agota (cotas duras). La semantica de protocolos no se duplica:
# vive en aegis-wire (FASE 70).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "inline" ]; then
    printf '%s==>%s AegisInline · perfil por destino, desambiguacion por endpoint, latencia p50/p99\n' "$GRIS" "$FIN"
    if ./tools/verificar-inline.sh > $LOGS/aegis-inline-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-inline-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-inline-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisMemForensics (FASE 86): analisis forense de memoria.
#
# Un adquiridor de memoria que pudiera escribir seria una primitiva de inyeccion
# con otro nombre. Esta puerta comprueba la ausencia de ese camino, que es la
# unica forma de comprobar una ausencia: buscando lo que no deberia estar.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "volcado" ]; then
    printf '%s==>%s AegisMemForensics · memoria inerte, y el camino que no existe\n' "$GRIS" "$FIN"
    if ./tools/verificar-volcado.sh > $LOGS/aegis-volcado-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-volcado-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-volcado-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisInstrument (FASE 87): instrumentacion confinada por el TIPO.
#
# Un instrumentador que pueda escribir en un proceso es una primitiva de
# inyeccion. Aqui esa capacidad necesita una prueba de estar dentro de la jaula
# de detonacion, y esa prueba solo se obtiene midiendo: fuera, el programa NO
# COMPILA. La puerta lo comprueba con dos ejemplos atados a su codigo de error.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "instrumentar" ]; then
    printf '%s==>%s AegisInstrument · instrumentacion confinada por el tipo\n' "$GRIS" "$FIN"
    if ./tools/verificar-instrumentar.sh > $LOGS/aegis-instr-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-instr-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-instr-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisDissect (FASE 89): diseccion de protocolos empresariales, industriales y
# de nube, con COBERTURA DECLARADA.
#
# Disecar muchos protocolos no es la propiedad interesante. Lo que ningun sensor
# del sector contesta es la pregunta que importa cuando falta una alerta: «¿esto
# no paso, o no lo supimos leer?». Esta puerta comprueba que cada disector
# declara sus dos mitades, que ninguno hace entrada/salida, que ninguno puede
# responder, y que los dos techos de memoria son LOS MISMOS que los del motor y
# no dos parecidos al lado — que es la unica forma de que la invariante de la
# cota global signifique algo con un crate nuevo.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "disectores" ]; then
    printf '%s==>%s AegisDissect · diseccion ampliada con cobertura declarada\n' "$GRIS" "$FIN"
    if ./tools/verificar-disectores.sh > $LOGS/aegis-disectores-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-disectores-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-disectores-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisCapture (FASE 90): captura indexada por entidad con retencion por veredicto.
#
# Un capturador es el sitio donde se acumula todo lo que paso por la red, y eso
# lo convierte en dos armas contra su propio dueno: un sitio del que robar
# credenciales y una forma de llenar el disco. Esta puerta comprueba que las dos
# estan paradas por propiedades ESTRUCTURALES —el anillo solo acepta bytes
# redactados, guardar entero exige un veredicto, y el anillo no crece— y no por
# limites configurables que alguien pueda subir.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "captura" ]; then
    printf '%s==>%s AegisCapture · captura por entidad con retencion por veredicto\n' "$GRIS" "$FIN"
    if ./tools/verificar-captura.sh > $LOGS/aegis-captura-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-captura-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-captura-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisLure (FASE 91): red de senuelos atribuible con procedencia por destino.
#
# Un senuelo es una capacidad nueva del producto y, por tanto, una capacidad nueva
# para quien lo comprometa: puede usarse como amplificador contra un tercero, como
# forma de agotar el agente y como via de entrada. Esta puerta comprueba que las
# tres estan paradas por construccion —la cota de amplificacion la aplica el
# envoltorio, el limitador es de la red entera, y los dialogos NO PUEDEN ejecutar
# nada porque no hay nada que ejecutar— y que cada senuelo entrega un token
# distinto atado a su sitio, que es lo que contesta «por donde entraron».
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "senuelos" ]; then
    printf '%s==>%s AegisLure · senuelos que conversan, con procedencia por destino\n' "$GRIS" "$FIN"
    if ./tools/verificar-senuelos.sh > $LOGS/aegis-senuelos-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-senuelos-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-senuelos-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisFirmware+ (FASE 92): de dos superficies de firmware a la plataforma
# entera —protecciones de la flash, SMM, bloqueos del chipset, MSR, IOMMU,
# mitigaciones, microcodigo, todas las variables UEFI, el AML y la cadena de
# arranque explicada—, con la escritura IMPOSIBLE de expresar. Lo primero que se
# ejerce es, otra vez, la inocuidad: cada superficie nueva rechaza la escritura
# en el kernel, y el tipo no la puede ni pedir. El AML real se coteja en la
# propia puerta contra iasl y acpiexec, y la tabla de CHIPSEC contra el codigo.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "plataforma" ]; then
    printf '%s==>%s AegisFirmware+ · auditoria de plataforma de grado CHIPSEC, sin poder escribir\n' "$GRIS" "$FIN"
    if ./tools/verificar-plataforma.sh > $LOGS/aegis-plataforma-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-plataforma-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-plataforma-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisConfine (FASE 93): confinamiento DERIVADO del comportamiento. Se aprende lo
# que un programa hace de verdad con la notificacion de usuario de seccomp, se
# ensaya en permisivo sin bloquear nada, se impone solo con confirmacion —seccomp
# en lista blanca, Landlock sobre las rutas usadas y el conjunto limite de
# capacidades— y se retira solo si rompe la produccion. Lo que se comprueba aqui
# es contra el KERNEL: lo aprendido funciona y lo demas lo bloquea el kernel. Y el
# autoataque: el motor no puede confinar al propio agente ni a los activos
# protegidos, porque ni siquiera puede construir el objetivo.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "confinar" ]; then
    printf '%s==>%s AegisConfine · confinamiento aprendido, ensayado y reversible\n' "$GRIS" "$FIN"
    if ./tools/verificar-confinar.sh > $LOGS/aegis-confinar-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-confinar-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-confinar-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisPosture (FASE 94): inventario de componentes (SBOM) con alcanzabilidad
# EN EJECUCION —cargado, alcanzable, expuesto, cada una tri-estado y sacada de
# la telemetria que el agente ya tiene— y postura de nube reconstruida de los
# eventos. Lo primero, el autoataque: el inventario es el mapa que un atacante
# querria, y no sale sin pasar por el juez de difusion. Despues, contra la
# maquina real: dpkg-query, objcopy, procesos compilados en la prueba, el
# presupuesto de memoria medido y un CycloneDX que lee otra herramienta.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "postura" ]; then
    printf '%s==>%s AegisPosture · SBOM con alcanzabilidad en ejecucion y postura de nube\n' "$GRIS" "$FIN"
    if ./tools/verificar-postura.sh > $LOGS/aegis-postura-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-postura-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-postura-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisStore (FASE 96): el almacen historico del plano de control, indexado por
# ENTIDAD y consultado con el MISMO AegisQL que el endpoint. Lo primero, la
# garantia de disponibilidad: una consulta que barreria demasiados dias sin
# acotar se rechaza antes de leer nada, y el error dice como arreglarla.
# Despues, contra PostgreSQL real, y la misma consulta contra el ejecutor real
# del endpoint y contra el almacen.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "almacen" ]; then
    printf '%s==>%s AegisStore · almacen historico por entidad con AegisQL de coste declarado\n' "$GRIS" "$FIN"
    if ./tools/verificar-almacen.sh > $LOGS/aegis-almacen-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-almacen-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-almacen-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisFlow (FASE 97): la automatizacion de respuesta. Lo primero, el autoataque:
# los flujos que un error de plantilla escribiria para dejar a la organizacion
# sin red, contra mil maquinas en PostgreSQL real, detenidos por los frenos. Y
# lo que no compila, leyendo el error real del compilador de cada caso.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "flujo" ]; then
    printf '%s==>%s AegisFlow · flujos tipados y transaccionales con los cinco frenos por paso\n' "$GRIS" "$FIN"
    if ./tools/verificar-flujo.sh > $LOGS/aegis-flujo-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-flujo-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-flujo-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisKnowledge (FASE 98): el grafo de conocimiento STIX 2.1 unido a lo
# observado. Lo primero, el autoataque: una relacion falsa inyectada por un
# canal se aisla por su procedencia y se revierte revocandolo, sin tirar lo que
# sostenian los demas. Despues, ATT&CK entero de ida y vuelta, la hipotesis que
# no se puede hacer pasar por un hecho, y la comparativa medida con OpenCTI.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "conocimiento" ]; then
    printf '%s==>%s AegisKnowledge · grafo STIX 2.1 unido a lo observado, con inferencia explicable\n' "$GRIS" "$FIN"
    if ./tools/verificar-conocimiento.sh > $LOGS/aegis-conocimiento-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-conocimiento-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-conocimiento-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisRange (FASE 99): emulacion de adversario y medida de cobertura de deteccion.
# Contra Caldera y Atomic Red Team, que ejecutan la tecnica y dejan que TU mires;
# aqui el ciclo se cierra automatico: se ejecuta una emulacion BENIGNA y REVERSIBLE
# en un rango declarado, se pregunta al arbitro real por la entidad afectada, y si
# no hubo veredicto se DICE como hueco de cobertura con el nombre de la tecnica.
# Solo en el rango y reversion obligatoria son garantias POR TIPO (compile_fail); el
# informe tiene tres estados y no infla una «no aplicable» como detectada.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "rango" ]; then
    printf '%s==>%s AegisRange · emulacion de adversario y cobertura de deteccion medida\n' "$GRIS" "$FIN"
    if ./tools/verificar-rango.sh > $LOGS/aegis-rango-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-rango-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-rango-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# El tejido que convierte nueve subsistemas en un producto (AegisFabric, FASE 79):
# un solo modelo de entidad, una sola escala, un solo arbitro y un solo linaje. Lo
# que se comprueba aqui es lo que NINGUNA puerta de subsistema puede comprobar: la
# UNION. Once subsistemas encadenados —paquete, diseccion, fichero extraido, corpus
# mundial, microVM, arbitro, caso, enriquecimiento, camino de ataque, contencion,
# TAXII y enjambre— sobre UN SOLO identificador de entidad, con el codigo real de
# cada uno. Mas el inventario de veredictos recorrido, la ruta caliente medida
# contra el criterio de antes, y la comprobacion de que el arbol de dependencias
# del endpoint no crece ni un crate.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "fabric" ]; then
    printf '%s==>%s AegisFabric · un solo modelo de entidad, un solo veredicto\n' "$GRIS" "$FIN"
    if ./tools/verificar-fabric.sh > $LOGS/aegis-fabric-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-fabric-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-fabric-ci.log | tail -40
        FALLOS=$((FALLOS + 1))
    fi
fi

# Forense de memoria a escala (RAM YARA, FASE 57): el nucleo —chunks con
# solapamiento, YARA real, filtro existencial de AegisQL— se prueba en "Rust ·
# tests". Aqui se re-ejercita y se DECLARA el muro: leer memoria fisica/ajena
# necesita privilegios/driver, y el estrangulado real lo pone el SO (cgroups).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "memhunt" ]; then
    printf '%s==>%s RAM YARA · forense de memoria a escala (nucleo probado; lectura fisica gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-memscanner.sh > $LOGS/aegis-memscanner-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-memscanner-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-memscanner-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Introspeccion de Ring -1 (VMI + EPT, FASE 54): el nucleo —estructuras EPT con
# ABI verificada, recorrido de tablas, clasificacion de violaciones, parser del
# kernel desde memoria fisica, deteccion de procesos ocultos por vista cruzada—
# se prueba en "Rust · tests". Aqui se comprueba que la fontaneria en vivo sobre
# KVM COMPILA y se declara el muro: arrancar el hipervisor necesita VT-x/AMD-V.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "vmi" ]; then
    printf '%s==>%s VMI Ring -1 · introspeccion por EPT (nucleo probado; hipervisor gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-vmi.sh > $LOGS/aegis-vmi-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-vmi-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-vmi-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Resiliencia empresarial (autodefensa ELAM/PPL + tamper crypto, FASE 60): el
# nucleo —traducir una senal de parada del SO a su operacion protegida, verificar
# y consumir el OTP hibrido del Control Plane, decidir permitir/denegar, y los
# contratos de ABI de Windows (BDCB_*/PS_PROTECTION) con tamano y codigos reales
# del WDK verificados en compilacion— se prueba en "Rust · tests". Aqui se
# re-ejercita y se DECLARA el muro: la puesta en vivo (registrar el callback ELAM,
# que el kernel conceda PPL, imponer un SIGKILL) necesita Windows + WDK + cert AM.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "resiliencia" ]; then
    printf '%s==>%s Resiliencia · autodefensa ELAM/PPL + tamper crypto (nucleo probado; puesta en vivo gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-resiliencia.sh > $LOGS/aegis-resiliencia-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-resiliencia-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-resiliencia-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisHPC (telemetria de la PMU, FASE 61): el nucleo —aprender la linea base por
# EWMA y decidir si un pico de fallos de cache es canal lateral o un pico de
# fallos de prediccion de saltos es ROP/JOP— se prueba en "Rust · tests". Aqui se
# re-ejercita y se DECLARA el muro: LEER la PMU en vivo necesita que el hardware
# la exponga, y este runner (microVM) no lo hace (perf_event_open -> ENOENT).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "hardsense" ]; then
    printf '%s==>%s AegisHPC · telemetria PMU anti canal-lateral/ROP (nucleo probado; PMU en vivo gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-hardsense.sh > $LOGS/aegis-hardsense-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-hardsense-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-hardsense-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# AegisCloudNative (escape de contenedor, FASE 62): el nucleo —reconocer los
# patrones de escape (release_agent/core_pattern, montaje del disco del host,
# setns al host, bpf en contenedor, unshare(NEWUSER)+mount) y NO marcar las mismas
# syscalls en el host— se prueba en "Rust · tests". Aqui se re-ejercita y se
# DECLARA el muro: enganchar esas syscalls en vivo es un eBPF en el kernel (BTF,
# privilegios, bytecode cargado).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "cloudnative" ]; then
    printf '%s==>%s AegisCloudNative · escape de contenedor (nucleo probado; enganche eBPF gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-cloudnative.sh > $LOGS/aegis-cloudnative-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-cloudnative-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-cloudnative-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Flota: la pila de gestion de flota (mTLS mutuo, certificados rotativos, claves
# en memoria) es criptografia de espacio de usuario y opera en cualquier maquina;
# el informe lo confirma donde corre la puerta de calidad.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "fleet" ]; then
    printf '%s==>%s Flota · gestion sobre gRPC/mTLS con certificados rotativos\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-fleet --example fleet_support > $LOGS/aegis-fleet.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-fleet.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-fleet.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

paso docs  "Docs · enlaces relativos"   ./tools/check-links.sh
# El fichero de cadenas cifradas (FASE 13) tiene que estar al dia respecto al
# manifiesto: si alguien cambia una cadena critica y no regenera, el binario
# llevaria en claro lo que deberia ir cifrado. Solo aplica si hay python3.
if command -v python3 >/dev/null 2>&1; then
    paso harden "Blindaje · cadenas cifradas al dia" python3 tools/obfuscate.py --check
else
    printf '%s==>%s Blindaje · %somitido (sin python3)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
fi

# El presupuesto de recursos es un compromiso del producto (ver README), no una
# aspiracion. Un componente que se lo salta es un bug atribuible, y por eso se
# mide en la misma puerta que el resto.
#
# Ya no es un numero fijo comparado durante cuatro segundos. Son TRES regimenes
# repartidos como fraccion de la RAM del host, DOS puertas (el presupuesto del
# host, que escala, y la linea base de arranque, que no escala y es la que caza
# la regresion) y TRES capas que lo obligan, de las cuales la ultima es el kernel
# via cgroup v2 y no depende de que el agente se porte bien.
if [ -n "${SOLO:-}" ] && [ "$SOLO" != "budget" ]; then :; else
    printf '%s==>%s Presupuesto de memoria del agente\n' "$GRIS" "$FIN"
    if ./tools/verificar-presupuesto.sh > $LOGS/aegis-presupuesto-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-presupuesto-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-presupuesto-ci.log | tail -25
        FALLOS=$((FALLOS + 1))
    fi
fi

# Simulacion de Red Team (FASE 17): ataques reales contra las defensas. Es el
# ultimo paso porque necesita los binarios de ejemplo compilados y ejercita el
# sistema entero. Requiere python3 y un compilador de C para la victima de
# inyeccion; si faltan, se omite en vez de fallar.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "redteam" ]; then
    if command -v python3 >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
        printf '%s==>%s Red Team · simulacion de ataques\n' "$GRIS" "$FIN"
        cargo build -q -p aegis-evasion --example scan_pid 2>/dev/null
        cargo build -q -p aegis-ransom --example honeypot_probe 2>/dev/null
        cargo build -q -p aegis-sandbox --example escape_attempt 2>/dev/null
        cargo build -q -p aegis-deception --example decoy_sting 2>/dev/null
        cargo build -q -p aegis-forensics --example incident_capture 2>/dev/null
        cargo build -q -p aegis-mesh --example mesh_node 2>/dev/null
        cargo build -q -p aegis-kintegrity --example dkom_probe 2>/dev/null
        cargo build -q -p aegis-firmware --example bootkit_probe 2>/dev/null
        cargo build -q -p aegis-unpacker --example unpack_probe 2>/dev/null
        cargo build -q -p aegis-syscallguard --example syscall_probe 2>/dev/null
        cargo build -q -p aegis-fleet --example fleet_probe 2>/dev/null
        make -C drivers/linux/aegis-bpf build sign >/dev/null 2>&1 || true
        if python3 tests/red_team_sim.py > $LOGS/aegis-redteam.log 2>&1; then
            printf '    %sOK%s\n' "$VERDE" "$FIN"
        else
            printf '    %sFALLO%s\n' "$ROJO" "$FIN"
            sed 's/^/    | /' $LOGS/aegis-redteam.log | tail -30
            FALLOS=$((FALLOS + 1))
        fi
    else
        printf '%s==>%s Red Team · %somitido (sin python3 o sin cc)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
    fi
fi

# LAS QUINCE INVARIANTES sobre el producto COMPLETO (AegisProof, FASE 80).
#
# Va la ULTIMA a proposito: comprueba lo que se rompe al sumar, y para eso todo lo
# demas tiene que haber corrido ya. Cada verificar-<fase>.sh comprueba lo suyo y lo
# comprueba mejor que esta; lo que ninguna puede comprobar es que el agente siga
# cabiendo en su presupuesto con TODAS las capacidades encendidas a la vez, que
# ningun crate de analisis haya ganado un `unsafe` por el camino, que el arbol de
# dependencias del endpoint no haya engordado sin justificacion escrita, y que el
# producto entero —no solo el enjambre— siga protegiendo con el plano de control
# caido.
#
# Y tiene DERECHO DE VETO: si demuestra que una invariante se rompio, se arregla de
# raiz antes de dar el trabajo por terminado, aunque obligue a volver sobre una
# fase anterior. Una invariante que se relaja «solo esta vez» deja de ser una
# invariante y pasa a ser una aspiracion.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "invariantes" ]; then
    printf '%s==>%s AegisProof · las dieciseis invariantes sobre el producto completo\n' "$GRIS" "$FIN"
    if ./tools/verificar-invariantes.sh > $LOGS/aegis-invariantes-ci.log 2>&1; then
        sed 's/^/    | /' $LOGS/aegis-invariantes-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' $LOGS/aegis-invariantes-ci.log
        FALLOS=$((FALLOS + 1))
    fi
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%sTodas las comprobaciones pasan.%s\n' "$VERDE" "$FIN"
    exit 0
fi
printf '%s%d grupo(s) de comprobaciones han fallado.%s\n' "$ROJO" "$FALLOS" "$FIN"
exit 1
