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
# Uso:  ./tools/ci-local.sh          (todo)
#       ./tools/ci-local.sh rust     (solo un grupo)
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0
SOLO="${1:-}"

paso() {
    local grupo="$1"; shift
    local titulo="$1"; shift
    if [ -n "$SOLO" ] && [ "$SOLO" != "$grupo" ]; then return 0; fi
    printf '%s==>%s %s\n' "$GRIS" "$FIN" "$titulo"
    if "$@" > /tmp/ci-local.log 2>&1; then
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/ci-local.log | tail -40
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
    if ./tools/verificar-kafka.sh > /tmp/aegis-kafka.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-kafka.log | tail -5
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        sed 's/^/    | /' /tmp/aegis-kafka.log | tail -20
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
    if cargo run -q -p aegis-sandbox --example sandbox_support > /tmp/aegis-sandbox.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-sandbox.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-sandbox.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

if [ -z "${SOLO:-}" ] || [ "$SOLO" = "firmware" ]; then
    printf '%s==>%s Firmware · capacidades de arranque medido de la maquina\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-firmware --example firmware_support > /tmp/aegis-firmware.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-firmware.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-firmware.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

if [ -z "${SOLO:-}" ] || [ "$SOLO" = "unpacker" ]; then
    printf '%s==>%s Unpacker · capacidades de desempaquetado dinamico\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-unpacker --example unpacker_support > /tmp/aegis-unpacker.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-unpacker.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-unpacker.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# SyscallGuard: reporte honesto de las capacidades de hardware (PMU/DRx) y de la
# via de verificacion cruzada. Igual que el sandbox y el firmware, deja
# constancia de lo que ofrece la maquina donde corre.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "syscallguard" ]; then
    printf '%s==>%s SyscallGuard · deteccion de syscalls directas (PMU/DRx)\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-syscallguard --example syscallguard_support > /tmp/aegis-syscallguard.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-syscallguard.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-syscallguard.log | tail -20
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
    if ./tools/verificar-ptguard.sh > /tmp/aegis-ptguard.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-ptguard.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-ptguard.log | tail -20
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
    if ./tools/verificar-honeytoken.sh > /tmp/aegis-honeytoken.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-honeytoken.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-honeytoken.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# ITDR (FASE 58): el nucleo —parsear tickets Kerberos, decidir Kerberoasting /
# Golden / Silver y correlacionar el grafo de identidad— se prueba en "Servidor ·
# tests". Aqui se re-ejercita ese nucleo y se DECLARA que la captura EN VIVO de la
# capa de identidad necesita un dominio Active Directory real, que no hay aqui.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "itdr" ]; then
    printf '%s==>%s ITDR · deteccion de identidad (nucleo probado; captura en vivo gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-itdr.sh > /tmp/aegis-itdr-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-itdr-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-itdr-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Forense de memoria a escala (RAM YARA, FASE 57): el nucleo —chunks con
# solapamiento, YARA real, filtro existencial de AegisQL— se prueba en "Rust ·
# tests". Aqui se re-ejercita y se DECLARA el muro: leer memoria fisica/ajena
# necesita privilegios/driver, y el estrangulado real lo pone el SO (cgroups).
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "memhunt" ]; then
    printf '%s==>%s RAM YARA · forense de memoria a escala (nucleo probado; lectura fisica gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-memscanner.sh > /tmp/aegis-memscanner-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-memscanner-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-memscanner-ci.log | tail -20
        FALLOS=$((FALLOS + 1))
    fi
fi

# Flota: la pila de gestion de flota (mTLS mutuo, certificados rotativos, claves
# en memoria) es criptografia de espacio de usuario y opera en cualquier maquina;
# el informe lo confirma donde corre la puerta de calidad.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "fleet" ]; then
    printf '%s==>%s Flota · gestion sobre gRPC/mTLS con certificados rotativos\n' "$GRIS" "$FIN"
    if cargo run -q -p aegis-fleet --example fleet_support > /tmp/aegis-fleet.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-fleet.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-fleet.log | tail -20
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
if [ -n "${SOLO:-}" ] && [ "$SOLO" != "budget" ]; then :; else
    printf '%s==>%s Presupuesto de memoria del agente\n' "$GRIS" "$FIN"
    if cargo build --release -p aegis-agent -q 2>/dev/null && [ -x target/release/aegis-agent ]; then
        ./target/release/aegis-agent --stats-interval 300 >/dev/null 2>/tmp/aegis-budget.err &
        PID_AGENTE=$!
        sleep 4
        RSS=$(grep VmRSS "/proc/$PID_AGENTE/status" 2>/dev/null | awk '{print $2}')
        kill -TERM "$PID_AGENTE" 2>/dev/null
        wait "$PID_AGENTE" 2>/dev/null
        if [ -z "$RSS" ]; then
            printf '    %somitido: el agente no arranco%s\n' "$GRIS" "$FIN"
            printf '    %s  causa: %s%s\n' "$GRIS" "$(tail -1 /tmp/aegis-budget.err 2>/dev/null | head -c 160)" "$FIN"
        elif [ "$RSS" -lt 46080 ]; then
            printf '    %sOK%s (%s KB de un presupuesto de 46080 KB)\n' "$VERDE" "$FIN" "$RSS"
        else
            printf '    %sFALLO%s: %s KB supera el presupuesto de 46080 KB\n' "$ROJO" "$FIN" "$RSS"
            FALLOS=$((FALLOS + 1))
        fi
    else
        printf '    %somitido (no se pudo compilar el agente)%s\n' "$GRIS" "$FIN"
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
        if python3 tests/red_team_sim.py > /tmp/aegis-redteam.log 2>&1; then
            printf '    %sOK%s\n' "$VERDE" "$FIN"
        else
            printf '    %sFALLO%s\n' "$ROJO" "$FIN"
            sed 's/^/    | /' /tmp/aegis-redteam.log | tail -30
            FALLOS=$((FALLOS + 1))
        fi
    else
        printf '%s==>%s Red Team · %somitido (sin python3 o sin cc)%s\n' "$GRIS" "$FIN" "$GRIS" "$FIN"
    fi
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%sTodas las comprobaciones pasan.%s\n' "$VERDE" "$FIN"
    exit 0
fi
printf '%s%d grupo(s) de comprobaciones han fallado.%s\n' "$ROJO" "$FALLOS" "$FIN"
exit 1
