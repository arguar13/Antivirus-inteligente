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

# Orquestador de remediacion (AI-RO, FASE 64): el nucleo —la maquina de estados
# transaccional que elige el playbook, lanza las acciones en paralelo, sobrevive a
# fallos parciales y es idempotente en el reintento— se prueba en "Servidor ·
# tests". Aqui se re-ejercita y se DECLARA el muro: la ejecucion REAL de cada
# accion (XDP, matar proceso, revocar ticket, volcado) ocurre en el agente contra
# un sistema real, por gRPC/mTLS.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "orchestrator" ]; then
    printf '%s==>%s AI-RO · orquestador de remediacion (nucleo probado; ejecucion en flota gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-orchestrator.sh > /tmp/aegis-orchestrator-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-orchestrator-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-orchestrator-ci.log | tail -20
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
    if ./tools/verificar-l7hunter.sh > /tmp/aegis-l7hunter-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-l7hunter-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-l7hunter-ci.log | tail -25
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
    if ./tools/verificar-memhunter.sh > /tmp/aegis-memhunter-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-memhunter-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-memhunter-ci.log | tail -20
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
    if ./tools/verificar-fwaudit.sh > /tmp/aegis-fwaudit-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-fwaudit-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-fwaudit-ci.log | tail -25
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
    if ./tools/verificar-swarm.sh > /tmp/aegis-swarm-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-swarm-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-swarm-ci.log | tail -25
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
    if ./tools/verificar-predict.sh > /tmp/aegis-predict-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-predict-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-predict-ci.log | tail -25
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
    if ./tools/verificar-wire.sh > /tmp/aegis-wire-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-wire-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-wire-ci.log | tail -25
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
    if ./tools/verificar-ips.sh > /tmp/aegis-ips-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-ips-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-ips-ci.log | tail -25
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
    if ./tools/verificar-ruleforge.sh > /tmp/aegis-ruleforge-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-ruleforge-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-ruleforge-ci.log | tail -25
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
    if ./tools/verificar-detonate.sh > /tmp/aegis-detonate-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-detonate-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-detonate-ci.log | tail -30
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
    if ./tools/verificar-scale.sh > /tmp/aegis-scale-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-scale-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-scale-ci.log | tail -30
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
    if ./tools/verificar-ingest.sh > /tmp/aegis-ingest-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-ingest-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-ingest-ci.log | tail -30
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
    if ./tools/verificar-case.sh > /tmp/aegis-case-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-case-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-case-ci.log | tail -30
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
    if ./tools/verificar-enrich.sh > /tmp/aegis-enrich-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-enrich-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-enrich-ci.log | tail -30
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
    if ./tools/verificar-share.sh > /tmp/aegis-share-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-share-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-share-ci.log | tail -30
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
    if ./tools/verificar-estado.sh > /tmp/aegis-estado-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-estado-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-estado-ci.log | tail -30
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
    if ./tools/verificar-custodia.sh > /tmp/aegis-custodia-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-custodia-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-custodia-ci.log | tail -30
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
    if ./tools/verificar-pe.sh > /tmp/aegis-pe-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-pe-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-pe-ci.log | tail -30
        FALLOS=$((FALLOS + 1))
    fi
fi

# LAS TRECE INVARIANTES sobre el producto COMPLETO (AegisProof, FASE 80).
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
    printf '%s==>%s AegisProof · las trece invariantes sobre el producto completo\n' "$GRIS" "$FIN"
    if ./tools/verificar-invariantes.sh > /tmp/aegis-invariantes-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-invariantes-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-invariantes-ci.log
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
    if ./tools/verificar-fabric.sh > /tmp/aegis-fabric-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-fabric-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-fabric-ci.log | tail -40
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

# Introspeccion de Ring -1 (VMI + EPT, FASE 54): el nucleo —estructuras EPT con
# ABI verificada, recorrido de tablas, clasificacion de violaciones, parser del
# kernel desde memoria fisica, deteccion de procesos ocultos por vista cruzada—
# se prueba en "Rust · tests". Aqui se comprueba que la fontaneria en vivo sobre
# KVM COMPILA y se declara el muro: arrancar el hipervisor necesita VT-x/AMD-V.
if [ -z "${SOLO:-}" ] || [ "$SOLO" = "vmi" ]; then
    printf '%s==>%s VMI Ring -1 · introspeccion por EPT (nucleo probado; hipervisor gated)\n' "$GRIS" "$FIN"
    if ./tools/verificar-vmi.sh > /tmp/aegis-vmi-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-vmi-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-vmi-ci.log | tail -20
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
    if ./tools/verificar-resiliencia.sh > /tmp/aegis-resiliencia-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-resiliencia-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-resiliencia-ci.log | tail -20
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
    if ./tools/verificar-hardsense.sh > /tmp/aegis-hardsense-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-hardsense-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-hardsense-ci.log | tail -20
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
    if ./tools/verificar-cloudnative.sh > /tmp/aegis-cloudnative-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-cloudnative-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-cloudnative-ci.log | tail -20
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
#
# Ya no es un numero fijo comparado durante cuatro segundos. Son TRES regimenes
# repartidos como fraccion de la RAM del host, DOS puertas (el presupuesto del
# host, que escala, y la linea base de arranque, que no escala y es la que caza
# la regresion) y TRES capas que lo obligan, de las cuales la ultima es el kernel
# via cgroup v2 y no depende de que el agente se porte bien.
if [ -n "${SOLO:-}" ] && [ "$SOLO" != "budget" ]; then :; else
    printf '%s==>%s Presupuesto de memoria del agente\n' "$GRIS" "$FIN"
    if ./tools/verificar-presupuesto.sh > /tmp/aegis-presupuesto-ci.log 2>&1; then
        sed 's/^/    | /' /tmp/aegis-presupuesto-ci.log
        printf '    %sOK%s\n' "$VERDE" "$FIN"
    else
        printf '    %sFALLO%s\n' "$ROJO" "$FIN"
        sed 's/^/    | /' /tmp/aegis-presupuesto-ci.log | tail -25
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
