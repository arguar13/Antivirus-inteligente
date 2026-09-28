#!/usr/bin/env bash
#
# Verificacion de AegisL7Hunter (inspeccion L7 de TLS por uprobes, FASE 66).
# Informa SIEMPRE de que se pudo ejercer y que no.
#
# QUE SE PRUEBA DE VERDAD AQUI
# ----------------------------
# Casi todo, y contra infraestructura real:
#
#  1. Los NUEVE programas eBPF ante el VERIFICADOR REAL del kernel. En eBPF
#     compilar no demuestra nada: el verificador rechaza programas que compilan
#     limpios (copias sin acotar desde memoria de usuario, bucles que no puede
#     probar que terminan). Esa es la prueba.
#  2. El ABI del evento, cotejado C<->Rust con los DOS compiladores. Un campo
#     desplazado no rompe la compilacion: hace que el analizador lea el pid donde
#     hay una longitud. El sintoma en produccion no es un fallo, es un EDR que
#     procesa basura y no detecta nada.
#  3. La resolucion del objetivo del uprobe contra los BINARIOS REALES de esta
#     maquina, incluida la OpenSSL de verdad y los ejecutables no-PIE, que son los
#     que distinguen la traduccion correcta de direccion a desplazamiento de la
#     ingenua.
#  4. La matematica de balizas, con la cota teorica comprobada para todo el rango
#     de jitter y para suenos de 0,5 s a 1 h.
#  5. La inferencia ONNX real sobre sesiones sinteticas construidas segun el
#     comportamiento documentado de los frameworks de C2.
#
# EL MURO: enganchar el uprobe en un proceso vivo que hable TLS y leer su texto
# plano. Necesita CAP_BPF/CAP_PERFMON y un proceso victima real con una sesion TLS
# en curso. NO se hace aqui, y se dice.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisL7Hunter: resolucion del objetivo del uprobe (ELF real de esta maquina)"
if cargo test -p aegis-l7hunter --quiet -- elf:: objetivo:: >/tmp/aegis-l7-elf.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (SSL_read/SSL_write localizados en la OpenSSL real; la traduccion"
    echo "    ${VERDE}  ${FIN} vaddr -> desplazamiento verificada contra TODOS los binarios de la maquina,"
    echo "    ${VERDE}  ${FIN} incluidos los no-PIE, donde la version ingenua se equivoca en 4 MiB)"
else
    echo "    ${ROJO}FALLO${FIN}: la resolucion del objetivo no pasa"
    sed 's/^/    | /' /tmp/aegis-l7-elf.log | tail -30
    exit 1
fi

echo "==> AegisL7Hunter: matematica de balizas y analisis L7"
if cargo test -p aegis-l7hunter --quiet -- baliza:: l7:: abi:: >/tmp/aegis-l7-mat.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (ninguna baliza con jitter uniforme supera CV = 2/raiz(12), comprobado"
    echo "    ${VERDE}  ${FIN} para J de 0 a 1; un corte de red no la esconde y un navegador a rafagas"
    echo "    ${VERDE}  ${FIN} no la imita; el parseo L7 no entra en panico con ninguna entrada hostil)"
else
    echo "    ${ROJO}FALLO${FIN}: la matematica de balizas o el analisis L7 no pasan"
    sed 's/^/    | /' /tmp/aegis-l7-mat.log | tail -30
    exit 1
fi

echo "==> AegisL7Hunter: clasificacion TinyML (inferencia ONNX real)"
if cargo test -p aegis-l7hunter --quiet -- modelo:: >/tmp/aegis-l7-ml.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (baliza con y sin jitter -> canal C2; un agente de monitorizacion, que"
    echo "    ${VERDE}  ${FIN} es IGUAL de periodico, -> benigno; un navegador -> benigno; un canal"
    echo "    ${VERDE}  ${FIN} binario de alta entropia -> sospechoso aunque no sea periodico)"
else
    echo "    ${ROJO}FALLO${FIN}: la clasificacion no pasa"
    sed 's/^/    | /' /tmp/aegis-l7-ml.log | tail -30
    exit 1
fi

echo "==> AegisL7Hunter: desplazamientos derivados (no adivinados), verificacion y redaccion (FASE 107)"
if cargo test -p aegis-l7hunter --quiet -- desplazamiento:: verificacion:: privacidad:: bibliotecas:: >/tmp/aegis-l7-107.log 2>&1 \
    && cargo test -p aegis-l7hunter --test autoataque --quiet >>/tmp/aegis-l7-107.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (el offset se DERIVA de la tabla/DWARF/BTF o del analisis del binario"
    echo "    ${VERDE}  ${FIN} —el producto se usa a si mismo—, y si no se puede es NoConcluyente, jamas"
    echo "    ${VERDE}  ${FIN} una lectura a ciegas; un gancho no verificado en caliente no se usa; y la"
    echo "    ${VERDE}  ${FIN} redaccion es OBLIGATORIA en el tipo —no hay texto sin redactar— con su"
    echo "    ${VERDE}  ${FIN} presupuesto de difusion (FASE 78). Cobertura declarada de 13 pilas TLS)"
else
    echo "    ${ROJO}FALLO${FIN}: la derivacion de offsets, la verificacion o la redaccion no pasan"
    sed 's/^/    | /' /tmp/aegis-l7-107.log | tail -30
    exit 1
fi

echo "==> AegisL7Hunter: ABI del evento, cotejado C <-> Rust"
fallo_abi=0
for compilador in gcc clang; do
    if command -v "$compilador" >/dev/null 2>&1; then
        if CC="$compilador" ./tools/abi-check-l7.sh >/tmp/aegis-l7-abi.log 2>&1; then
            echo "    ${VERDE}OK${FIN} ($compilador: $(grep -o '[0-9]* entradas' /tmp/aegis-l7-abi.log | head -1) de layout coinciden)"
        else
            echo "    ${ROJO}FALLO${FIN} ($compilador): el ABI del evento L7 ha divergido"
            sed 's/^/    | /' /tmp/aegis-l7-abi.log | tail -20
            fallo_abi=1
        fi
    else
        echo "    ${GRIS}$compilador no esta en esta maquina: cotejo omitido${FIN}"
    fi
done
[ "$fallo_abi" -eq 0 ] || exit 1

echo "==> AegisL7Hunter: los programas eBPF ante el verificador REAL del kernel"
if [ -f drivers/linux/aegis-bpf/Makefile ]; then
    if make -C drivers/linux/aegis-bpf build >/tmp/aegis-l7-bpf.log 2>&1; then
        if make -C drivers/linux/aegis-bpf verify >>/tmp/aegis-l7-bpf.log 2>&1; then
            n=$(grep -c 'OK  aegis_\(ssl\|gnutls\)' /tmp/aegis-l7-bpf.log || echo 0)
            echo "    ${VERDE}OK${FIN} ($n programas de uprobe cargados y aceptados por el verificador)"
        else
            echo "    ${ROJO}FALLO${FIN}: el verificador del kernel rechaza los programas"
            sed 's/^/    | /' /tmp/aegis-l7-bpf.log | tail -25
            exit 1
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: los programas eBPF no compilan"
        sed 's/^/    | /' /tmp/aegis-l7-bpf.log | tail -25
        exit 1
    fi
else
    echo "    ${GRIS}subproyecto eBPF no presente: omitido${FIN}"
fi

echo "==> AegisL7Hunter: ENGANCHE en un proceso vivo con TLS (muro)"
echo "    ${GRIS}NO ejercido aqui. Adjuntar el uprobe y leer el texto plano de un proceso ajeno${FIN}"
echo "    ${GRIS}necesita CAP_BPF/CAP_PERFMON y una victima real con una sesion TLS en curso.${FIN}"
echo "    ${GRIS}Lo que SI se comprueba arriba es todo lo que decide: donde enganchar (contra los${FIN}"
echo "    ${GRIS}binarios reales), que el kernel acepta los programas, que el evento se decodifica${FIN}"
echo "    ${GRIS}con el mismo layout en los dos lados, y que la clasificacion separa una baliza de${FIN}"
echo "    ${GRIS}un agente de monitorizacion, que es el falso positivo que de verdad importa.${FIN}"
exit 0
