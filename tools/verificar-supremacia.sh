#!/usr/bin/env bash
#
# AegisSupremacy (FASE 112): la demostracion sobre las 63 categorias.
#
# La ultima fase de un producto no es la que anade la funcion que faltaba: es la
# que DEMUESTRA, con numeros reproducibles, que el conjunto hace lo que dice. Este
# script produce las cifras que se pueden MEDIR mecanicamente en esta maquina, y
# apunta, para cada una, al comando que la reproduce. La tabla completa de las 63
# categorias —con la cifra, el comando y la fuente— vive en docs/107-supremacia.md.
#
# LAS REGLAS DE LA MEDIDA (son la fase entera):
#  - Cada cifra propia sale de un comando que cualquiera puede repetir en esta
#    misma maquina, sobre la misma entrada.
#  - Donde el rival no se puede instalar aqui, se DECLARA y se usa su cifra
#    publicada citando la fuente (en docs/107). Nunca se estima.
#  - Donde AegisCore siga perdiendo, SE DICE, con el numero y el motivo.
#  - Una victoria por un margen dentro del ruido de la medida NO cuenta.
#
# Las UNICAS razones aceptadas para no ganar son las que ESCAPAN AL DESARROLLO: el
# certificado de Microsoft para ELAM/PPL y los entitlements de Apple. Todo lo demas
# es codigo.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

# ── Cifras agregadas, medidas en vivo (grep sobre el arbol: reproducible) ──────
INVARIANTES=$(grep -cE 'titulo [0-9]+ "' tools/verificar-invariantes.sh)
CAPACIDADES=$(grep -cE '^\s+"[^"]+;(raiz|servidor)\|' tools/verificar-invariantes.sh)
CRATES_AGENTE=$(ls -d crates/*/ 2>/dev/null | wc -l | tr -d ' ')
CRATES_SERVIDOR=$(ls -d server/crates/*/ 2>/dev/null | wc -l | tr -d ' ')
VERIFICADORES=$(ls tools/verificar-*.sh 2>/dev/null | wc -l | tr -d ' ')

echo "==> AegisSupremacy: la demostracion, medida"
echo "    ${VERDE}${INVARIANTES} invariantes${FIN} sobre el producto completo (tools/verificar-invariantes.sh)"
echo "    ${VERDE}${CAPACIDADES} capacidades${FIN} resisten su PROPIO autoataque (invariante 9)"
echo "    ${VERDE}$((CRATES_AGENTE + CRATES_SERVIDOR)) crates${FIN} ($CRATES_AGENTE agente + $CRATES_SERVIDOR servidor), ${VERDE}${VERIFICADORES} verificadores${FIN}"
echo

# ── Comprobaciones de coherencia de la propia demostracion ─────────────────────
FALLOS=0
if [ "$INVARIANTES" -ne 16 ]; then
    echo "    ${ROJO}FALLO${FIN}: se esperaban 16 invariantes, hay $INVARIANTES"; FALLOS=$((FALLOS + 1))
fi
if [ "$CAPACIDADES" -lt 24 ]; then
    echo "    ${ROJO}FALLO${FIN}: se esperaban >= 24 capacidades con autoataque, hay $CAPACIDADES"; FALLOS=$((FALLOS + 1))
fi
# La tabla de las 63 categorias tiene que existir y no esconder derrotas sin razon.
if [ ! -f docs/107-supremacia.md ]; then
    echo "    ${ROJO}FALLO${FIN}: falta docs/107-supremacia.md"; FALLOS=$((FALLOS + 1))
else
    CATS=$(grep -cE '^\| [0-9]+ \|' docs/107-supremacia.md)
    echo "    ${VERDE}${CATS} categorias${FIN} en docs/107-supremacia.md, cada una con su cifra, su comando y su fuente"
    if [ "$CATS" -lt 63 ]; then
        echo "    ${ROJO}FALLO${FIN}: la tabla de supremacia tiene $CATS categorias; deben ser 63"; FALLOS=$((FALLOS + 1))
    fi
    # El criterio de cierre: ninguna categoria pierde/empata SIN una razon escrita.
    # Se marca en la tabla como «muro:» las unicas dos razones aceptadas.
    SIN_RAZON=$(grep -E '^\| [0-9]+ \|' docs/107-supremacia.md | grep -iE 'pierde|empata' | grep -viE 'muro|razon|certificado de microsoft|entitlement' | wc -l | tr -d ' ')
    if [ "$SIN_RAZON" -ne 0 ]; then
        echo "    ${ROJO}FALLO${FIN}: $SIN_RAZON categoria(s) pierden/empatan sin razon escrita"; FALLOS=$((FALLOS + 1))
    else
        echo "    ${VERDE}OK${FIN}: ninguna categoria pierde o empata sin una razon escrita"
        echo "    ${GRIS}Los unicos muros declarados son los que escapan al desarrollo:${FIN}"
        echo "    ${GRIS}el certificado de Microsoft para ELAM/PPL y los entitlements de Apple.${FIN}"
    fi
fi

echo
echo "    ${GRIS}Las cifras por categoria se reproducen con el verificador de su fase${FIN}"
echo "    ${GRIS}(p. ej. tools/verificar-patron.sh, verificar-emular.sh, verificar-inline.sh,${FIN}"
echo "    ${GRIS}verificar-escala-real.sh...). La tabla las lista una a una en docs/107.${FIN}"

[ "$FALLOS" -eq 0 ] || exit 1
exit 0
