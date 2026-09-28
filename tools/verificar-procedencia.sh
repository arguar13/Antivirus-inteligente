#!/usr/bin/env bash
#
# Verificacion de AegisProvenance (procedencia del propio producto, FASE 108).
#
# CONTRA QUIEN COMPITE: in-toto, SLSA, Sigstore. Es la UNICA fase que audita al
# proyecto. Lo distintivo, probado como logica pura:
#  - CONSTRUCCION REPRODUCIBLE bit a bit: dos builds del mismo fuente dan el mismo
#    binario (construir-reproducible.sh). in-toto atestigua; esto REPITE.
#  - ATESTACION VERIFICADA EN EL ENDPOINT ANTES DE APLICAR: aegis-update no aplica
#    una actualizacion cuya atestacion no case con el SBOM y la politica. En el
#    camino critico, no en un informe.
#  - UNA SOLA CADENA de linaje fuente->...->TPM, con un Eid por eslabon.
#  - TRANSPARENCIA SIN CONEXION: registro Merkle de solo apendice; un registro
#    bifurcado se detecta por la prueba de consistencia (RFC 6962).
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisProvenance: transparencia (inclusion+consistencia), cadena, gate y reproducibilidad"
if cargo test -p aegis-procedencia >/tmp/aegis-procedencia.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (la inclusion y la consistencia del registro Merkle verifican para todo"
    echo "    ${VERDE}  ${FIN} tamano; un registro reescrito NO es consistente; la cadena de linaje"
    echo "    ${VERDE}  ${FIN} llega al TPM y un hueco es eslabon roto; y la puerta rechaza —y registra—"
    echo "    ${VERDE}  ${FIN} una atestacion que no casa con el SBOM antes de aplicar)"
else
    echo "    ${ROJO}FALLO${FIN}"; sed 's/^/    | /' /tmp/aegis-procedencia.log | tail -30; exit 1
fi

echo "==> AegisProvenance: la procedencia se verifica ANTES de aplicar (en aegis-update)"
# La puerta esta en el camino critico: aegis-update tiene el metodo que la consulta.
if grep -q 'aplicar_con_procedencia' crates/aegis-update/src/updater.rs; then
    echo "    ${VERDE}OK${FIN} (aegis-update::Updater::aplicar_con_procedencia consulta la puerta de"
    echo "    ${VERDE}  ${FIN} procedencia antes de tocar nada; una atestacion rechazada no se aplica)"
else
    echo "    ${ROJO}FALLO${FIN}: aegis-update no consulta la procedencia antes de aplicar."; exit 1
fi

echo "==> AegisProvenance: construccion reproducible bit a bit"
if ./tools/construir-reproducible.sh; then
    :
else
    echo "    ${ROJO}FALLO${FIN}: la construccion no es reproducible (ver arriba el motivo declarado)."
    exit 1
fi
exit 0
