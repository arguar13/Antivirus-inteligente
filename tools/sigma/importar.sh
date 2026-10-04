#!/usr/bin/env bash
#
# Importa el subconjunto Linux del catalogo publico SigmaHQ al contenido del
# agente (FASE 4 del MP-16, paso 3: contenido).
#
# POR QUE ASI:
#   - FIJADO A UN COMMIT (tools/sigma/COMMIT). El contenido de deteccion es
#     codigo que decide en cada endpoint: se importa una version concreta, que
#     una persona fijo, y no «lo ultimo». Se comprueba que la etiqueta de la
#     release sigue apuntando a ese commit y que el checkout es exactamente el.
#   - FILTRA CON EL CODIGO DEL AGENTE. La decision de que entra la toma el
#     ejemplo `importar` de aegis-sigma, que usa el mismo `Juego::cargar` que el
#     agente y la misma puerta de eventos generados. Lo que usa `|re`, un campo
#     que la telemetria no produce, un servicio (auditd...) o una categoria que
#     no tenemos, se descarta CON MOTIVO en reglas/linux/INFORME-IMPORTACION.
#   - LICENCIA Y ATRIBUCION. SigmaHQ publica sus reglas bajo la Detection Rule
#     License 1.1, que pide conservar el autor, enlazar el origen e incluir el
#     texto de la licencia. Las reglas se copian SIN CAMBIOS (autor, id,
#     referencias); el texto de la DRL 1.1 va al lado (LICENCIA-DRL-1.1.md, de
#     su repositorio, fijado tambien en COMMIT) y reglas/linux/ATRIBUCION lista
#     fichero, id, titulo, autor y ruta de origen con el commit. Sin la licencia
#     no se importa nada.
#   - TODO O NADA. Se genera en un directorio temporal y solo si sale bien se
#     sustituye el contenido del repositorio.
#
# Uso:   tools/sigma/importar.sh            (necesita red, git y cargo)
# Salida: crates/aegis-sigma/reglas/linux/{*.yml,PRESUPUESTOS,ATRIBUCION,
#         INFORME-IMPORTACION,LICENCIA-DRL-1.1.md} y crates/aegis-sigma/src/incluidas.rs
#
# Despues: revisar PRESUPUESTOS (las lineas nuevas salen del nivel de la regla),
# `git add` de crates/aegis-sigma/reglas/linux y pasar tools/verificar-sigma.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."

FIJADO=tools/sigma/COMMIT
dato() { # clave -> valor de tools/sigma/COMMIT (se lee, no se ejecuta)
    sed -n "s/^$1=//p" "$FIJADO" | head -1 | tr -d '[:space:]'
}
SIGMA_REPO="${SIGMA_REPO:-https://github.com/SigmaHQ/sigma.git}"
DRL_REPO="${DRL_REPO:-https://github.com/SigmaHQ/Detection-Rule-License.git}"
COMMIT="$(dato SIGMA_COMMIT)"
ETIQUETA="$(dato SIGMA_ETIQUETA)"
DRL_COMMIT="$(dato DRL_COMMIT)"
for par in "SIGMA_COMMIT:$COMMIT" "DRL_COMMIT:$DRL_COMMIT"; do
    if ! printf '%s' "${par#*:}" | grep >/dev/null -E '^[0-9a-f]{40}$'; then
        echo "importar: $FIJADO: ${par%%:*} no es un commit completo (40 hex): «${par#*:}»." >&2
        echo "          Lo fija una persona; no se importa «lo ultimo»." >&2
        exit 2
    fi
done
if [ -z "$ETIQUETA" ]; then
    echo "importar: $FIJADO: falta SIGMA_ETIQUETA" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

traer() { # repo commit destino
    git init -q "$3"
    git -C "$3" remote add origin "$1"
    git -C "$3" fetch -q --depth 1 origin "$2"
    git -C "$3" checkout -q FETCH_HEAD
    local real
    real="$(git -C "$3" rev-parse HEAD)"
    if [ "$real" != "$2" ]; then
        echo "importar: el checkout de $1 es $real y no $2" >&2
        exit 1
    fi
}

# La etiqueta de la release tiene que seguir apuntando al commit fijado: si la
# movieron, el commit fijado ya no es «la release ETIQUETA» y lo decide una
# persona, no este script.
APUNTA="$(git ls-remote "$SIGMA_REPO" "refs/tags/$ETIQUETA^{}" | awk '{print $1}')"
[ -n "$APUNTA" ] || APUNTA="$(git ls-remote "$SIGMA_REPO" "refs/tags/$ETIQUETA" | awk '{print $1}')"
if [ "$APUNTA" != "$COMMIT" ]; then
    echo "importar: la etiqueta $ETIQUETA apunta a «$APUNTA», no a $COMMIT" >&2
    exit 1
fi

traer "$SIGMA_REPO" "$COMMIT" "$TMP/sigma"
traer "$DRL_REPO" "$DRL_COMMIT" "$TMP/drl"

# La estructura que el importador supone. Si cambia, se para con el motivo.
for d in rules/linux rules/linux/process_creation rules/linux/file_event rules/linux/network_connection; do
    [ -d "$TMP/sigma/$d" ] || { echo "importar: el commit $COMMIT no tiene $d" >&2; exit 1; }
done
grep -q 'Detection Rule License (DRL) 1.1' "$TMP/sigma/LICENSE" 2> /dev/null \
    || { echo "importar: el LICENSE de SigmaHQ en $COMMIT no declara la DRL 1.1" >&2; exit 1; }
LICENCIA="$TMP/drl/LICENSE.Detection.Rules.md"
head -1 "$LICENCIA" 2> /dev/null | grep >/dev/null 'Detection Rule License (DRL) 1.1' \
    || { echo "importar: $DRL_REPO@$DRL_COMMIT no trae el texto de la DRL 1.1" >&2; exit 1; }

# Se genera aparte. Los presupuestos que ya reviso una persona se conservan.
DESTINO=crates/aegis-sigma
mkdir -p "$TMP/salida/reglas/linux" "$TMP/salida/src"
[ -f "$DESTINO/reglas/linux/PRESUPUESTOS" ] \
    && cp "$DESTINO/reglas/linux/PRESUPUESTOS" "$TMP/salida/reglas/linux/PRESUPUESTOS"
cargo run -q --locked -p aegis-sigma --example importar -- \
    "$TMP/sigma" "$LICENCIA" "$COMMIT" "$ETIQUETA" "$DRL_COMMIT" "$TMP/salida"
rustfmt --edition 2021 "$TMP/salida/src/incluidas.rs"

rm -rf "$DESTINO/reglas/linux"
mkdir -p "$DESTINO/reglas"
cp -r "$TMP/salida/reglas/linux" "$DESTINO/reglas/linux"
cp "$TMP/salida/src/incluidas.rs" "$DESTINO/src/incluidas.rs"

echo "importar: informe en $DESTINO/reglas/linux/INFORME-IMPORTACION"
sed -n '1,20p' "$DESTINO/reglas/linux/INFORME-IMPORTACION"
