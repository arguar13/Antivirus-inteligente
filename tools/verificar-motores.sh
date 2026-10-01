#!/usr/bin/env bash
#
# Verificacion del contrato unico de motor y del arbitro del agente (FASE 1 del
# MP-16).
#
# LA CAUSA RAIZ que cierra: el agente crecio por bibliotecas. Cada motor tenia su
# forma de recibir un evento y de decir lo que pensaba, se cableaba a mano en el
# bucle, sin presupuesto y sin forma de decir «no pude mirar», y el bucle
# imprimia escalados sin decidir nada. Sumar un motor era una ocasion de romper
# el presupuesto del agente sin que nadie lo notase.
#
# Lo que esta puerta sostiene:
#   1. el contrato y el arbitro hacen lo que dicen (pruebas de combinacion, de
#      presupuesto, de suspension y de SinDatos con causa), tambien con los
#      motores REALES del agente detras;
#   2. el arbitro es el UNICO punto de entrada: nadie en el agente llama a un
#      motor, ni combina veredictos, ni se salta el arbitro alimentando el
#      pipeline a mano;
#   3. todo crate de la capa de motores que el agente enlaza solo se toca desde
#      src/motores/, donde cada modulo implementa el contrato y se registra.
#      Los que aun no (PENDIENTES, abajo) estan declarados, y la lista solo puede
#      menguar.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0
AGENTE=crates/aegis-agent
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fallo() { echo "    ${ROJO}FALLO${FIN}: $1"; FALLOS=$((FALLOS + 1)); }

# Modulos del agente que envuelven un motor y AUN no entran por el contrato. Solo
# puede menguar. Ya salio el emulador (`microsandbox`), que ahora corre en el
# trabajador confinado; queda el modelo en el endpoint, que necesita la traza de
# comportamiento que construye la fase 2.
PENDIENTES=(
    "src/edge_ml.rs"
)

echo "==> Motores: el contrato y el arbitro"
if cargo test -q -p aegis-motor > "$TMP/motor.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/motor.log" | head -1))"
else
    fallo "cargo test -p aegis-motor"; sed 's/^/    | /' "$TMP/motor.log" | tail -30
fi

echo "==> Motores: los motores reales del agente detras del arbitro"
if cargo test -q -p aegis-agent --test arbitro > "$TMP/agente.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/agente.log" | head -1))"
else
    fallo "cargo test -p aegis-agent --test arbitro"; sed 's/^/    | /' "$TMP/agente.log" | tail -30
fi

echo "==> Motores: el arbitro es el unico punto de entrada"
ANTES=$FALLOS
if grep -rn 'arbitrar(' "$AGENTE/src" > "$TMP/x"; then
    fallo "el agente combina veredictos por su cuenta (solo el arbitro de aegis-motor combina):"
    sed 's/^/    | /' "$TMP/x"
fi
# Las pruebas UNITARIAS de un motor (su bloque `#[cfg(test)]`) si lo invocan: es
# el unico modo de mirar su estado interno. Se excluye exactamente ese bloque,
# contando llaves desde el atributo hasta que cierra, y no «desde ahi hasta el
# final del fichero»: una llamada de produccion escrita despues de las pruebas
# tiene que seguir saliendo aqui.
fuera_de_pruebas() {
    awk '
        /^[[:space:]]*#\[cfg\(test\)\]/ { prueba = 1; abierto = 0; prof = 0; next }
        {
            if (prueba) {
                n = gsub(/\{/, "{"); c = gsub(/\}/, "}")
                prof += n - c
                if (n > 0) abierto = 1
                if (abierto && prof <= 0) prueba = 0
                next
            }
            print FILENAME ":" FNR ":" $0
        }' "$@"
}
# La exclusion no puede tapar de mas: se comprueba sobre un fichero hecho a
# proposito, con una llamada de produccion DESPUES del bloque de pruebas.
cat > "$TMP/muerde.rs" <<'RS'
fn a() {}
#[cfg(test)]
mod pruebas {
    fn b() { m.evaluar(&e, &p); }
}
fn c() { m.evaluar(&e, &p); }
RS
if [ "$(fuera_de_pruebas "$TMP/muerde.rs" | grep -c '\.evaluar(')" != "1" ]; then
    fallo "la exclusion del bloque de pruebas tapa codigo de produccion (autocomprobacion)"
fi
if fuera_de_pruebas $(find "$AGENTE/src" -name '*.rs' | sort) | grep -E '\.evaluar\(' > "$TMP/x"; then
    fallo "el agente llama a un motor sin pasar por el arbitro:"
    sed 's/^/    | /' "$TMP/x"
fi
if grep -nE '\.(ingest|ingest_raw)\(' "$AGENTE/src/main.rs" > "$TMP/x"; then
    fallo "el bucle del agente alimenta el pipeline a mano, saltandose el arbitro:"
    sed 's/^/    | /' "$TMP/x"
fi
[ "$FALLOS" -eq "$ANTES" ] && echo "    ${VERDE}OK${FIN} (nadie llama a un motor, ni combina, ni se salta el arbitro)"

echo "==> Motores: los crates de deteccion solo entran por src/motores/"
python3 - "$AGENTE" "${PENDIENTES[@]}" > "$TMP/capa.txt" <<'PY'
import sys, tomllib, pathlib
agente = pathlib.Path(sys.argv[1])
capas = tomllib.load(open("tools/config/capas.toml", "rb"))
motores = set(capas["motores"]["crates"]) - {"aegis-motor"}
deps = tomllib.load(open(agente / "Cargo.toml", "rb")).get("dependencies", {})
for d in sorted(deps):
    if d in motores:
        print(d.replace("-", "_"))
PY
DEP_FALLOS=0
while read -r crate; do
    [ -n "$crate" ] || continue
    while IFS= read -r fichero; do
        rel="${fichero#"$AGENTE"/}"
        case "$rel" in
            src/motores/*) continue ;;
        esac
        pendiente=0
        for p in "${PENDIENTES[@]}"; do [ "$rel" = "$p" ] && pendiente=1; done
        if [ "$pendiente" -eq 0 ]; then
            fallo "$rel usa $crate fuera de src/motores/: un motor que no entra por el contrato"
            DEP_FALLOS=$((DEP_FALLOS + 1))
        fi
    done < <(grep -rlw "$crate" "$AGENTE/src" 2>/dev/null)
done < "$TMP/capa.txt"
for p in "${PENDIENTES[@]}"; do
    if [ ! -f "$AGENTE/$p" ] || ! grep -qwf "$TMP/capa.txt" "$AGENTE/$p"; then
        fallo "$p ya no envuelve un motor fuera del contrato: quitalo de PENDIENTES (la lista solo mengua)"
        DEP_FALLOS=$((DEP_FALLOS + 1))
    fi
done
[ "$DEP_FALLOS" -eq 0 ] && echo "    ${VERDE}OK${FIN} ($(wc -l < "$TMP/capa.txt") crate(s) de deteccion enlazados; ${#PENDIENTES[@]} modulo(s) pendiente(s), declarados)"

echo "==> Motores: cada modulo de src/motores/ implementa el contrato y se registra"
REG_FALLOS=0
for f in "$AGENTE"/src/motores/*.rs; do
    [ "$(basename "$f")" = "mod.rs" ] && continue
    if ! grep -qE 'impl (aegis_motor::)?Motor<' "$f"; then
        fallo "${f#"$AGENTE"/} no implementa aegis_motor::Motor"
        REG_FALLOS=$((REG_FALLOS + 1))
    fi
    while read -r tipo; do
        if ! grep -qw "$tipo" "$AGENTE/src/main.rs"; then
            fallo "$tipo implementa el contrato pero el agente no lo registra"
            REG_FALLOS=$((REG_FALLOS + 1))
        fi
    done < <(grep -oE 'impl (aegis_motor::)?Motor<[^>]*> for [A-Za-z0-9_]+' "$f" | awk '{print $NF}')
done
[ "$REG_FALLOS" -eq 0 ] && echo "    ${VERDE}OK${FIN} ($(grep -lE 'impl (aegis_motor::)?Motor<' "$AGENTE"/src/motores/*.rs | wc -l) motor(es), todos registrados en el agente)"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> Motores verificados${FIN}"
else
    echo "${ROJO}==> Motores: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
