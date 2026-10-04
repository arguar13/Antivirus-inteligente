#!/usr/bin/env bash
#
# Verificacion del canal de contenido firmado (FASE 4.5 del MP-16).
#
# LA CAUSA RAIZ que cierra: el contenido de deteccion viajaba dentro del
# binario, sin anillos, sin modo por regla, sin apagado individual ni marcha
# atras, y nada impedia que una regla que no compila o que se come la CPU
# llegase a toda la flota a la vez.
#
# Lo que esta puerta sostiene:
#   1. el canal hace lo que dice: un paquete alterado, de otra clave, de otro
#      dominio, VIEJO (reposicion), ROTO (en la puerta y firmado saltandosela),
#      fuera de su anillo o con una escalera falsa se rechaza sin tocar el
#      estado; apagado, auditoria y rollback funcionan;
#   2. el contenido del repositorio (contenido/) pasa la puerta de publicacion:
#      compila, dispara con sus muestras, no con las benignas, y cabe en su
#      presupuesto de coste. Si no, no se fusiona y no se publica;
#   3. la puerta MUERDE: la misma prueba sobre una copia rota a proposito
#      (una regla que no compila, otra que se pasa de su cota) tiene que fallar;
#   4. la puerta esta en el tipo: `Firmable` no tiene campos publicos, y solo
#      `publicar.rs` lo construye;
#   5. el agente solo toca el almacen de contenido a traves de aegis-contenido,
#      y sus ordenes --contenido funcionan contra un almacen y una clave reales.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fallo() { echo "    ${ROJO}FALLO${FIN}: $1"; FALLOS=$((FALLOS + 1)); }
CRATE=crates/aegis-contenido

echo "==> Contenido: el canal (firma, epoca, anillos, escalera, ajustes, rollback)"
if cargo test -q -p aegis-contenido --lib --test canal > "$TMP/canal.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/canal.log" | tail -1))"
else
    fallo "cargo test -p aegis-contenido"; sed 's/^/    | /' "$TMP/canal.log" | tail -40
fi

echo "==> Contenido: el contenido del repositorio pasa la puerta de publicacion"
if cargo test -q -p aegis-contenido --test contenido_del_repo -- --nocapture \
        > "$TMP/repo.log" 2>&1; then
    grep -h '^AEGIS-CONTENIDO' "$TMP/repo.log" | sed 's/^/    | /'
    echo "    ${VERDE}OK${FIN}"
else
    fallo "el contenido de contenido/ NO se puede publicar"
    sed 's/^/    | /' "$TMP/repo.log" | tail -40
fi

echo "==> Contenido: la puerta muerde (copias rotas a proposito)"
# Cada caso: una copia del arbol con UN defecto. La prueba tiene que fallar.
ANTES=$FALLOS
PRIMERA=$(find contenido/yara -mindepth 1 -maxdepth 1 -type d | sort | head -1)
if [ -z "$PRIMERA" ]; then
    fallo "contenido/yara no tiene ninguna regla con la que probar la puerta"
else
    NOMBRE=$(basename "$PRIMERA")
    for caso in no-compila excede-cota no-dispara; do
        rm -rf "$TMP/$caso"; cp -r contenido "$TMP/$caso"
        R="$TMP/$caso/yara/$NOMBRE"
        case "$caso" in
            no-compila)  printf 'rule %s { condition: \n' "$NOMBRE" > "$R/regla.yar" ;;
            excede-cota) sed -i 's/^pasos_por_byte.*/pasos_por_byte = 0/' "$R/ficha.txt" ;;
            no-dispara)  rm -f "$R"/dispara*; printf 'sin marcador\n' > "$R/dispara-1.txt" ;;
        esac
        if AEGIS_CONTENIDO_FUENTE="$TMP/$caso" \
                cargo test -q -p aegis-contenido --test contenido_del_repo \
                > "$TMP/$caso.log" 2>&1; then
            fallo "la puerta dejo pasar un paquete roto ($caso)"
        elif ! grep -q "NO se puede publicar" "$TMP/$caso.log"; then
            # Fallo, pero no en la puerta (no compilo la prueba, no encontro el
            # arbol...): eso no demuestra que la puerta muerda.
            fallo "la copia rota ($caso) fallo por otra causa, no por la puerta:"
            sed 's/^/    | /' "$TMP/$caso.log" | tail -20
        fi
    done
fi
[ "$FALLOS" -eq "$ANTES" ] && echo "    ${VERDE}OK${FIN} (no compila, excede su cota y no dispara: los tres rechazados)"

echo "==> Contenido: la puerta esta en el tipo"
ANTES=$FALLOS
if awk '/^pub struct Firmable/,/^}/' "$CRATE/src/publicar.rs" | grep >/dev/null -E '^\s+pub'; then
    fallo "Firmable tiene campos publicos: cualquiera podria fabricarlo sin pasar la puerta"
fi
if grep -rn 'Firmable {' "$CRATE/src" | grep -v "^$CRATE/src/publicar.rs:" | grep -v 'pub struct' > "$TMP/x"; then
    fallo "Firmable se construye fuera de publicar.rs:"; sed 's/^/    | /' "$TMP/x"
fi
[ "$FALLOS" -eq "$ANTES" ] && echo "    ${VERDE}OK${FIN} (solo publicar::preparar produce algo firmable)"

echo "==> Contenido: el agente solo entra por aegis-contenido"
ANTES=$FALLOS
if grep -rnE '"(activo|anterior)\.aegc"|ajustes\.aegs' crates/aegis-agent/src > "$TMP/x"; then
    fallo "el agente toca los ficheros del almacen por su cuenta:"; sed 's/^/    | /' "$TMP/x"
fi
if cargo test -q -p aegis-agent --test contenido > "$TMP/agente.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/agente.log" | tail -1))"
else
    fallo "cargo test -p aegis-agent --test contenido"
    sed 's/^/    | /' "$TMP/agente.log" | tail -30
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> Contenido verificado${FIN}"
else
    echo "${ROJO}==> Contenido: $FALLOS fallo(s)${FIN}"
fi
echo "${GRIS}    (lo no cubierto aqui: ningun motor consume aun el contenido; sin prueba en la matriz de kernels)${FIN}"
exit "$FALLOS"
