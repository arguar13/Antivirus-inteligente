#!/usr/bin/env bash
#
# Verificacion del motor Sigma del agente y de su contenido (FASE 4 del MP-16,
# paso 5).
#
# LA CAUSA RAIZ que cierra: la fabrica (aegis-ruleforge) compilaba reglas Sigma
# que ningun endpoint evaluaba, con un evaluador que tenia fallos que ninguna
# prueba veia (listas de mapas leidas al reves, palabras clave que casaban con
# todo, comodines comparados como caracteres, un panico con multibyte). Y el
# contenido de deteccion era una tabla escrita a mano, sin eventos de prueba.
#
# Lo que esta puerta sostiene:
#   1. el compilador y el evaluador compartidos (aegis-sigma) hacen lo que
#      dicen, con los hallazgos convertidos en pruebas;
#   2. el origen del contenido esta FIJADO (tools/sigma/COMMIT, commits
#      completos) y lo que viaja viene de ese commit, con su licencia (DRL 1.1)
#      y su atribucion;
#   3. CADA regla que viaja en el agente entra sin rechazo, tiene un evento
#      GENERADO desde la regla que la dispara y otro que no, y un presupuesto
#      de falsos positivos; el directorio y la lista incluida coinciden;
#   4. esas mismas reglas, convertidas en eventos del kernel, disparan en el
#      MOTOR del agente con su id, y el evento negativo no.
#
# SIN CONTENIDO NO ES UN FALLO, PERO SE DICE. Importar es un paso aparte (red,
# y una persona que revisa los presupuestos): mientras no se haga, el motor se
# registra sin reglas, lo dice al arrancar, la matriz de capacidades lo deja en
# Biblioteca (no hay prueba en vivo ni medida) y esta puerta lo declara en cada
# make ci. Lo que SI falla es un vacio incoherente: presupuestos, atribucion o
# ficheros sueltos sin reglas, o reglas sin su licencia.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; AMARILLO=$'\033[33m'; FIN=$'\033[0m'
FALLOS=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fallo() { echo "    ${ROJO}FALLO${FIN}: $1"; FALLOS=$((FALLOS + 1)); }
REGLAS=crates/aegis-sigma/reglas/linux
FIJADO=tools/sigma/COMMIT
dato() { sed -n "s/^$1=//p" "$FIJADO" 2> /dev/null | head -1 | tr -d '[:space:]'; }

echo "==> Sigma: compilador, evaluador sin retroceso y generador de eventos"
if cargo test -q -p aegis-sigma > "$TMP/sigma.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/sigma.log" | head -1))"
else
    fallo "cargo test -p aegis-sigma"; sed 's/^/    | /' "$TMP/sigma.log" | tail -40
fi

echo "==> Sigma: origen fijado, licencia, atribucion y presupuestos"
ANTES=$FALLOS
COMMIT="$(dato SIGMA_COMMIT)"
ETIQUETA="$(dato SIGMA_ETIQUETA)"
for par in "SIGMA_COMMIT:$COMMIT" "DRL_COMMIT:$(dato DRL_COMMIT)"; do
    printf '%s' "${par#*:}" | grep >/dev/null -E '^[0-9a-f]{40}$' \
        || fallo "$FIJADO: ${par%%:*} no es un commit completo (40 hex)"
done
[ -n "$ETIQUETA" ] || fallo "$FIJADO: falta SIGMA_ETIQUETA"
N=$(find "$REGLAS" -maxdepth 1 -name '*.yml' 2> /dev/null | wc -l)
if [ "$N" -eq 0 ]; then
    # El vacio tiene que ser vacio de verdad: nada que aparente contenido.
    SUELTOS=$(find "$REGLAS" -mindepth 1 2> /dev/null | wc -l)
    [ "$SUELTOS" -eq 0 ] || fallo "$REGLAS tiene $SUELTOS fichero(s) y ninguna regla: reimportar o borrar"
    if [ "$FALLOS" -eq "$ANTES" ]; then
        echo "    ${VERDE}OK${FIN} (origen fijado: SigmaHQ $ETIQUETA, ${COMMIT:0:12})"
        echo "    ${AMARILLO}SIN CONTENIDO${FIN}: 0 reglas importadas; el motor sigma se registra y no"
        echo "    evalua nada. Importar: tools/sigma/importar.sh (red) y revisar PRESUPUESTOS."
    fi
else
    for f in LICENCIA-DRL-1.1.md ATRIBUCION PRESUPUESTOS INFORME-IMPORTACION; do
        [ -s "$REGLAS/$f" ] || fallo "falta $REGLAS/$f"
    done
    grep -q 'Detection Rule License (DRL) 1.1' "$REGLAS/LICENCIA-DRL-1.1.md" 2> /dev/null \
        || fallo "$REGLAS/LICENCIA-DRL-1.1.md no es el texto de la DRL 1.1"
    # Lo que viaja viene del commit fijado: si se cambia COMMIT, hay que reimportar.
    grep -qx "commit $COMMIT (release $ETIQUETA)" "$REGLAS/ATRIBUCION" 2> /dev/null \
        || fallo "ATRIBUCION no viene de SigmaHQ $ETIQUETA ($COMMIT): reimportar con tools/sigma/importar.sh"
    # Cada regla, con su id en la atribucion y en los presupuestos. Es la misma
    # comprobacion que hace la prueba en Rust, repetida sin compilar: si alguien
    # añade un .yml a mano, falla aqui aunque no se ejecuten las pruebas.
    for y in "$REGLAS"/*.yml; do
        id=$(sed -n 's/^id:[[:space:]]*//p' "$y" | head -1 | tr -d "'\"[:space:]")
        base=$(basename "$y")
        [ -n "$id" ] || { fallo "$base no tiene id"; continue; }
        grep -qF "$base | $id |" "$REGLAS/ATRIBUCION" 2> /dev/null || fallo "$base ($id) no esta en ATRIBUCION"
        grep -Eq "^$id[[:space:]]+[0-9]+$" "$REGLAS/PRESUPUESTOS" 2> /dev/null || fallo "$base ($id) sin presupuesto de falsos positivos"
    done
    [ "$FALLOS" -eq "$ANTES" ] && echo "    ${VERDE}OK${FIN} ($N reglas; $(sed -n '1p' "$REGLAS/INFORME-IMPORTACION" 2> /dev/null))"
fi

echo "==> Sigma: cada regla dispara en el motor del agente con su evento, y calla con el otro"
if cargo test -q -p aegis-agent --test reglas_sigma -- --nocapture > "$TMP/agente.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/agente.log" | head -1))"
    grep -E 'no representables|SIN CONTENIDO' "$TMP/agente.log" | head -1 | sed "s/^/    ${GRIS}/;s/$/${FIN}/"
else
    fallo "cargo test -p aegis-agent --test reglas_sigma"; sed 's/^/    | /' "$TMP/agente.log" | tail -40
fi

echo "    ${GRIS}Muros declarados: sin evento de fork en la sonda, ParentImage e Image${FIN}"
echo "    ${GRIS}faltan en procesos creados por fork sin exec (servidores preforked); la${FIN}"
echo "    ${GRIS}linea de comandos llega cortada a 128 bytes (8 argumentos de 63). Ver el${FIN}"
echo "    ${GRIS}contador sin_padre/sin_imagen del motor.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> Sigma verificado${FIN}"
else
    echo "${ROJO}==> Sigma: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
