#!/usr/bin/env bash
#
# Verificacion de AegisKnowledge (FASE 98): el grafo de conocimiento STIX 2.1
# completo, unido a lo observado, con inferencia acotada y explicable.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. AUTOATAQUE, antes que nada: el conocimiento como via de envenenamiento.
#      Un canal inyecta una relacion falsa sobre conocimiento legitimo; la
#      procedencia la AISLA (la hipotesis falsa dice que cae si se revoca solo
#      ese canal), la revocacion la REVIERTE, y lo que sostenian los demas sigue
#      en pie.
#   2. Ida y vuelta STIX 2.1 sin perder lo que este nodo no entiende, con datos
#      REALES: MITRE ATT&CK Enterprise, ICS y Mobile (unos 31 000 objetos, con
#      tipos y relaciones personalizados) entran por el lector por objetos,
#      salen por el juez de difusion, y cada objeto sale IGUAL que entro.
#   3. La hipotesis: cadena completa, acotada a dos atribuciones, rebatible
#      contra el grafo de ahora, y que solo sale confirmada por una persona. Y
#      no compila hacerla pasar por un hecho (E0308) ni fabricarla (E0451).
#   4. Las tablas de relaciones son las de sus fuentes: se regeneran desde el
#      PDF de STIX 2.1, el validador de OASIS y el codigo de OpenCTI, fijados a
#      su version, y tienen que salir identicas a las del repositorio.
#   5. La comparativa MEDIDA con OpenCTI: el canon de STIX y las relaciones
#      reales de ATT&CK contra su esquema de relaciones.
#   6. Una sola salida: el documento para fuera solo se construye en
#      `exportar`, despues del juez de difusion.
#
# EL MURO, DECLARADO: OpenCTI no se ha ejecutado (se despliega con Docker y
# esta maquina no lo tiene): se mide contra su esquema de relaciones, que es lo
# que la plataforma deja representar, no contra una instancia con su conector
# de MITRE, que podria traducir algo de lo que su esquema no admite tal cual.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-conocimiento-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
ATTACK=/opt/aegis-comparativa/attack
FUENTES=/opt/aegis-comparativa/stix-tablas

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

# Los datos reales. Se descargan una vez; sin ellos la ida y vuelta no se
# ejerce, y eso no se da por bueno.
for c in enterprise-attack ics-attack mobile-attack; do
    if [ ! -s "$ATTACK/$c.json" ]; then
        mkdir -p "$ATTACK"
        curl -sSfL -o "$ATTACK/$c.json" \
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/$c/$c.json" \
            || fallo "no se pudo descargar ATT&CK ($c)"
    fi
done

# Descargado, se EXIGE: una prueba que no lo encuentre falla en vez de omitirse
# (H-10/H-20). Sin esto, las pruebas que corren sin --nocapture lo omitirian en
# silencio, y el grep de OMITIDA de abajo solo ve las que lo llevan.
export AEGIS_EXIGIR="${AEGIS_EXIGIR:+$AEGIS_EXIGIR,}attack"

echo "==> AegisKnowledge: AUTOATAQUE — el conocimiento como via de envenenamiento"
if (cd server && cargo test -p aegis-conocimiento --quiet --test envenenamiento -- --nocapture) \
    >"$TMP/veneno.log" 2>&1; then
    grep -E '^(HIPOTESIS|  4\.|  cae si)' "$TMP/veneno.log" | cut -c1-150 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} (la procedencia aisla la relacion falsa; revocar el canal la tumba y deja en pie"
    echo "    ${VERDE}  ${FIN} el malware, el indicador, el actor real y lo observado)"
else
    fallo "una relacion falsa no se aisla o no se revierte" "$TMP/veneno.log"
fi

echo "==> AegisKnowledge: ida y vuelta STIX 2.1 con ATT&CK entero"
if (cd server && cargo test -p aegis-share --quiet --test attack -- --nocapture \
        && cargo test -p aegis-conocimiento --quiet --test attack -- --nocapture --test-threads=1) \
    >"$TMP/attack.log" 2>&1; then
    grep -q 'OMITIDA' "$TMP/attack.log" && fallo "ATT&CK no esta: la ida y vuelta no se ejercio" "$TMP/attack.log"
    grep -E 'ida y vuelta identica|salen [0-9]+ objeto|por admision|Cobalt Strike visto|^TAXII' "$TMP/attack.log" \
        | sort -u | cut -c1-160 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} (cada objeto sale igual que entro; lo revocado se retiene y se dice)"
else
    fallo "la ida y vuelta pierde algo" "$TMP/attack.log"
fi

echo "==> AegisKnowledge: la hipotesis — cadena, cota, rebatir, confirmar, y lo que no compila"
if (cd server && cargo test -p aegis-conocimiento --quiet --lib --test hipotesis) >"$TMP/hip.log" 2>&1 \
    && (cd server && cargo test -p aegis-conocimiento --doc -- --nocapture) >"$TMP/doc.log" 2>&1; then
    grep -q 'error\[E0451\]: fields `actor`.*of struct `Hipotesis` are private' "$TMP/doc.log" \
        || fallo "fabricar una hipotesis no falla por sus campos privados" "$TMP/doc.log"
    grep -q 'error\[E0308\]: mismatched types' "$TMP/doc.log" \
        && grep -q 'expected `Objeto`, found `Hipotesis`' "$TMP/doc.log" \
        || fallo "meter una hipotesis en el grafo no falla por el tipo" "$TMP/doc.log"
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/hip.log" | awk '{s+=$4} END {print s}') pruebas; no compila fabricarla (E0451)"
    echo "    ${VERDE}  ${FIN} ni hacerla pasar por un hecho (E0308))"
else
    fallo "la hipotesis" "$TMP/hip.log"
fi

echo "==> AegisKnowledge: las tablas de relaciones salen de sus fuentes"
if [ -s "$FUENTES/enums.py" ] && [ -s "$FUENTES/stix.ts" ] && [ -s "$FUENTES/espec.txt" ] && [ -s "$FUENTES/arbol.json" ]; then
    if python3 tools/tablas-stix.py "$FUENTES" "$TMP" >"$TMP/tablas.log" 2>&1 \
        && diff -q "$TMP/relaciones-stix21.tsv" server/crates/aegis-conocimiento/datos/relaciones-stix21.tsv >/dev/null \
        && diff -q "$TMP/relaciones-opencti.tsv" server/crates/aegis-conocimiento/datos/relaciones-opencti.tsv >/dev/null; then
        sed "s/^/    ${GRIS}/;s/\$/${FIN}/" "$TMP/tablas.log"
        echo "    ${VERDE}OK${FIN} (regeneradas desde las fuentes fijadas, identicas a las del repositorio)"
    else
        fallo "las tablas no salen de sus fuentes" "$TMP/tablas.log"
    fi
else
    echo "    ${GRIS}sin las fuentes descargadas (${FUENTES}): se usan las tablas versionadas, con su commit${FIN}"
fi

echo "==> AegisKnowledge: comparativa MEDIDA con OpenCTI (su esquema de relaciones)"
if (cd server && cargo test -p aegis-conocimiento --quiet --test opencti -- --nocapture --test-threads=1) \
    >"$TMP/opencti.log" 2>&1; then
    grep -E '^(canon|tipos|ATT&CK|  fuera)|filas cuyo' "$TMP/opencti.log" | cut -c1-160 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN}"
else
    fallo "la comparativa con OpenCTI" "$TMP/opencti.log"
fi

echo "==> AegisKnowledge: una sola salida, despues del juez"
# El documento para fuera (`a_json`) se construye en UN sitio del crate, dentro
# de `exportar`, y despues de `repartir`. Un segundo sitio seria un segundo
# camino de salida sin juez.
SITIOS=$(grep -rn 'a_json(' server/crates/aegis-conocimiento/src | wc -l)
ORDEN=$(awk '/^pub fn exportar/,/^}/' server/crates/aegis-conocimiento/src/intercambio.rs \
    | grep -oE 'repartir\(|a_json\(' | tr -d '(' | tr '\n' ' ')
if [ "$SITIOS" = "1" ] && [ "$ORDEN" = "repartir a_json " ]; then
    echo "    ${VERDE}OK${FIN} (un solo sitio construye el documento, y lo hace despues del juez de difusion)"
else
    fallo "hay $SITIOS sitio(s) que construyen un documento; orden en exportar: $ORDEN"
fi
