#!/usr/bin/env bash
#
# Verificacion de AegisPosture (FASE 94): inventario de componentes (SBOM) con
# alcanzabilidad en ejecucion, y postura de nube.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. AUTOATAQUE, antes que nada: el escaner como reconocimiento para el
#      atacante. El inventario de una maquina es el mapa que un atacante querria.
#      Por CADA canal que existe, hacia fuera de la organizacion, se retiene; el
#      enjambre no lo saca ni hacia dentro; un destino no declarado es un error.
#      Y escribirlo sin pasar por el juez NO COMPILA (compile_fail con codigo):
#      CycloneDX y SPDX son privados y el marcado no se puede elegir.
#   2. El inventario de paquetes de ESTA maquina, cotejado con `dpkg-query`; los
#      metadatos de `cargo-auditable` de un binario real, con una lectura
#      independiente (objcopy + zlib de Python); y la firma de OpenSSL de la
#      biblioteca real, con la version de su paquete.
#   3. Alcanzabilidad con PROCESOS REALES compilados en la prueba: una biblioteca
#      cargada y otra que no carga nadie dan respuestas distintas y se ve por que;
#      la funcion a la que se llega desde main es alcanzable y la que solo llama
#      una funcion muerta NO; escuchar en 0.0.0.0 es estar expuesto y en
#      127.0.0.1 no.
#   4. La postura de nube, reconstruida de eventos de forma real de AWS, Azure y
#      GCP, con su evidencia, su entidad y SinDatos donde no hay datos.
#   5. El inventario entero de esta maquina, dentro del presupuesto de memoria
#      del agente (384 MiB, el de la clase mas alta), medido por el nucleo.
#   6. El documento que sale lo lee OTRA herramienta: Trivy consume el CycloneDX
#      exportado.
#
# EL MURO, DECLARADO: no hay Docker en esta maquina (las capas de contenedor se
# prueban con imagenes construidas en la prueba, en los tres formatos); no hay
# Go para compilar binarios de prueba (el lector de buildinfo se coteja con los
# binarios de Go reales instalados); la ruta vulnerable se busca dentro de un
# binario, no entre modulos; y la comparativa con Trivy, Grype y Syft necesita
# red y minutos, asi que se mide aparte (docs/86) y no en cada puerta.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-postura-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

echo "==> AegisPosture: AUTOATAQUE — el inventario no sale sin pasar por el estrangulamiento"
if (cd server && cargo test -p aegis-postura --quiet --test autoataque_inventario -- --nocapture) \
    >"$TMP/auto.log" 2>&1; then
    grep -E 'canales' "$TMP/auto.log" | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/auto.log" | head -1))"
else
    fallo "el inventario puede salir de la organizacion" "$TMP/auto.log"
fi
# Sin --quiet: con el, cargo no dice cuales eran compile_fail.
if (cd server && cargo test -p aegis-postura --doc) >"$TMP/doc.log" 2>&1; then
    N=$(grep -c 'compile fail ... ok' "$TMP/doc.log")
    [ "$N" -ge 3 ] || fallo "se esperaban 3 pruebas compile_fail y pasaron $N" "$TMP/doc.log"
    echo "    ${VERDE}OK${FIN} ($N compile_fail: CycloneDX y SPDX son privados (E0603 x2) y el marcado no"
    echo "    ${VERDE}  ${FIN} se puede pasar (E0061))"
else
    fallo "las pruebas compile_fail no pasan" "$TMP/doc.log"
fi

echo "==> AegisPosture: el paquete fuente y la multiarquitectura en el escaner de siempre"
if cargo test -p aegis-vuln --quiet >"$TMP/vuln.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/vuln.log" | awk '{s+=$4} END {print s}') pruebas)"
else
    fallo "aegis-vuln" "$TMP/vuln.log"
fi

echo "==> AegisPosture: comparadores de version, OSV, contenedores capa a capa, ruta y alcance"
if cargo test -p aegis-sbom --quiet --lib >"$TMP/lib.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/lib.log" | head -1))"
else
    fallo "aegis-sbom" "$TMP/lib.log"
fi

echo "==> AegisPosture: contra la maquina REAL (dpkg-query, objcopy, procesos compilados aqui)"
if cargo test -p aegis-sbom --quiet --test real -- --nocapture --test-threads=1 \
    >"$TMP/real.log" 2>&1; then
    grep -E '^(dpkg-query|\S+: [0-9]+ crates|\S+libcrypto|cargada, funcion muerta|procesos:)|OMITIDA' "$TMP/real.log" \
        | cut -c1-150 | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/real.log" | head -1))"
else
    fallo "la prueba contra la maquina real" "$TMP/real.log"
fi

echo "==> AegisPosture: postura de nube reconstruida de los eventos"
if (cd server && cargo test -p aegis-postura --quiet --lib --test postura) >"$TMP/nube.log" 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$TMP/nube.log" | awk '{s+=$4} END {print s}') pruebas)"
else
    fallo "la postura de nube" "$TMP/nube.log"
fi

echo "==> AegisPosture: el inventario de ESTA maquina, dentro del presupuesto de memoria del agente"
cargo build --quiet --release -p aegis-sbom --example postura_support >"$TMP/b.log" 2>&1 \
    || fallo "no compila el ejemplo" "$TMP/b.log"
DIR="${CARGO_TARGET_DIR:-target}"
OSV=()
if [ -d /root/osv-ubuntu/2604 ]; then
    OSV=(--osv /root/osv-ubuntu/2604)
fi
if /usr/bin/time -f '%M' -o "$TMP/rss" "$DIR/release/examples/postura_support" "${OSV[@]}" --hallazgos 5 \
    >"$TMP/inv.log" 2>&1; then
    RSS=$(tail -1 "$TMP/rss")
    sed -n '1,40p' "$TMP/inv.log" | grep -vE '^      ' | sed 's/^/    | /'
    [ "$RSS" -lt $((384 * 1024)) ] || fallo "el inventario uso ${RSS} KB, por encima de 384 MiB" "$TMP/inv.log"
    echo "    ${VERDE}OK${FIN} (memoria maxima $((RSS / 1024)) MiB, medida por el nucleo)"
    [ ${#OSV[@]} -eq 0 ] && echo "    ${GRIS}sin avisos OSV descargados: se midio el inventario y la telemetria, no el cotejo${FIN}"
else
    fallo "el inventario de la maquina" "$TMP/inv.log"
fi

echo "==> AegisPosture: el CycloneDX exportado lo lee otra herramienta"
if (cd server && cargo run --quiet --release -p aegis-postura --example exportar_sbom -- cyclonedx "$TMP/sbom.cdx.json") \
    >"$TMP/exp.log" 2>&1; then
    sed 's/^/    | /' "$TMP/exp.log"
    TRIVY=/opt/aegis-comparativa/bin/trivy
    if [ -x "$TRIVY" ] && [ -d "$HOME/.cache/trivy/db" ]; then
        if "$TRIVY" sbom --skip-db-update -q --format json -o "$TMP/t.json" "$TMP/sbom.cdx.json" 2>"$TMP/t.err"; then
            N=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results',[])))" "$TMP/t.json")
            echo "    ${VERDE}OK${FIN} (Trivy lee el documento y encuentra $N vulnerabilidades en el)"
        else
            fallo "Trivy no lee el CycloneDX exportado" "$TMP/t.err"
        fi
    else
        echo "    ${GRIS}OMITIDO: Trivy o su base de datos no estan en esta maquina; el documento se${FIN}"
        echo "    ${GRIS}valida en las pruebas de aegis-postura, no con una herramienta ajena${FIN}"
    fi
else
    fallo "la exportacion del inventario real" "$TMP/exp.log"
fi

exit 0
