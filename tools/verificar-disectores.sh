#!/usr/bin/env bash
#
# Verificacion de AegisDissect (diseccion de protocolos ampliada, FASE 89).
#
# LO QUE ESTA PUERTA COMPRUEBA, Y POR QUE ESO Y NO OTRA COSA
#
# Disecar muchos protocolos no es la propiedad interesante: Wireshark diseca
# cientos y Zeek trae cincuenta analizadores. Lo que ninguno de los dos hace es
# contestar a la pregunta que importa cuando falta una alerta: «¿esto no paso, o
# no lo supimos leer?». Cuando un analizador no entiende un mensaje, lo salta o lo
# marca como malformado, y el analista ve una traza con menos lineas sin saber
# que faltan.
#
# De ahi las cinco cosas que se comprueban aqui:
#
#   1. SANS-IO. Ningun disector abre un socket, lee un fichero ni mira el reloj.
#      Se comprueba por AUSENCIA, buscando lo que no deberia estar: es la unica
#      forma de comprobar una ausencia. Eso es lo que permite construir cada
#      ataque entero en una prueba, sin montar un servidor y sin carreras.
#
#   2. EL SENSOR NO ES UN AMPLIFICADOR. El rasgo `Disector` devuelve hechos, no
#      bytes para enviar. No responde, no sondea y no pregunta al dispositivo —
#      que en una red industrial no es una preferencia de estilo: un PLC de hace
#      veinte anos se cae con un escaneo, y el sensor que «enriquece»
#      preguntandole provoca la parada de planta que venia a evitar.
#
#   3. UNA COTA POR FLUJO NO ES UNA COTA. El atacante elige tambien el numero de
#      flujos. Los dos techos de este crate son LOS MISMOS que los del motor, no
#      dos parecidos al lado: un crate nuevo que se declarara su propio
#      presupuesto no estaria cumpliendo la invariante, estaria esquivandola.
#
#   4. COBERTURA DECLARADA. Cada disector publica lo que entiende y lo que
#      reconoce y no analiza. Un disector con la segunda lista vacia esta diciendo
#      que lo entiende todo, y de estos protocolos no se entiende ninguno entero.
#
#   5. ENTRADA HOSTIL. Un disector es lo primero que toca los bytes de un
#      desconocido, en un agente con privilegios en cien mil maquinas. Un panico
#      aqui ES una denegacion de servicio contra la propia defensa.
#
# EL MURO, declarado. Este crate NO descifra nada: de DNS sobre TLS, de WireGuard
# y de HTTP/3 ve el sobre y no el contenido, y eso se cuenta como «cifrado» y no
# como «no implementado» — son cosas distintas, porque una se arregla escribiendo
# codigo y la otra no. Tampoco implementa Huffman de HPACK ni sigue la tabla
# dinamica, ni lee protobuf sin sus definiciones. Los tres huecos estan
# declarados en el propio disector y salen en la cifra.

set -uo pipefail
cd "$(dirname "$0")/.."

ROJO=$'\033[31m'; VERDE=$'\033[32m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0

paso()  { echo "${VERDE}  ok${FIN} $1"; }
falla() { echo "${ROJO}  FALLO${FIN} $1"; FALLOS=$((FALLOS + 1)); }

CRATE=crates/aegis-disectores
SRC="$CRATE/src"

echo "${GRIS}== AegisDissect: diseccion ampliada con cobertura declarada ==${FIN}"

# ── 1. Sans-IO, comprobado por ausencia ────────────────────────────────────
#
# Se excluyen las lineas de comentario y de documentacion: el codigo habla de lo
# que NO hace, y un grep que no distinga el comentario de la linea de codigo
# convierte una explicacion honesta en un fallo inventado.
sin_comentarios() {
    grep -rn "$1" --include=*.rs "$SRC" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+: *//' \
        | grep -vE '^[^:]+:[0-9]+: *//!' || true
}

PROHIBIDO_IO='std::net::|TcpStream|UdpSocket|std::fs::|File::open|SystemTime|Instant::now'
HALLAZGOS=$(sin_comentarios "$PROHIBIDO_IO")
if [ -z "$HALLAZGOS" ]; then
    paso "sans-IO: ningun disector abre un socket, lee un fichero ni mira el reloj"
else
    falla "hay entrada/salida en un disector:"
    echo "$HALLAZGOS" | sed 's/^/      /'
fi

# ── 2. El sensor no puede ser un amplificador ──────────────────────────────
#
# La comprobacion es del TIPO, no del comportamiento: si el rasgo devolviera
# bytes para enviar, esto lo veria. Se busca en la definicion del rasgo.
if grep -q "pub trait Disector" "$SRC/disector.rs" \
   && ! grep -A40 "pub trait Disector" "$SRC/disector.rs" | grep -qE 'fn (responder|enviar|emitir_bytes|sondear)'; then
    paso "el rasgo Disector no tiene ninguna forma de emitir bytes"
else
    falla "el rasgo Disector ha ganado una forma de responder"
fi

if ! sin_comentarios 'std::process::Command' | grep -q .; then
    paso "ningun disector lanza un proceso"
else
    falla "un disector lanza un proceso"
fi

# ── 3. Los techos se DERIVAN de los del motor, no se copian ────────────────
if grep -q 'MAX_ESTADO_POR_FLUJO: usize = aegis_wire::motor::MAX_BUFER_APP' "$SRC/disector.rs" \
   && grep -q 'MAX_ESTADO_GLOBAL: usize = aegis_wire::MAX_MEMORIA_APP' "$SRC/disector.rs"; then
    paso "los dos techos se derivan de los del motor: un solo presupuesto, no dos"
else
    falla "los techos de memoria se han copiado a mano y pueden separarse del original"
fi

# ── 4. Cada disector esta en el catalogo y declara sus dos mitades ─────────
#
# Se cuenta sobre el codigo, no sobre una lista: cada `impl Disector for X` tiene
# que aparecer en alguna familia del catalogo. Un disector escrito y no
# registrado es codigo muerto que nadie ejecuta y que igualmente hay que auditar.
IMPLS=$(grep -rhn "^impl Disector for " "$SRC" | sed 's/.*impl Disector for \([A-Za-z0-9_]*\).*/\1/' | sort -u)
FALTAN=""
for t in $IMPLS; do
    if ! grep -q "::$t)" "$SRC/catalogo.rs" && ! grep -q "Box::new($t)" "$SRC/catalogo.rs"; then
        FALTAN="$FALTAN $t"
    fi
done
if [ -z "$FALTAN" ]; then
    paso "los $(echo "$IMPLS" | wc -w) disectores estan registrados en el catalogo"
else
    falla "disectores escritos y no registrados en el catalogo:$FALTAN"
fi

# ── 5. Nada de `unsafe`, y que lo impida el compilador ─────────────────────
if grep -q '#!\[forbid(unsafe_code)\]' "$SRC/lib.rs"; then
    paso "el crate prohibe unsafe: el modo de fallo es un error con nombre"
else
    falla "el crate ya no prohibe unsafe"
fi

# ── 6. Cero dependencias externas nuevas ───────────────────────────────────
#
# Un disector analiza bytes que escribe el atacante, sin autenticacion previa y a
# velocidad de linea. Meter aqui una biblioteca de parsing generica seria
# importar codigo no auditado al sitio mas caliente del agente.
EXTERNAS=$(sed -n '/^\[dependencies\]/,/^\[/p' "$CRATE/Cargo.toml" \
    | grep -E '^[a-z0-9-]+ *=' | grep -v 'path *= *"' | cut -d= -f1 | tr -d ' ')
ESPERADAS="sha2"
if [ "$(echo "$EXTERNAS" | tr '\n' ' ' | xargs)" = "$ESPERADAS" ]; then
    paso "dependencias externas: solo sha2, que el agente ya enlaza"
else
    falla "dependencias externas inesperadas: $(echo "$EXTERNAS" | tr '\n' ' ')"
fi

# ── 7. Las pruebas, que son donde se mide de verdad ────────────────────────
echo "${GRIS}  -- pruebas del crate --${FIN}"
for grupo in "--lib" "--test vectores_rfc" "--test hostil" "--test techo_global" "--test comparacion"; do
    # shellcheck disable=SC2086
    if cargo test -p aegis-disectores $grupo --quiet > /tmp/aegis-disectores-$$.log 2>&1; then
        paso "cargo test $grupo"
    else
        falla "cargo test $grupo"
        tail -25 /tmp/aegis-disectores-$$.log | sed 's/^/      /'
    fi
done
rm -f /tmp/aegis-disectores-$$.log

# ── 8. Las cifras medidas, impresas para que se puedan leer ────────────────
echo "${GRIS}  -- cifras medidas --${FIN}"
cargo test -p aegis-disectores --test comparacion --quiet -- --nocapture el_informe 2>/dev/null \
    | sed -n '/este sensor diseca/p' | sed 's/^/    /'
cargo test -p aegis-disectores --test comparacion --quiet -- --nocapture la_cifra 2>/dev/null \
    | sed -n '/disectores cubriendo/p' | sed 's/^/    /'
cargo test -p aegis-disectores --test comparacion --quiet -- --nocapture la_cobertura 2>/dev/null \
    | sed -n '/^total:/p' | sed 's/^/    /'
cargo test -p aegis-disectores --test techo_global --quiet -- --nocapture 2>/dev/null \
    | sed -n '/cien mil flujos:/p;/disecciones:/p' | sed 's/^/    /'

# ── 9. Clippy sin excepciones ──────────────────────────────────────────────
if cargo clippy -p aegis-disectores --all-targets --quiet -- -D warnings \
        > /tmp/aegis-disectores-clippy-$$.log 2>&1; then
    paso "clippy limpio"
else
    falla "clippy"
    tail -25 /tmp/aegis-disectores-clippy-$$.log | sed 's/^/      /'
fi
rm -f /tmp/aegis-disectores-clippy-$$.log

echo
echo "  ${GRIS}LO QUE ESTA PUERTA NO PUEDE COMPROBAR, dicho aqui:${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: una comparacion ejecutada contra Zeek. La relacion de sus"
echo "  ${GRIS}analizadores esta transcrita de su documentacion y se compara con lo que${FIN}"
echo "  ${GRIS}este sensor mide de si mismo. Presentar un dato de segunda mano como si${FIN}"
echo "  ${GRIS}se hubiera medido es la clase de cifra que este crate existe para no dar.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: trafico capturado de una planta real. Los vectores son de la"
echo "  ${GRIS}norma de cada protocolo, con su documento y su seccion citados, y el${FIN}"
echo "  ${GRIS}barrido hostil se genera de ellos. Lo que no hay es una captura de una${FIN}"
echo "  ${GRIS}fabrica en marcha, y no se finge que la haya.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: el descifrado. De DNS sobre TLS, de WireGuard y de HTTP/3 se"
echo "  ${GRIS}ve el sobre y no el contenido. Se cuenta como CIFRADO y no como «no${FIN}"
echo "  ${GRIS}implementado», porque lo primero no lo arregla escribir mas codigo.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: Huffman de HPACK y la tabla dinamica. De HTTP/2 se sacan las"
echo "  ${GRIS}cabeceras que estan en la tabla ESTATICA, que no dependen de haber visto${FIN}"
echo "  ${GRIS}el principio de la conexion. Las demas se cuentan como hueco declarado.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisDissect verificado${FIN}"
else
    echo "${ROJO}==> AegisDissect: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
