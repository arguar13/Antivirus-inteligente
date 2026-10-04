#!/usr/bin/env bash
#
# Verificacion de AegisCapture (captura indexada por entidad, FASE 90).
#
# LAS DOS COSAS QUE UN CAPTURADOR ES, ADEMAS DE UN CAPTURADOR
#
# Un capturador es, por diseno, el sitio donde se acumula todo lo que paso por la
# red. Eso lo convierte en dos armas contra su propio dueno:
#
#   - UN SITIO DEL QUE ROBAR. Si guarda credenciales, quien lea el disco se lleva
#     las contrasenas de todos los usuarios de la ultima semana. No hace falta
#     comprometer el agente.
#   - UNA FORMA DE LLENAR EL DISCO. Si guarda todo lo que le echen, quien genere
#     trafico decide cuando se queda sin espacio la maquina — y una maquina sin
#     espacio deja de escribir registros, que es apagar la defensa por detras.
#
# Las dos se paran con propiedades ESTRUCTURALES, que es lo que esta puerta
# comprueba, y no con limites configurables:
#
#   1. NO HAY CAMINO DE LOS BYTES DEL CABLE AL DISCO QUE SE SALTE LA REDACCION.
#      El anillo acepta `Limpio`, y `Limpio` no tiene mas constructor que
#      `Redactor::limpiar`. Se comprueba por AUSENCIA: buscando el constructor
#      que no debe existir.
#   2. SIN VEREDICTO NO HAY CONTENIDO. Guardar entero exige una `Autorizacion`, y
#      `Autorizacion` solo se construye desde un veredicto. No hay `nueva()`, no
#      hay `Default`, no hay `From`. Tambien por ausencia.
#   3. NADA DE LO QUE CRECE CON EL TRAFICO CRECE SIN TECHO. Son DOS cosas, no
#      una: el anillo guarda el contenido y el indice guarda el sobre — y el sobre
#      se anota tambien del noventa y nueve por ciento que no se guarda. El anillo
#      no tiene `reservar` ni `redimensionar`; el indice tiene un techo de
#      entradas atado al presupuesto EN TIEMPO DE COMPILACION. Quien genere
#      trafico no decide cuanta memoria usa el agente, y quien lo inunde se
#      desaloja a si mismo en vez de borrarle el sobre a la maquina callada.
#   4. LA PERDIDA SE CUENTA. Las dos invariantes de contabilidad del anillo, que
#      es lo que separa una captura incompleta de una que lo parece.
#   5. LA REPRODUCCION ES DETERMINISTA. Los mismos bytes dan el mismo veredicto, y
#      donde no se puede prometer —bytes tapados— se declara en vez de callarse.
#
# EL MURO, declarado: este crate NO abre sockets ni lee interfaces de red. Recibe
# paquetes con su marca de tiempo. La captura de verdad la hace el plano de datos
# (XDP, `aegis-net`), que ya existe y tiene sus propias garantias; lo que se
# prueba aqui es todo lo que pasa DESPUES, que es donde estan las dos armas.

set -uo pipefail
cd "$(dirname "$0")/.."

ROJO=$'\033[31m'; VERDE=$'\033[32m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0

paso()  { echo "${VERDE}  ok${FIN} $1"; }
falla() { echo "${ROJO}  FALLO${FIN} $1"; FALLOS=$((FALLOS + 1)); }

SRC=crates/aegis-captura/src
ALMACEN=server/crates/aegis-almacen-pcap

echo "${GRIS}== AegisCapture: retencion por veredicto y reproduccion determinista ==${FIN}"

# Las lineas de comentario y de documentacion se excluyen: el codigo habla de lo
# que NO hace, y un grep que no lo distinga convierte una explicacion honesta en
# un fallo inventado.
sin_comentarios() {
    grep -rn "$1" --include=*.rs "$SRC" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+: *///?!?' || true
}

# ── 1. Ningun camino se salta la redaccion ─────────────────────────────────
if grep -q "pub fn meter(&mut self, cuando_ns: u64, limpio: &Limpio)" "$SRC/anillo.rs"; then
    paso "el anillo solo acepta bytes que pasaron por la redaccion"
else
    falla "el anillo ya no exige Limpio: hay un camino del cable al disco sin redactar"
fi

# `Limpio` no puede tener otro constructor. Se busca lo que NO debe estar.
if grep -nE 'impl (From<[^>]*> )?for Limpio|impl Limpio \{' "$SRC/redaccion.rs" \
        | grep >/dev/null -vE 'impl Limpio \{'; then
    falla "Limpio ha ganado una conversion: ya se puede construir sin redactar"
else
    paso "Limpio no tiene From ni constructor publico fuera del redactor"
fi
if grep -nE 'pub fn (nuevo|nueva|new|de_bytes|desde)\s*\(' "$SRC/redaccion.rs" \
        | grep >/dev/null 'Limpio'; then
    falla "Limpio ha ganado un constructor publico"
else
    paso "el unico camino a Limpio sigue siendo Redactor::limpiar"
fi

# ── 2. Sin veredicto no hay contenido ──────────────────────────────────────
if grep -q "pub fn del_veredicto(v: &Veredicto) -> Option<Autorizacion>" "$SRC/retencion.rs"; then
    paso "la autorizacion para guardar entero SALE de un veredicto"
else
    falla "la autorizacion ya no sale de un veredicto"
fi
if grep -nE 'impl Default for Autorizacion|impl From<[^>]*> for Autorizacion' "$SRC/retencion.rs" \
        | grep >/dev/null .; then
    falla "Autorizacion ha ganado un Default o un From: se puede fabricar sin veredicto"
else
    paso "Autorizacion no tiene Default ni From"
fi

# ── 3. Las DOS estructuras que crecen con el trafico tienen techo ──────────
#
# El anillo acota el contenido; el indice acota el sobre, que se anota de TODO el
# trafico. Un techo en una sola de las dos no es un techo: el sobre del noventa y
# nueve por ciento que no se guarda crece igual, y quien genera el trafico es de
# quien hay que defenderse. Es la invariante 9 aplicada aqui — una cota por flujo
# no es una cota.
if sin_comentarios 'fn (reservar|redimensionar|crecer|reserve|resize)' | grep >/dev/null "anillo.rs"; then
    falla "el anillo ha ganado una forma de crecer"
else
    paso "el anillo no tiene forma de crecer: su tamano se fija al arrancar"
fi

if grep -q 'pub const MAX_ENTRADAS: usize' "$SRC/indice.rs"; then
    paso "el indice tiene techo de entradas, no solo el anillo de bytes"
else
    falla "el indice ha perdido su techo: el sobre vuelve a crecer con el trafico"
fi

# El techo del indice tiene que salir del presupuesto, comprobado por el
# COMPILADOR. Es la leccion de la FASE 89, donde el techo global de los disectores
# valia ocho veces el del motor y nadie lo vio hasta medirlo.
if grep -q 'const _: () = assert!(MAX_MEMORIA_INDICE <= aegis_wire::MAX_MEMORIA_APP' "$SRC/indice.rs"; then
    paso "el techo del indice cabe bajo el del motor, y lo comprueba el compilador"
else
    falla "el techo del indice ya no esta atado al presupuesto en tiempo de compilacion"
fi

# Y no puede haber una puerta de atras para quedarse sin techo.
if sin_comentarios 'fn sin_tope|tope: *usize::MAX' | grep >/dev/null .; then
    falla "hay una forma de construir un indice sin techo"
else
    paso "no hay forma de construir un indice sin techo: hay que escribir un numero"
fi

# ── 4. Sans-IO, como los disectores ────────────────────────────────────────
#
# El crate del agente no abre sockets ni mira el reloj. El del servidor SI toca
# ficheros —es un almacen—, y por eso se comprueban por separado.
PROHIBIDO='std::net::|TcpStream|UdpSocket|SystemTime::now|Instant::now'
HALLAZGOS=$(sin_comentarios "$PROHIBIDO" | grep -v '/tests/' || true)
if [ -z "$HALLAZGOS" ]; then
    paso "sans-IO: el capturador no abre sockets ni mira el reloj"
else
    falla "hay entrada/salida o reloj en el capturador:"
    echo "$HALLAZGOS" | sed 's/^/      /'
fi

# ── 5. Nada de unsafe, y que lo impida el compilador ───────────────────────
if grep -q '#!\[forbid(unsafe_code)\]' "$SRC/lib.rs"; then
    paso "el crate prohibe unsafe"
else
    falla "el crate ya no prohibe unsafe"
fi

# ── 6. Cero dependencias externas ──────────────────────────────────────────
for c in crates/aegis-captura "$ALMACEN"; do
    EXTERNAS=$(sed -n '/^\[dependencies\]/,/^\[/p' "$c/Cargo.toml" \
        | grep -E '^[a-z0-9-]+ *=' | grep -v 'path *= *"' | cut -d= -f1 | tr -d ' ')
    if [ -z "$EXTERNAS" ]; then
        paso "$c: cero dependencias externas"
    else
        falla "$c: dependencias externas inesperadas: $(echo "$EXTERNAS" | tr '\n' ' ')"
    fi
done

# ── 7. Las pruebas, que es donde se mide ───────────────────────────────────
echo "${GRIS}  -- pruebas del agente --${FIN}"
for grupo in "--lib" "--test determinismo" "--test autoataque" "--test medidas" "--test techo_indice"; do
    # shellcheck disable=SC2086
    if cargo test -p aegis-captura $grupo --quiet > /tmp/aegis-captura-$$.log 2>&1; then
        paso "cargo test $grupo"
    else
        falla "cargo test $grupo"
        tail -25 /tmp/aegis-captura-$$.log | sed 's/^/      /'
    fi
done
rm -f /tmp/aegis-captura-$$.log

echo "${GRIS}  -- pruebas del almacen --${FIN}"
if (cd server && cargo test -p aegis-almacen-pcap --quiet) > /tmp/aegis-almacen-$$.log 2>&1; then
    paso "cargo test -p aegis-almacen-pcap"
else
    falla "cargo test -p aegis-almacen-pcap"
    tail -25 /tmp/aegis-almacen-$$.log | sed 's/^/      /'
fi
rm -f /tmp/aegis-almacen-$$.log

# ── 8. Las cifras medidas, impresas para que se puedan leer ────────────────
echo "${GRIS}  -- cifras medidas --${FIN}"
cargo test -p aegis-captura --test medidas --quiet -- --nocapture 2>/dev/null \
    | grep -E "^  (trafico visto|guardandolo todo|retencion por veredicto|y el sobre)|paquetes de [0-9]+ bytes en|^  [0-9]+ paquetes capturados|entradas de .* entidades" \
    | sed 's/^/    /'
cargo test -p aegis-captura --test techo_indice --quiet -- --nocapture 2>/dev/null \
    | grep -E "bytes vivos|techo del agente|a la (callada|ruidosa)|en el indice quedan" \
    | sed 's/^/    /'

# ── 9. Clippy sin excepciones ──────────────────────────────────────────────
if cargo clippy -p aegis-captura --all-targets --quiet -- -D warnings \
        > /tmp/aegis-captura-clippy-$$.log 2>&1; then
    paso "clippy limpio (agente)"
else
    falla "clippy (agente)"
    tail -25 /tmp/aegis-captura-clippy-$$.log | sed 's/^/      /'
fi
if (cd server && cargo clippy -p aegis-almacen-pcap --all-targets --quiet -- -D warnings) \
        > /tmp/aegis-almacen-clippy-$$.log 2>&1; then
    paso "clippy limpio (almacen)"
else
    falla "clippy (almacen)"
    tail -25 /tmp/aegis-almacen-clippy-$$.log | sed 's/^/      /'
fi
rm -f /tmp/aegis-captura-clippy-$$.log /tmp/aegis-almacen-clippy-$$.log

echo
echo "  ${GRIS}LO QUE ESTA PUERTA NO PUEDE COMPROBAR, dicho aqui:${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: la captura desde una interfaz de red real. Este crate no abre"
echo "  ${GRIS}sockets a proposito —es lo que permite probar la carga entera sin red y sin${FIN}"
echo "  ${GRIS}condiciones de carrera—. El plano de datos ya existe en aegis-net.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: una comparacion ejecutada contra Arkime. Lo que se compara es"
echo "  ${GRIS}el MODELO de almacenamiento, con el mismo perfil de trafico para los dos y${FIN}"
echo "  ${GRIS}el perfil escrito en la prueba para que se pueda discutir. Presentar una${FIN}"
echo "  ${GRIS}cifra ajena como medida propia es lo que este producto existe para no hacer.${FIN}"
echo "  ${GRIS}DECLARADO${FIN}: un flujo con bytes tapados NO promete reproducir el mismo"
echo "  ${GRIS}veredicto. Si la senal estaba en la credencial que se tapo, al reproducirlo${FIN}"
echo "  ${GRIS}ya no esta. Se dice en Fidelidad::ConTapados en vez de esconderse detras de${FIN}"
echo "  ${GRIS}una media, y la igualdad solo se exige donde la fidelidad es exacta.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisCapture verificado${FIN}"
else
    echo "${ROJO}==> AegisCapture: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
