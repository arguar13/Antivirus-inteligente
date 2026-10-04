#!/usr/bin/env bash
#
# Verificacion de AegisLure (red de senuelos atribuible, FASE 91).
#
# LAS TRES FORMAS DE VOLVER UNA TRAMPA CONTRA QUIEN LA PUSO
#
# Un senuelo es una capacidad nueva del producto, y como toda capacidad nueva de
# un producto de seguridad, es tambien una capacidad nueva para quien lo
# comprometa. Son tres, y las tres se paran con propiedades ESTRUCTURALES:
#
#   1. COMO AMPLIFICADOR. Un servicio que contesta mas de lo que le preguntan,
#      sobre un transporte donde el origen puede falsificarse, manda trafico a una
#      victima que no pidio nada — con nuestra direccion en sus registros. Es
#      exactamente como se han usado NTP, DNS, memcached y BACNET, que es uno de
#      los protocolos que este producto finge. Se para con una cota que compara la
#      respuesta con la pregunta, aplicada por el ENVOLTORIO y no por cada
#      dialogo: asi no hay forma de anadir un senuelo que se la salte.
#   2. COMO FORMA DE AGOTAR EL AGENTE. Quien genere conexiones decide cuanta CPU y
#      cuanta memoria gasta la maquina que le esta vigilando. Se para con un
#      limitador COMPARTIDO por toda la red —uno por conexion no limita nada,
#      porque se cuelga y se vuelve a llamar—, un techo de turnos y un techo de
#      estado por dialogo.
#   3. COMO VIA DE ENTRADA. Es la que hunde a los tarros de miel de alta
#      interaccion clasicos: dan un interprete de ordenes de verdad sobre un
#      sistema de ficheros de verdad, y un fallo de la carcel deja al atacante
#      dentro de una maquina real. Aqui no se para con una carcel: NO HAY NADA QUE
#      ENCARCELAR. Los dialogos son maquinas de estados que transforman bytes en
#      bytes, y se comprueba por AUSENCIA — que es la unica garantia que no
#      depende de que el codigo de comprobacion este bien.
#
# Y LA PROPIEDAD QUE JUSTIFICA LA FASE
#
#   4. CADA SENUELO ENTREGA UN TOKEN DISTINTO, atado a su servicio y su puerto. Un
#      senuelo que cuenta visitas contesta «¿me esta mirando alguien?», que es util
#      el primer dia. Con procedencia por destino contesta «¿POR DONDE entraron, y
#      donde ha estado despues lo que se llevaron?», que es la que se hace en un
#      incidente. La diferencia es que el marcador se DERIVA del sitio donde se
#      sembro, asi que el sitio viaja dentro de la credencial y no en una tabla
#      que se desincroniza.

set -uo pipefail
cd "$(dirname "$0")/.."

ROJO=$'\033[31m'; VERDE=$'\033[32m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0

paso()  { echo "${VERDE}  ok${FIN} $1"; }
falla() { echo "${ROJO}  FALLO${FIN} $1"; FALLOS=$((FALLOS + 1)); }

SRC=crates/aegis-deception/src
TOK=crates/aegis-honeytoken/src

echo "${GRIS}== AegisLure: senuelos que conversan, con procedencia por destino ==${FIN}"

# Las lineas de comentario y de documentacion se excluyen: el codigo habla de lo
# que NO hace, y un grep que no lo distinga convierte una explicacion honesta en
# un fallo inventado.
sin_comentarios() {
    grep -rn "$1" --include=*.rs "${2:-$SRC}" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+: *///?!?' || true
}

# ── 1. Los dialogos no pueden ejecutar ni escribir nada ────────────────────
#
# Se comprueba por AUSENCIA, sobre el directorio de dialogos. Si `Command` no
# aparece, no hay proceso hijo que confinar, lo intente quien lo intente.
PROHIBIDO='Command|std::process|std::fs|File::|TcpStream|UdpSocket|std::net|unsafe|SystemTime::now|Instant::now'
HALLAZGOS=$(sin_comentarios "$PROHIBIDO" "$SRC/dialogos")
if [ -z "$HALLAZGOS" ]; then
    paso "los dialogos no ejecutan, no abren ficheros, no abren sockets y no miran el reloj"
else
    falla "un dialogo ha ganado una capacidad que no debe tener:"
    echo "$HALLAZGOS" | sed 's/^/      /'
fi

DIALOGOS=$(find "$SRC/dialogos" -name '*.rs' | wc -l)
if [ "$DIALOGOS" -ge 5 ]; then
    paso "hay $DIALOGOS ficheros de dialogo y todos pasan por la comprobacion"
else
    falla "solo se encontraron $DIALOGOS ficheros de dialogo: falta alguno por revisar"
fi

# ── 2. La cota de amplificacion la aplica el envoltorio ────────────────────
#
# Si la aplicara cada dialogo, el dialogo nuevo que alguien escriba dentro de un
# ano no la aplicaria — y no fallaria ruidosamente, amplificaria en silencio.
if grep -q 'limitador.filtrar(' "$SRC/dialogo.rs"; then
    paso "el unico camino de los bytes al cable pasa por el limitador"
else
    falla "la conversacion ya no filtra: un senuelo puede amplificar sin que nadie lo pare"
fi
if grep -q 'el_origen_puede_ser_falso()' "$SRC/limitador.rs"; then
    paso "la cota de amplificacion depende del transporte, no de una opcion"
else
    falla "la cota de amplificacion ya no mira el transporte"
fi
# Y ningun dialogo puede filtrar por su cuenta: eso seria la segunda fuente.
if sin_comentarios 'fn filtrar' "$SRC/dialogos" | grep >/dev/null .; then
    falla "un dialogo aplica su propio filtro: hay dos fuentes y se separaran"
else
    paso "ningun dialogo aplica filtro propio"
fi

# ── 3. El limitador es de la red, no de la conversacion ────────────────────
#
# Un cubo de fichas por conexion no limita nada: quien quiera pasarse cuelga y
# vuelve a llamar con el cubo lleno.
if grep -q 'limitador: RefCell<Limitador>' "$SRC/decoy.rs"; then
    paso "el limitador es UNO para toda la red de senuelos"
else
    falla "el limitador ha vuelto a ser por conexion: se salta colgando y llamando"
fi
if grep -q 'limitador: &mut Limitador,' "$SRC/dialogo.rs"; then
    paso "la conversacion recibe el limitador en vez de fabricarse uno"
else
    falla "la conversacion se fabrica su propio limitador"
fi

# ── 4. Los techos de la conversacion ───────────────────────────────────────
for c in MAX_TURNOS MAX_ESTADO; do
    if grep -q "pub const $c" "$SRC/dialogo.rs"; then
        paso "hay techo declarado: $c"
    else
        falla "falta el techo $c: quien hable decide la memoria del agente"
    fi
done
if grep -q 'pub const ORIGENES_RECORDADOS' "$SRC/limitador.rs"; then
    paso "el recuerdo de origenes tiene techo"
else
    falla "el recuerdo de origenes ya no tiene techo"
fi

# ── 5. La procedencia va DENTRO del token ──────────────────────────────────
#
# Si el destino estuviera en una tabla al lado, esa tabla se desincroniza, se
# pierde con la maquina y se la lleva por delante quien borre registros.
if grep -q 'pub destino: Destino' "$TOK/token.rs"; then
    paso "la atribucion lleva DONDE se sembro, no solo a quien"
else
    falla "la atribucion ha perdido el destino: vuelve a ser una tabla aparte"
fi
if grep -q 'v.extend_from_slice(&self.destino.bytes());' "$TOK/token.rs"; then
    paso "el destino entra en el computo del marcador"
else
    falla "el marcador ya no depende del destino: dos sitios darian el mismo token"
fi
# La clase va primero en los bytes del destino: sin ella, un fichero «prod» y una
# base «prod» colisionarian.
if grep -q 'v.extend_from_slice(self.clase().as_bytes());' "$TOK/destino.rs"; then
    paso "la clase del destino va primero: dos clases con el mismo texto no colisionan"
else
    falla "la clase ya no etiqueta el destino: dos destinos distintos pueden colisionar"
fi

# ── 6. Un destino, un token ────────────────────────────────────────────────
if grep -q 'if self.registro.en_destino(&destino).is_some()' "$SRC/plantado.rs"; then
    paso "un destino solo se siembra una vez: no hay dos tokens en el mismo sitio"
else
    falla "se puede sembrar dos veces el mismo sitio: no se sabria cual se toco"
fi

# ── 7. El escaneo de marcadores no depende de cuantos haya ─────────────────
#
# Un bucle por token sobre un volcado de cuatro megabytes con diez mil tokens son
# cuarenta gigabytes de comparaciones, y las dos magnitudes las mueve el atacante.
if grep -q 'fn pareja_posible' "$TOK/registry.rs"; then
    paso "el registro busca con prefiltro: una pasada, sin depender de cuantos tokens hay"
else
    falla "el registro ha vuelto al bucle por token: es un amplificador de CPU"
fi

# ── 8. Nada de unsafe en los dos crates ────────────────────────────────────
if grep -q '#!\[deny(unsafe_code)\]' crates/aegis-honeytoken/src/lib.rs; then
    paso "aegis-honeytoken prohibe unsafe"
else
    falla "aegis-honeytoken ya no prohibe unsafe"
fi

# ── 9. Las pruebas ─────────────────────────────────────────────────────────
echo "${GRIS}  -- pruebas --${FIN}"
for grupo in "--lib" "--test senuelos_vivos" "--test autoataque_senuelos" \
             "--test atribucion" "--test comparacion" "--test deception"; do
    # shellcheck disable=SC2086
    if cargo test -p aegis-deception $grupo --quiet > /tmp/aegis-lure-$$.log 2>&1; then
        paso "cargo test -p aegis-deception $grupo"
    else
        falla "cargo test -p aegis-deception $grupo"
        tail -25 /tmp/aegis-lure-$$.log | sed 's/^/      /'
    fi
done
if cargo test -p aegis-honeytoken --quiet > /tmp/aegis-lure-$$.log 2>&1; then
    paso "cargo test -p aegis-honeytoken"
else
    falla "cargo test -p aegis-honeytoken"
    tail -25 /tmp/aegis-lure-$$.log | sed 's/^/      /'
fi
rm -f /tmp/aegis-lure-$$.log

# ── 10. Las cifras medidas, impresas para que se puedan leer ───────────────
echo "${GRIS}  -- cifras medidas --${FIN}"
cargo test -p aegis-deception --test senuelos_vivos --quiet -- --nocapture 2>/dev/null \
    | grep -E "conversaron de verdad" | sed 's/^/    /'
cargo test -p aegis-deception --test autoataque_senuelos --quiet -- --nocapture 2>/dev/null \
    | grep -E "peor en (UDP|TCP)|entradas hostiles|ficheros de dialogo|conexiones hostiles" \
    | sed 's/^/    /'
cargo test -p aegis-deception --test comparacion --quiet -- --nocapture 2>/dev/null \
    | grep -E "^MEDIDO|^CITADO|^  industriales|^  solo aqui" | sed 's/^/    /'

# ── 11. Clippy sin excepciones ─────────────────────────────────────────────
for c in aegis-deception aegis-honeytoken; do
    if cargo clippy -p "$c" --all-targets --quiet -- -D warnings > /tmp/aegis-lure-clippy-$$.log 2>&1; then
        paso "clippy limpio ($c)"
    else
        falla "clippy ($c)"
        tail -25 /tmp/aegis-lure-clippy-$$.log | sed 's/^/      /'
    fi
done
rm -f /tmp/aegis-lure-clippy-$$.log

echo
echo "  ${GRIS}LO QUE ESTA PUERTA NO PUEDE COMPROBAR, dicho aqui:${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: ningun senuelo completa la criptografia. SSH llega al KEXINIT,"
echo "  ${GRIS}TLS al ClientHello y OPC-UA al ACKNOWLEDGE. Es donde acaba lo que se puede${FIN}"
echo "  ${GRIS}fingir sin construir un riesgo, y resulta que lo mas valioso de cada uno${FIN}"
echo "  ${GRIS}—la huella del cliente, el nombre que buscaba, el usuario— va ANTES.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: no se ha ejecutado Cowrie contra este corpus. Lo que se compara"
echo "  ${GRIS}son PROPIEDADES, y se escribe primero lo que el otro hace mejor: en SSH y${FIN}"
echo "  ${GRIS}Telnet, que es donde compiten, Cowrie saca mas. Una comparacion se hace${FIN}"
echo "  ${GRIS}igual de deshonesta inflando al otro que inflandose uno.${FIN}"
echo "  ${GRIS}AUSENTE${FIN}: el senuelo de BACnet se prueba por TCP, no por UDP. El oyente de"
echo "  ${GRIS}la red es de TCP; lo que importa de ese senuelo —que no amplifique— se mide${FIN}"
echo "  ${GRIS}en el dialogo, que es donde vive la cota, y con su mensaje real.${FIN}"
echo "  ${GRIS}DECLARADO${FIN}: aceptar el acceso a la tercera credencial en Telnet es una"
echo "  ${GRIS}decision, no un descuido: aceptar a la primera levanta sospechas y no${FIN}"
echo "  ${GRIS}aceptar nunca pierde lo que el atacante hace cuando cree haber entrado.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisLure verificado${FIN}"
else
    echo "${ROJO}==> AegisLure: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
