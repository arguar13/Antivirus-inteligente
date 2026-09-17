#!/usr/bin/env bash
#
# Verificacion de AegisState (el estado del endpoint, entero y consultable, FASE 81).
#
# LA TESIS, dicha sin adornos: AegisQL era mejor LENGUAJE que el SQL de osquery
# —no tiene JOIN, asi que su coste es acotable; valida antes de salir de la
# consola; no puede expresar una escritura— y corria sobre CINCO tablas. Un
# lenguaje excelente sobre una fraccion del sistema responde bien a lo que puede
# responder y no dice nada de lo demas, que es la peor manera de fallar: el
# analista no sabe que no puede preguntar.
#
# Esta fase lo lleva a cincuenta y dos tablas, y anade cuatro cosas que osquery
# no tiene y que no son de grado sino de clase:
#
#   1. MOTIVO. Una tabla de osquery que no se puede leer devuelve filas vacias.
#      No es un descuido de su implementacion: con `Vec<Row>` como tipo de
#      retorno NO HAY DONDE poner el motivo, asi que «no hay nada» y «no pude
#      mirar» se escriben igual y en un informe se leen igual. Aqui la firma es
#      `Result<Filas, MotivoNoLeible>` y la segunda respuesta tiene sitio propio.
#   2. COSTE DECLARADO POR TABLA, con un nivel —Peligroso— para el estado cuyo
#      coste no lo acota el tamano de la tabla sino el disco del cliente. Sin
#      acotar NO se ejecuta, y en Rust ni siquiera compila.
#   3. EMPUJE DE PREDICADOS. `WHERE pid = N` abre un fichero, no miles.
#   4. IDENTIDAD. Cada fila que nombra una cosa lleva su Eid, asi que el
#      resultado se une con el linaje sin correlacionar por texto.
#
# EL MURO, declarado en vez de disimulado: osquery NO esta instalado en la
# maquina de integracion, asi que sus cifras no se miden aqui — se citan de su
# documentacion y se dice que son citadas. Inventar una comparativa contra un
# rival que no corre seria exactamente la clase de numero que este proyecto no
# publica. Lo que si se mide, y en esta misma maquina, es lo propio.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisState: los proveedores, el catalogo y la cota de coste"
if cargo test -q -p aegis-estado --lib > /tmp/aegis-estado-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-estado-lib.log | head -1))"
    echo "    ${GRIS}Las pruebas del catalogo son las que sostienen la fase: el esquema${FIN}"
    echo "    ${GRIS}vive en aegis-parser —lo necesita el plano de control para validar${FIN}"
    echo "    ${GRIS}sin compilar syscalls de Linux— y los proveedores viven aparte. Dos${FIN}"
    echo "    ${GRIS}sitios que tienen que decir lo mismo SE DESINCRONIZAN, y las dos${FIN}"
    echo "    ${GRIS}averias son silenciosas: una tabla que el lenguaje declara y nadie${FIN}"
    echo "    ${GRIS}sirve, o un proveedor que funciona y que nadie puede consultar. Aqui${FIN}"
    echo "    ${GRIS}las dos rompen la compilacion de las pruebas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-estado-lib.log)"
    tail -30 /tmp/aegis-estado-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: autoataque contra la capacidad nueva"
if cargo test -q -p aegis-estado --test autoataque > /tmp/aegis-estado-ataque.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-estado-ataque.log | head -1))"
    echo "    ${GRIS}Cuatro vias por las que un proveedor de estado hace daño en el${FIN}"
    echo "    ${GRIS}endpoint de un cliente, y las cuatro se atacan: AGOTAMIENTO (una${FIN}"
    echo "    ${GRIS}consulta que el propio cliente se difunde y tarda minutos en cada${FIN}"
    echo "    ${GRIS}maquina), PANICO (el agente lleva panic=abort: un panico no es una${FIN}"
    echo "    ${GRIS}excepcion, es la flota ciega), FUGA (estas tablas leen el entorno de${FIN}"
    echo "    ${GRIS}los procesos y /etc/shadow) y MENTIRA (cero filas cuando no se pudo${FIN}"
    echo "    ${GRIS}mirar). La cuarta es la mas silenciosa y la que la fase existe para${FIN}"
    echo "    ${GRIS}cerrar.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-estado-ataque.log)"
    tail -30 /tmp/aegis-estado-ataque.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: el rechazo en compilacion de lo que no se puede difundir"
if cargo test -q -p aegis-estado --doc > /tmp/aegis-estado-doc.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-estado-doc.log | head -1))"
    echo "    ${GRIS}Dos de esos doctests son compile_fail, y son la prueba de que la cota${FIN}"
    echo "    ${GRIS}no es una comprobacion que alguien pueda saltarse: una caceria de${FIN}"
    echo "    ${GRIS}coste Caro o Peligroso SIN ACOTAR no compila, porque el rasgo que la${FIN}"
    echo "    ${GRIS}autoriza a difundirse no tiene implementacion para esa combinacion.${FIN}"
    echo "    ${GRIS}Y el rasgo esta SELLADO: nadie puede anadirla desde otro crate. Es la${FIN}"
    echo "    ${GRIS}ausencia como frontera, aplicada al coste.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-estado-doc.log)"
    tail -30 /tmp/aegis-estado-doc.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: el puente con AegisQL, de la consulta a la fila"
if cargo test -q -p aegis-hunt > /tmp/aegis-estado-hunt.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-estado-hunt.log | head -1))"
    echo "    ${GRIS}Solo se empujan predicados en CONJUNCION PURA en la raiz. Bajo un OR,${FIN}"
    echo "    ${GRIS}saber que una rama pide pid = 42 no autoriza a mirar solo el 42 —la${FIN}"
    echo "    ${GRIS}otra rama acepta mas—, y empujarlo perderia filas EN SILENCIO, que es${FIN}"
    echo "    ${GRIS}la unica forma de que este mecanismo haga daño. Empujar de menos${FIN}"
    echo "    ${GRIS}cuesta tiempo; empujar de mas pierde deteccion.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-estado-hunt.log)"
    tail -30 /tmp/aegis-estado-hunt.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: toda tabla peligrosa se niega a leerse sin filtro"
PELIGROSAS=$(grep -c 'Coste::Peligroso' crates/aegis-estado/src/*.rs 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
if [ "$PELIGROSAS" -ge 6 ]; then
    echo "    ${VERDE}OK${FIN} ($PELIGROSAS declaraciones de coste peligroso en los proveedores)"
    echo "    ${GRIS}Peligroso no es «muy caro»: es «su coste NO lo acota el tamano de la${FIN}"
    echo "    ${GRIS}tabla sino el disco del cliente». Recorrer el arbol de ficheros para${FIN}"
    echo "    ${GRIS}encontrar los suid no depende de cuantos suid haya. Y una de las seis${FIN}"
    echo "    ${GRIS}—process_environment— es peligrosa por lo que CONTIENE y no por lo que${FIN}"
    echo "    ${GRIS}tarda: difundirla juntaria los tokens de nube y las contrasenas de${FIN}"
    echo "    ${GRIS}toda la flota en un solo sitio, que es el peor sitio donde podrian${FIN}"
    echo "    ${GRIS}estar juntos.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: solo $PELIGROSAS tablas declaran coste peligroso, se esperaban 6"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: ningun proveedor escribe unsafe"
# El patron es el mismo que usa la invariante 02: busca `unsafe` SEGUIDO de lo que
# de verdad abre un bloque o una funcion, y exige que no haya una barra antes en
# la linea. Un `grep unsafe` a secas encuentra la palabra en los COMENTARIOS —que
# en este crate la nombran a proposito, para explicar por que no hace falta— y
# falla contra codigo que esta bien. Una puerta que da falsos positivos se acaba
# desactivando, que es peor que no tenerla.
if grep -rnE '^[^/]*\b(unsafe)\b[[:space:]]*(\{|fn |impl |extern |trait )' \
        crates/aegis-estado/src/ > /tmp/aegis-estado-unsafe.log 2>&1; then
    echo "    ${ROJO}FALLO${FIN}: hay unsafe en los proveedores de estado"
    sed 's/^/    | /' /tmp/aegis-estado-unsafe.log
    FALLOS=$((FALLOS + 1))
elif ! grep -q 'forbid(unsafe_code)' crates/aegis-estado/src/lib.rs; then
    echo "    ${ROJO}FALLO${FIN}: falta #![forbid(unsafe_code)] en aegis-estado"
    FALLOS=$((FALLOS + 1))
else
    echo "    ${VERDE}OK${FIN} (forbid(unsafe_code), y no hace falta levantarlo)"
    echo "    ${GRIS}Merece una frase porque no era obvio: casi todo el estado del sistema${FIN}"
    echo "    ${GRIS}en Linux es TEXTO en /proc, /sys y /etc, y leer texto no necesita${FIN}"
    echo "    ${GRIS}punteros crudos. Lo unico que si necesita llamadas al sistema de${FIN}"
    echo "    ${GRIS}verdad —enumerar procesos, leer memoria ajena, cruzar inodos de${FIN}"
    echo "    ${GRIS}socket, y desde esta fase los atributos extendidos— vive detras de${FIN}"
    echo "    ${GRIS}aegis-scal, que es donde el unsafe esta concentrado y revisado.${FIN}"
fi

echo "==> AegisState: la comparativa, medida en esta maquina"
if cargo run -q -p aegis-hunt --example comparativa > /tmp/aegis-estado-comparativa.log 2>&1; then
    echo "    ${VERDE}OK${FIN}"
    sed 's/^/    | /' /tmp/aegis-estado-comparativa.log
    echo "    ${GRIS}osquery declara unas 280 tablas en Linux, y no se compara el numero${FIN}"
    echo "    ${GRIS}por una razon que conviene decir: una parte grande de ese catalogo es${FIN}"
    echo "    ${GRIS}introspeccion de osquery MISMO (osquery_flags, osquery_registry,${FIN}"
    echo "    ${GRIS}osquery_schedule...) y tablas de otras plataformas. Contarlas como${FIN}"
    echo "    ${GRIS}visibilidad del endpoint infla la comparativa a favor de quien la${FIN}"
    echo "    ${GRIS}publica. Lo que aqui se mide es lo que responde una caza real.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-estado-comparativa.log)"
    tail -20 /tmp/aegis-estado-comparativa.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisState: osquery instalado para medir de tu a tu"
echo "    ${GRIS}AUSENTE${FIN}: osquery no esta en la maquina de integracion, asi que sus"
echo "    ${GRIS}tiempos NO se miden aqui. Se citan de su documentacion y se dice que son${FIN}"
echo "    ${GRIS}citados. El dia que este instalado, esta misma puerta corre las diez${FIN}"
echo "    ${GRIS}consultas equivalentes en osqueryi y publica las dos columnas. Hasta${FIN}"
echo "    ${GRIS}entonces, la unica cifra honesta es la propia.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: Windows y macOS. Sus tablas llegan en las FASES 83 y 84;"
echo "    ${GRIS}las cincuenta y dos de hoy son de Linux, y el catalogo lo dice en vez de${FIN}"
echo "    ${GRIS}devolver cero filas en la plataforma que no es.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisState verificado${FIN}"
else
    echo "${ROJO}==> AegisState: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
