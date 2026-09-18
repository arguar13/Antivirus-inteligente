#!/usr/bin/env bash
#
# Verificacion de AegisWin (paridad real en Windows, FASE 83).
#
# LA TESIS, dicha sin adornos: el agente sabia mirar un proceso de Windows por
# fuera —quien lo lanzo, con quien habla— y NO sabia abrir su fichero. Todo lo
# que un EDR decide sobre un ejecutable antes de dejarlo correr sale de dentro:
# si esta firmado y por quien, si le han quitado la firma, si le han pegado algo
# detras, si su punto de entrada esta donde deberia, si viene empaquetado. Sin
# eso, la paridad con Linux era de nombre: alli el agente lee ELF, /proc y los
# mapas de memoria; en Windows tenia el esqueleto de la SCAL devolviendo
# Unsupported con el nombre de la interfaz que falta. Honesto, y vacio.
#
# Esta puerta comprueba cuatro cosas, y las cuatro contra ficheros REALES:
#
#   1. CONTRA PE DE VERDAD, NO CONTRA FIXTURES. Un .exe guardado en el
#      repositorio es una foto: prueba que el lector entiende ESE fichero. Aqui
#      los ejecutables se construyen en el momento con clang y lld-link —la misma
#      cadena con la que este repositorio ya cross-compila el driver de Windows—
#      y lo que dice el lector se coteja contra llvm-readobj, que es otra
#      implementacion del mismo formato escrita por otra gente.
#   2. LA HUELLA AUTHENTICODE NO ES EL HASH DEL FICHERO. Salta el CheckSum, la
#      entrada del directorio de seguridad y la tabla de certificados, y recorre
#      las secciones por orden de DESPLAZAMIENTO y no por el de la tabla.
#      Saltarse de mas deja editar el ejecutable sin invalidar la firma;
#      saltarse de menos hace que nada cuadre nunca y que alguien acabe apagando
#      la comprobacion de firma. Se prueba por sus dos propiedades: cambiar el
#      CheckSum NO la mueve, y cambiar cualquier otro byte SI.
#   3. NINGUN FICHERO HOSTIL PUEDE TUMBAR AL AGENTE. Este crate lee enteros de
#      desplazamientos que vienen dentro del propio fichero: el atacante elige
#      los desplazamientos. Con panic = "abort", un panico aqui es el proceso
#      entero muriendose por un fichero — y un EDR que se mata mandandole un
#      fichero se desinstala solo. Se trunca un PE real por doscientos sitios y
#      se le voltean tres mil bits de los encabezados.
#   4. INDICIOS, NO VEREDICTOS. Cada hecho sobre la forma del fichero lleva su
#      falso positivo en la propia frase. Un lector de formato que dijera
#      «malicioso» seria un antivirus de los noventa.
#
# EL MURO, declarado en vez de disimulado: esto localiza la firma y calcula la
# huella que Windows compara. NO valida el PKCS#7 —cadena de confianza, marca de
# tiempo, revocacion—, que es otro trabajo y otra superficie. Decir «firma
# valida» cuando lo comprobado es «hay una firma» seria exactamente la clase de
# afirmacion que este proyecto no hace, y por eso el metodo se llama
# `lleva_tabla_de_certificados()` y no `firmado()`.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

echo "==> AegisWin: el lector de PE, pieza a pieza"
if cargo test -q -p aegis-pe --lib > /tmp/aegis-pe-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-pe-lib.log | head -1))"
    echo "    ${GRIS}La lectura acotada se prueba primero porque todo lo demas se apoya${FIN}"
    echo "    ${GRIS}en ella: un «desde + largo» sin acotar desborda con dos campos de 32${FIN}"
    echo "    ${GRIS}bits que declara el fichero, y un desbordamiento silencioso convierte${FIN}"
    echo "    ${GRIS}«apunta 4 GiB mas alla» en «apunta al principio» — la comprobacion de${FIN}"
    echo "    ${GRIS}limites pasaria y la lectura seria de otro sitio.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-pe-lib.log)"
    tail -30 /tmp/aegis-pe-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: contra ejecutables de Windows construidos aqui"
# Con --nocapture, para que los avisos de omision SE VEAN. Sin el, cargo se
# traga la salida de las pruebas que pasan, y una prueba que se omitio sola
# quedaria indistinguible de una que se ejercio: exactamente el fallo que este
# proyecto lleva persiguiendo, y que aqui se comprueba contando los avisos.
if cargo test -q -p aegis-pe --test pe_real -- --nocapture > /tmp/aegis-pe-real.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-pe-real.log | head -1))"
    OMITIDAS=$(grep -c "OMITIDA" /tmp/aegis-pe-real.log || true)
    OMITIDAS=${OMITIDAS:-0}
    if [ "$OMITIDAS" -eq 0 ]; then
        echo "    ${GRIS}Ninguna se omitio: las quince se ejercieron contra PE32+ reales${FIN}"
        echo "    ${GRIS}compilados y enlazados en esta maquina, y el numero de secciones y${FIN}"
        echo "    ${GRIS}la maquina objetivo se cotejaron contra llvm-readobj.${FIN}"
    else
        echo "    ${GRIS}AVISO: $OMITIDAS prueba(s) se omitieron por falta de cadena de${FIN}"
        echo "    ${GRIS}compilacion para Windows. Pasan, pero no ejercieron nada.${FIN}"
    fi
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-pe-real.log)"
    tail -30 /tmp/aegis-pe-real.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: la huella Authenticode, por sus dos propiedades"
FALTAN=""
for prueba in \
    cambiar_el_checksum_no_mueve_la_huella_authenticode \
    cambiar_la_entrada_del_directorio_de_seguridad_no_mueve_la_huella \
    cambiar_un_byte_de_una_seccion_si_mueve_la_huella \
    cambiar_un_byte_del_talon_dos_si_mueve_la_huella \
    pegar_datos_al_final_si_mueve_la_huella_cuando_no_hay_firma \
    la_huella_authenticode_no_es_el_sha256_del_fichero ; do
    grep -q "fn $prueba" crates/aegis-pe/tests/pe_real.rs || FALTAN="$FALTAN $prueba"
done
if [ -z "$FALTAN" ]; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Las dos mitades tienen que estar. Con solo la primera —que cambiar el${FIN}"
    echo "    ${GRIS}CheckSum no mueve la huella— una implementacion que no hasheara NADA${FIN}"
    echo "    ${GRIS}pasaria. Con solo la segunda, una que hasheara el fichero entero${FIN}"
    echo "    ${GRIS}tambien. Y hay una tercera que las cierra: la huella y el SHA-256 del${FIN}"
    echo "    ${GRIS}fichero NO pueden coincidir, porque se saltan tres tramos.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: falta la prueba de$FALTAN"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: entrada hostil, y que nunca haya un panico"
if grep -q "fn truncar_un_pe_real_por_cualquier_sitio_no_provoca_un_panico" \
        crates/aegis-pe/tests/pe_real.rs \
   && grep -q "fn voltear_bytes_sueltos_de_un_pe_real_no_provoca_un_panico" \
        crates/aegis-pe/tests/pe_real.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}El generador de mutaciones es determinista a proposito: una prueba que${FIN}"
    echo "    ${GRIS}falla una vez de cada cien y no se puede reproducir se acaba marcando${FIN}"
    echo "    ${GRIS}como inestable y desactivando, que es como se pierde la unica prueba${FIN}"
    echo "    ${GRIS}que de verdad estaba encontrando algo.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: falta la prueba de entrada hostil"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: el lector de entrada hostil no escribe unsafe"
if grep -q '#!\[forbid(unsafe_code)\]' crates/aegis-pe/src/lib.rs; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}Es exactamente donde el producto no admite unsafe: un desbordamiento${FIN}"
    echo "    ${GRIS}aqui es corrupcion de memoria en el camino por el que entra lo que${FIN}"
    echo "    ${GRIS}escribe el atacante, en un proceso privilegiado, en cien mil maquinas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: aegis-pe tendria que prohibir unsafe"
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: la decision del driver sigue compilando y probandose"
if ./tools/verificar-windows.sh > /tmp/aegis-pe-win.log 2>&1; then
    echo "    ${VERDE}OK${FIN}"
    echo "    ${GRIS}La politica de auto-defensa —que bits de acceso se recortan y que${FIN}"
    echo "    ${GRIS}evento de ETW-Ti es inyeccion— es la parte del driver que puede estar${FIN}"
    echo "    ${GRIS}mal de forma peligrosa, y la unica que se puede compilar sin Windows.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-pe-win.log)"
    tail -20 /tmp/aegis-pe-win.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> AegisWin: lo que esta fase NO cierra"
echo "    ${GRIS}AUSENTE${FIN}: la validacion criptografica de la firma. Se localiza la tabla"
echo "    ${GRIS}de certificados y se calcula la huella que Windows compara; validar el${FIN}"
echo "    ${GRIS}PKCS#7 —cadena de confianza, marca de tiempo, revocacion— es otro trabajo${FIN}"
echo "    ${GRIS}y otra superficie. Por eso el metodo se llama lleva_tabla_de_certificados${FIN}"
echo "    ${GRIS}y no firmado: uno se comprobo y el otro no.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: el driver completo. Sigue necesitando el WDK y firma de"
echo "    ${GRIS}Microsoft, y eso no lo arregla escribir mas codigo. Lo que si se compila${FIN}"
echo "    ${GRIS}y se prueba aqui es la DECISION, que es la parte peligrosa.${FIN}"
echo "    ${GRIS}AUSENTE${FIN}: las tablas de estado de Windows. La FASE 81 dejo cincuenta y"
echo "    ${GRIS}dos de Linux; las de Windows necesitan las interfaces nativas que la SCAL${FIN}"
echo "    ${GRIS}declara y que solo se pueden ejercer sobre un Windows de verdad.${FIN}"

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisWin verificado${FIN}"
else
    echo "${ROJO}==> AegisWin: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
