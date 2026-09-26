#!/usr/bin/env bash
#
# AegisProof (FASE 80): las trece invariantes, comprobadas sobre el producto
# COMPLETO y no sobre una fase.
#
# POR QUE ESTA PUERTA EXISTE APARTE DE LAS DEMAS
# ----------------------------------------------
# Cada `tools/verificar-<fase>.sh` comprueba lo suyo, y lo comprueba mejor que
# esta. Lo que ninguna puede comprobar es lo que se rompe **al sumar**: que el
# agente siga cabiendo en su presupuesto con todas las capacidades encendidas a la
# vez, que ningun crate de analisis haya ganado un `unsafe` por el camino, que el
# arbol de dependencias del endpoint no haya engordado sin que nadie lo justifique
# por escrito, y que el producto entero —no solo el enjambre— siga protegiendo con
# el plano de control caido.
#
# Y tiene DERECHO DE VETO. Si una invariante se rompio, se arregla de raiz antes de
# dar el trabajo por terminado, aunque obligue a volver sobre una fase anterior.
# Una invariante que se relaja «solo esta vez» deja de ser una invariante y pasa a
# ser una aspiracion.
#
# LAS TRECE, Y DE DONDE SALEN
# ---------------------------
# Ocho estructurales, una de autoataque con una fila por capacidad, y cuatro doctrinales
# que el producto ya sostiene y que aqui se comprueban mecanicamente en vez de
# afirmarse.
#
# Uso:  ./tools/verificar-invariantes.sh          (las trece)
#       ./tools/verificar-invariantes.sh 4        (solo la cuarta)
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0
SOLO="${1:-}"
declare -a ROTAS=()

# Si esta invariante toca ejecutarla.
toca() { [ -z "$SOLO" ] || [ "$SOLO" = "$1" ]; }

# Cabecera de una invariante.
titulo() {
    printf '\n%s[%02d]%s %s\n' "$GRIS" "$1" "$FIN" "$2"
}

# Resultado de una invariante.
veredicto() {
    local n="$1"; local nombre="$2"; local ok="$3"; local detalle="$4"
    if [ "$ok" = "si" ]; then
        printf '     %sEN PIE%s  %s\n' "$VERDE" "$FIN" "$detalle"
    else
        printf '     %sROTA%s    %s\n' "$ROJO" "$FIN" "$detalle"
        FALLOS=$((FALLOS + 1))
        ROTAS+=("[$(printf '%02d' "$n")] $nombre — $detalle")
    fi
}

# Explicacion de por que la invariante existe.
porque() { printf '     %s%s%s\n' "$GRIS" "$1" "$FIN"; }

mib() { echo "$(( ${1:-0} / 1024 / 1024 ))"; }

# Ejecuta unas pruebas y dice cuantas pasaron.
#
#   pruebas <raiz|servidor> <paquete> <destino> <filtro> <log>
#
# `destino` son los argumentos de cargo que eligen el binario de pruebas (por
# ejemplo `--lib` o `--test circuito`); vacio significa todos. `filtro` es el
# filtro por nombre, que cargo compara contra la RUTA completa de la prueba
# —modulo incluido—, asi que un nombre de modulo vale como filtro.
pruebas() {
    local donde="$1"; local paquete="$2"; local destino="$3"; local filtro="$4"; local log="$5"
    # shellcheck disable=SC2086
    if [ "$donde" = "servidor" ]; then
        (cd server && cargo test -q -p "$paquete" $destino -- $filtro) > "$log" 2>&1
    else
        cargo test -q -p "$paquete" $destino -- $filtro > "$log" 2>&1
    fi
}

# Cuantas pruebas pasaron segun un log de cargo.
pasadas() {
    grep -oE '^test result: ok\. [0-9]+' "$1" 2>/dev/null \
        | grep -oE '[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo 0
}

echo "AegisProof · las trece invariantes sobre el producto completo"

# ── 01. PRESUPUESTO ────────────────────────────────────────────────────────────
#
# El megaprompt de la fase pedia 46080 KB fijos. Se sustituyo a proposito y por
# instruccion explicita: un numero fijo para todo host es el que obliga a elegir
# entre ahogar una pasarela de 1 GiB o desaprovechar un servidor de 512 GiB, y el
# producto corre en los dos. El modelo real esta en `aegis-presupuesto`: fraccion
# de la RAM del host, con suelos y techos, y tres regimenes.
#
# Lo que NO escala, y por eso sigue siendo una regresion dura, es la huella de
# arranque: `LINEA_BASE_ARRANQUE = 32 MiB`. Si el agente arranca ocupando mas que
# eso, ha engordado, quepa o no quepa en el host que tenga delante.
if toca 1; then
    titulo 1 "PRESUPUESTO · el agente con todo encendido cabe en su perfil"
    if ./tools/verificar-presupuesto.sh > /tmp/inv-presupuesto.log 2>&1; then
        RESUMEN=$(grep -E "reposo de|linea base de|MiB" /tmp/inv-presupuesto.log | head -1 | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//')
        veredicto 1 "presupuesto" si "${RESUMEN:-el reparto por perfil se cumple}"
        porque "El 46080 KB fijo del enunciado se sustituyo por el reparto por clase de"
        porque "host: un numero fijo obliga a elegir entre ahogar una pasarela de 1 GiB o"
        porque "desaprovechar un servidor de 512 GiB, y el producto corre en los dos. Lo"
        porque "que no escala —y por eso sigue siendo regresion dura— es la huella de"
        porque "arranque: 32 MiB medidos y declarados."
    else
        veredicto 1 "presupuesto" no "ver /tmp/inv-presupuesto.log"
        sed 's/^/     | /' /tmp/inv-presupuesto.log | tail -20
    fi
fi

# ── 02. SEGURIDAD DE MEMORIA ───────────────────────────────────────────────────
#
# «Ningun crate de analisis ha ganado un `unsafe`», comprobado mecanicamente. La
# forma util de decirlo: todo crate del agente O declara `#![forbid(unsafe_code)]`
# —y entonces lo impone el compilador— O esta en `tools/lineabase-unsafe.txt` con
# su razon escrita. No hay tercera opcion.
if toca 2; then
    titulo 2 "SEGURIDAD DE MEMORIA · forbid o linea base, sin tercera opcion"
    SIN_DECLARAR=()
    SIN_USAR=()
    for d in crates/*/; do
        n=$(basename "$d")
        [ -f "$d/src/lib.rs" ] || continue
        if grep -q "forbid(unsafe_code)" "$d/src/lib.rs" 2>/dev/null; then
            continue
        fi
        if grep -qE "^$n[[:space:]]" tools/lineabase-unsafe.txt 2>/dev/null; then
            # Esta declarado: se comprueba que siga necesitandolo de verdad.
            if ! grep -rqE '^[^/]*\bunsafe\b[[:space:]]*(\{|fn |impl |extern |trait )' "$d/src" 2>/dev/null; then
                SIN_USAR+=("$n")
            fi
            continue
        fi
        SIN_DECLARAR+=("$n")
    done
    if [ ${#SIN_DECLARAR[@]} -eq 0 ] && [ ${#SIN_USAR[@]} -eq 0 ]; then
        DECLARADOS=$(grep -cE "^aegis-" tools/lineabase-unsafe.txt)
        CON_FORBID=$(grep -l "forbid(unsafe_code)" crates/*/src/lib.rs 2>/dev/null | wc -l)
        veredicto 2 "seguridad de memoria" si \
            "$CON_FORBID crate(s) con forbid impuesto por el compilador, $DECLARADOS declarados con su razon"
        porque "«Cero unsafe» seria mentira: hay codigo del agente cuyo trabajo ES hablar"
        porque "con el kernel —ioctl, mmap, mapas de eBPF, memoria ajena— y prohibirlo ahi"
        porque "no haria el producto mas seguro, lo haria imposible. Lo que si es cierto y"
        porque "se comprueba: en lo que MIRA entrada hostil no hay ninguno, porque ahi un"
        porque "unsafe no es rendimiento, es una corrupcion de memoria en el camino por el"
        porque "que entra lo del atacante, en un proceso privilegiado, en cien mil maquinas."
    else
        DETALLE=""
        [ ${#SIN_DECLARAR[@]} -gt 0 ] && DETALLE="sin forbid ni justificacion: ${SIN_DECLARAR[*]}"
        [ ${#SIN_USAR[@]} -gt 0 ] && DETALLE="$DETALLE; declarados y ya sin unsafe (ponles el forbid): ${SIN_USAR[*]}"
        veredicto 2 "seguridad de memoria" no "$DETALLE"
    fi
fi

# ── 03. ARBOL DE DEPENDENCIAS ──────────────────────────────────────────────────
#
# Cada dependencia directa del agente tiene su justificacion escrita en
# `tools/lineabase-agente.txt`. Sin justificacion, falla — y la respuesta correcta
# casi nunca es escribir la fila, sino preguntarse si ese crate tiene que entrar en
# el endpoint o puede vivir en el servidor, como se hizo con libp2p en la FASE 68.
if toca 3; then
    titulo 3 "ARBOL DE DEPENDENCIAS · cada crate del agente, con su razon escrita"
    NUEVAS=$(python3 - <<'PY'
import re, pathlib
declaradas = set()
for linea in pathlib.Path('tools/lineabase-agente.txt').read_text().splitlines():
    linea = linea.strip()
    if not linea or linea.startswith('#'):
        continue
    declaradas.add(linea.split()[0])

usadas = set()
for f in sorted(pathlib.Path('crates').glob('*/Cargo.toml')):
    txt = f.read_text()
    for m in re.finditer(r'^\[(?:target\.[^\]]+\.)?dependencies\]\s*$(.*?)(?=^\[|\Z)', txt, re.M | re.S):
        for linea in m.group(1).splitlines():
            linea = linea.strip()
            if not linea or linea.startswith('#'):
                continue
            nombre = linea.split('=')[0].strip()
            if not nombre or nombre.startswith('[') or nombre.startswith('aegis-'):
                continue
            if 'path =' in linea:
                continue
            usadas.add(nombre)

print(' '.join(sorted(usadas - declaradas)))
PY
)
    TOTAL=$(grep -cE "^[a-z]" tools/lineabase-agente.txt)
    if [ -z "$NUEVAS" ]; then
        veredicto 3 "arbol de dependencias" si "$TOTAL dependencias directas, todas justificadas por escrito"
        porque "El arbol del agente NO es una lista de bibliotecas: es la superficie de"
        porque "ataque de la cadena de suministro del endpoint. Cada crate que entra es"
        porque "codigo de un tercero que acabara corriendo con privilegios en cien mil"
        porque "sitios. La justificacion escrita es lo unico que impide que el arbol crezca"
        porque "por acumulacion de decisiones que nadie recuerda haber tomado."
    else
        veredicto 3 "arbol de dependencias" no "sin justificacion: $NUEVAS"
    fi
fi

# ── 04. DETERMINISMO ───────────────────────────────────────────────────────────
if toca 4; then
    titulo 4 "DETERMINISMO · el circuito repetido da exactamente lo mismo"
    if pruebas servidor aegis-tejido "--test circuito" "determinismo" /tmp/inv-determinismo.log; then
        veredicto 4 "determinismo" si "$(pasadas /tmp/inv-determinismo.log) prueba(s): mismo veredicto, mismo caso, misma propuesta de contencion"
        porque "No es una propiedad estetica. Sin ella no se puede comparar el informe de"
        porque "hoy con el de ayer, y esa comparacion es como se detecta que un cambio ha"
        porque "movido una deteccion sin que nadie lo pretendiera."
    else
        veredicto 4 "determinismo" no "ver /tmp/inv-determinismo.log"
        tail -25 /tmp/inv-determinismo.log | sed 's/^/     | /'
    fi
fi

# ── 05. EXPLICABILIDAD ─────────────────────────────────────────────────────────
if toca 5; then
    titulo 5 "EXPLICABILIDAD · ninguna ruta del arbitro devuelve una frase vacia"
    if pruebas raiz aegis-entidad "" "explicacion" /tmp/inv-explicabilidad.log; then
        veredicto 5 "explicabilidad" si "$(pasadas /tmp/inv-explicabilidad.log) prueba(s) recorriendo TODAS las combinaciones"
        porque "Se recorren todas las combinaciones en vez de afirmarlo, que es la"
        porque "diferencia entre una propiedad y una intencion. Un veredicto que el"
        porque "analista no puede reconstruir es un veredicto que no usa."
    else
        veredicto 5 "explicabilidad" no "ver /tmp/inv-explicabilidad.log"
        tail -25 /tmp/inv-explicabilidad.log | sed 's/^/     | /'
    fi
fi

# ── 06. TRI-ESTADO ─────────────────────────────────────────────────────────────
#
# «No pude mirar» nunca es «esta bien». Se comprueba de dos maneras: que los
# enumerados de veredicto del producto TENGAN la variante de duda —si no la
# tienen, el codigo no puede expresarla y la acabara disfrazando de limpio— y que
# las pruebas que lo ejercen pasen.
if toca 6; then
    titulo 6 "TRI-ESTADO · «no pude mirar» no es «esta bien», en ningun enumerado"
    FALTAN=()
    comprobar_variante() {
        local fichero="$1"; local enumerado="$2"; local variante="$3"
        if ! grep -A 60 "pub enum $enumerado\b" "$fichero" 2>/dev/null | grep -q "^    $variante"; then
            FALTAN+=("$(basename "$(dirname "$fichero")")::$enumerado sin $variante")
        fi
    }
    comprobar_variante crates/aegis-entidad/src/arbitro.rs Juicio NoConcluyente
    comprobar_variante crates/aegis-entidad/src/arbitro.rs Resultado SinDatos
    comprobar_variante server/crates/aegis-detonate/src/informe.rs Veredicto NoConcluyente
    comprobar_variante server/crates/aegis-enrich/src/fusion.rs Veredicto SinDatos
    comprobar_variante server/crates/aegis-enrich/src/dictamen.rs Juicio Desconocido
    comprobar_variante server/crates/aegis-case/src/modelo.rs Veredicto NoConcluyente
    comprobar_variante crates/aegis-l7hunter/src/baliza.rs Veredicto SinMuestra
    if [ ${#FALTAN[@]} -eq 0 ] \
        && pruebas raiz aegis-entidad "" "limpio" /tmp/inv-triestado-a.log \
        && pruebas servidor aegis-tejido "" "limpio" /tmp/inv-triestado-b.log; then
        veredicto 6 "tri-estado" si "7 enumerados con su variante de duda; $(( $(pasadas /tmp/inv-triestado-a.log) + $(pasadas /tmp/inv-triestado-b.log) )) prueba(s)"
        porque "La variante tiene que EXISTIR en el tipo: un enumerado que no puede decir"
        porque "«no se» obliga a quien lo usa a elegir entre malicioso y limpio, y la"
        porque "eleccion comoda es siempre limpio. Es la averia que este producto persigue"
        porque "desde la primera fase, y la que hace que una muestra que detecto el sandbox"
        porque "y se marcho entre en la flota con el sello de haber sido analizada."
    else
        DETALLE="${FALTAN[*]:-pruebas en rojo}"
        veredicto 6 "tri-estado" no "$DETALLE"
    fi
fi

# ── 07. AUTONOMIA ──────────────────────────────────────────────────────────────
if toca 7; then
    titulo 7 "AUTONOMIA · con el plano de control caido, el producto sigue protegiendo"
    if pruebas servidor aegis-tejido "--test autonomia" "" /tmp/inv-autonomia.log; then
        veredicto 7 "autonomia" si "$(pasadas /tmp/inv-autonomia.log) prueba(s) con el enlace cortado de verdad"
        porque "Cortar la salida a Internet es lo PRIMERO que hace un atacante, asi que el"
        porque "estado «sin plano de control» no es un fallo raro: es el estado en el que"
        porque "hay que detectar. Lo que se comprueba no es solo que el enjambre hable, sino"
        porque "que el producto entero siga dando veredicto: corpus local, arbitro,"
        porque "enriquecimiento degradado y corroboro entre pares."
    else
        veredicto 7 "autonomia" no "ver /tmp/inv-autonomia.log"
        tail -25 /tmp/inv-autonomia.log | sed 's/^/     | /'
    fi
fi

# ── 08. LOS CINCO FRENOS ───────────────────────────────────────────────────────
if toca 8; then
    titulo 8 "LOS CINCO FRENOS · siguen funcionando con el grafo enriquecido"
    if pruebas servidor aegis-predict "" "contencion" /tmp/inv-frenos.log \
        && pruebas servidor aegis-tejido "--test circuito" "contencion" /tmp/inv-frenos-b.log; then
        veredicto 8 "los cinco frenos" si "$(( $(pasadas /tmp/inv-frenos.log) + $(pasadas /tmp/inv-frenos-b.log) )) prueba(s), tambien sobre el grafo del circuito completo"
        porque "Este motor PROPONE aislar maquinas de produccion, y eso gobierna todo: un"
        porque "activo protegido no se toca jamas, por encima del tope de radio no actua"
        porque "sino que escala a una persona, la evidencia recien fabricada no mueve nada,"
        porque "un camino improbable tampoco, y se corta la identidad antes que la maquina."
        porque "En el circuito de la FASE 79 se ven los dos primeros a la vez: el camino"
        porque "acaba en el controlador de dominio, que esta protegido, asi que corta un"
        porque "salto antes en la cuenta de servicio."
    else
        veredicto 8 "los cinco frenos" no "ver /tmp/inv-frenos.log"
        tail -25 /tmp/inv-frenos.log | sed 's/^/     | /'
    fi
fi

# ── 09. AUTOATAQUE ─────────────────────────────────────────────────────────────
#
# Por cada capacidad nueva, una prueba que intenta usarla CONTRA el producto. No
# es una comprobacion de robustez generica: cada una es el ataque concreto que
# esa capacidad habilita, y tiene que fallar EN EL INTENTO.
if toca 9; then
    titulo 9 "AUTOATAQUE · cada capacidad, usada contra el producto"
    # Cada fila: <nombre del ataque> ; <ejecuciones separadas por «+»>, donde cada
    # ejecucion es <raiz|servidor>|<paquete>|<destino>|<filtro>.
    declare -a ATAQUES=(
        "el disector como amplificador;raiz|aegis-wire||agotamiento reensamblado flujo"
        "el IPS como denegacion de servicio;raiz|aegis-ips||limitador protegidos"
        "el compilador de reglas como via de ejecucion;servidor|aegis-ruleforge||regex_segura canario"
        "la detonacion como fuga del invitado;servidor|aegis-detonate||frontera receptor"
        "la ingesta como agotamiento de memoria;raiz|aegis-ingest||memoria+servidor|aegis-pipeline||admision"
        "el enriquecimiento como fuga de datos;servidor|aegis-enrich||salida observable"
        "la federacion como envenenamiento;servidor|aegis-share||procedencia federacion"
        # El capturador es, ademas de un capturador, un sitio del que robar —si
        # guarda credenciales, quien lea el disco se lleva las de toda la semana— y
        # una forma de llenar la maquina: el contenido en el anillo y el SOBRE en
        # el indice, que se anota tambien del trafico que no se guarda.
        "el capturador como sitio del que robar;raiz|aegis-captura|--test autoataque|+raiz|aegis-captura|--test techo_indice|"
        # El senuelo es una trampa, y una trampa se puede volver: como amplificador
        # contra un tercero —el origen de UDP se falsifica—, como forma de agotar
        # al agente que la puso, y como via de entrada. La tercera es la que hunde
        # a los tarros de miel clasicos, y aqui se para no teniendo nada que
        # encarcelar.
        "el senuelo como trampa vuelta del reves;raiz|aegis-deception|--test autoataque_senuelos|"
        # La auditoria de plataforma (FASE 92) lee la configuracion del chipset,
        # /dev/mem y los MSR. Vuelta del reves es un LADRILLO: una escritura en
        # la flash, en SMRAM o en un MSR deja la placa inservible. Se intenta
        # escribir por cada superficie contra el kernel, y ademas se comprueba
        # que el tipo no pueda ni pedirlo (compile_fail con codigo de error).
        "la auditoria de firmware como ladrillo;raiz|aegis-fwaudit|--test solo_lectura|+raiz|aegis-fwaudit|--doc|"
        # El confinamiento (FASE 93) puede dejar sin red, sin ficheros o sin
        # capacidades a cualquier proceso. Vuelto contra el propio agente lo
        # ciega; contra init o sshd deja al cliente sin maquina. El objetivo ni se
        # puede construir para ellos, un perfil malo se retira solo, y el modo
        # obligatorio no se puede construir sin confirmacion.
        "el confinamiento como denegacion de servicio;raiz|aegis-confinar|--test confinamiento_real|el_motor_no_puede un_perfil_malo+raiz|aegis-confinar|--lib|despliegue objetivo+raiz|aegis-confinar|--doc|"
    )
    ROTOS=()
    TOTAL_PRUEBAS=0
    for a in "${ATAQUES[@]}"; do
        nombre="${a%%;*}"
        IFS='+' read -r -a EJECUCIONES <<< "${a#*;}"
        n=0
        roto=""
        for (( i=0; i<${#EJECUCIONES[@]}; i++ )); do
            IFS='|' read -r donde paquete destino filtro <<< "${EJECUCIONES[$i]}"
            log="/tmp/inv-ataque-${paquete}-${i}.log"
            if pruebas "$donde" "$paquete" "$destino" "$filtro" "$log"; then
                n=$((n + $(pasadas "$log")))
            else
                roto="si"
            fi
        done
        if [ -z "$roto" ] && [ "$n" -gt 0 ]; then
            TOTAL_PRUEBAS=$((TOTAL_PRUEBAS + n))
            printf '     %s·%s %-46s %s%s prueba(s)%s\n' "$GRIS" "$FIN" "$nombre" "$VERDE" "$n" "$FIN"
        else
            ROTOS+=("$nombre")
            printf '     %s·%s %-46s %sROTO%s\n' "$GRIS" "$FIN" "$nombre" "$ROJO" "$FIN"
        fi
    done
    if [ ${#ROTOS[@]} -eq 0 ]; then
        veredicto 9 "autoataque" si "las ${#ATAQUES[@]} capacidades resisten su propio ataque ($TOTAL_PRUEBAS pruebas)"
        porque "Cada capacidad que se añade a un producto de seguridad es una capacidad"
        porque "nueva para quien lo comprometa. El disector que lee todo el trafico es un"
        porque "amplificador; el IPS que corta flujos es un boton de denegacion de"
        porque "servicio; el compilador de reglas ejecuta lo que escriben terceros. La"
        porque "prueba no es que el producto aguante: es que el intento falle DONDE se"
        porque "intenta, y que el intento este escrito."
    else
        veredicto 9 "autoataque" no "${ROTOS[*]}"
    fi
fi

# ── 10. DOCTRINA DEL ENJAMBRE ──────────────────────────────────────────────────
if toca 10; then
    titulo 10 "DOCTRINA DEL ENJAMBRE · transporta autoridad, no la concede"
    VARIANTES=$(grep -cE "^    (Observacion|Artefacto) \{" server/crates/aegis-share/src/puente.rs 2>/dev/null || echo 0)
    if [ "$VARIANTES" = "2" ] \
        && ! grep -qE "^    Orden \{" server/crates/aegis-share/src/puente.rs \
        && grep -q "pub fn exige_firma" server/crates/aegis-share/src/puente.rs; then
        veredicto 10 "doctrina del enjambre" si "la carga tiene 2 variantes y ninguna es una orden"
        porque "Si un agente pudiera decir «aisla al equipo X», quien comprometa UNO"
        porque "tendria un boton de denegacion de servicio sobre la organizacion entera, y"
        porque "podria aislar justo las maquinas que lo habrian detectado. Que la tercera"
        porque "variante NO EXISTA es la misma tecnica que la salida de la detonacion: lo"
        porque "que no se puede expresar no se puede configurar por error."
    else
        veredicto 10 "doctrina del enjambre" no "la carga del enjambre tiene $VARIANTES variantes o falta la firma"
    fi
fi

# ── 11. UN SOLO ESTRANGULAMIENTO DE SALIDA ─────────────────────────────────────
if toca 11; then
    titulo 11 "UN SOLO ESTRANGULAMIENTO · nada sale sin pasar por la politica"
    CANALES=$(grep -cE "^    (Taxii|Federacion|Enjambre|Exportacion)," server/crates/aegis-share/src/difusion.rs 2>/dev/null || echo 0)
    if [ "$CANALES" = "4" ] \
        && grep -q "pub const NO_DISTRIBUIBLE" server/crates/aegis-share/src/difusion.rs \
        && pruebas servidor aegis-share "" "difusion" /tmp/inv-estrangulamiento.log; then
        veredicto 11 "un solo estrangulamiento" si "los 4 canales pasan por el mismo juez; $(pasadas /tmp/inv-estrangulamiento.log) prueba(s)"
        porque "Si cada camino de salida tuviera su filtro, el que se quedara atras no"
        porque "fallaria ruidosamente: compartiria de mas. Y no hace falta un ataque —basta"
        porque "añadir un camino nuevo y olvidar el filtro—. Con un solo estrangulamiento,"
        porque "el motivo de retencion es EL MISMO en los cinco destinos, asi que la"
        porque "propiedad es cierta por construccion y no por haber configurado bien."
    else
        veredicto 11 "un solo estrangulamiento" no "$CANALES canal(es) declarados, o la prueba de difusion en rojo"
    fi
fi

# ── 12. LA AUSENCIA ES LA FRONTERA ─────────────────────────────────────────────
#
# Lo que no se puede expresar no se puede configurar por error. Se comprueba que
# los enumerados peligrosos NO tengan la variante peligrosa — que es una propiedad
# rara: se verifica por lo que falta, no por lo que hay.
if toca 12; then
    titulo 12 "LA AUSENCIA ES LA FRONTERA · lo que no se puede expresar no se configura mal"
    AUSENCIAS=()
    presente() { grep -qE "$2" "$1" 2>/dev/null; }
    presente server/crates/aegis-share/src/puente.rs "^    Orden \{" \
        && AUSENCIAS+=("aegis-share::puente::Carga tiene una variante Orden")
    presente crates/aegis-invitado/src/protocolo.rs "^    (Ejecutar|Orden|Mandato)" \
        && AUSENCIAS+=("aegis-invitado::protocolo::Evento tiene una variante que es una orden")
    grep -A 12 "pub enum Salida" server/crates/aegis-detonate/src/frontera.rs 2>/dev/null \
        | grep -qE "^    (Real|RedReal|Internet)" \
        && AUSENCIAS+=("aegis-detonate::frontera::Salida tiene una variante de red real")
    SALIDAS=$(grep -A 12 "pub enum Salida" server/crates/aegis-detonate/src/frontera.rs 2>/dev/null | grep -cE "^    (Ninguna|Simulada),")
    # FASE 92: la auditoria de firmware no puede escribir. El unico tipo que abre
    # ficheros no tiene operacion de escritura, el lector fisico no tiene wrmsr ni
    # escritura de memoria, y en todo el crate no hay una sola apertura para
    # escribir. Por lo que FALTA, como el resto de esta invariante.
    if awk '/^impl LecturaSolo/,/^}/' crates/aegis-fwaudit/src/solo_lectura.rs 2>/dev/null \
        | grep -qE 'fn +(escribir|write|truncar|set_len)'; then
        AUSENCIAS+=("aegis-fwaudit::LecturaSolo tiene una operacion de escritura")
    fi
    if awk '/^pub trait LectorFisico/,/^}/' crates/aegis-fwaudit/src/msr.rs 2>/dev/null \
        | grep -qE 'fn +(escribir|write|wrmsr)'; then
        AUSENCIAS+=("aegis-fwaudit::LectorFisico tiene una operacion de escritura")
    fi
    # Solo el codigo de produccion: lo que va antes de `#[cfg(test)]`. Las
    # pruebas SI crean ficheros temporales, y eso no es el producto.
    for f in crates/aegis-fwaudit/src/*.rs; do
        if awk '/#\[cfg\(test\)\]/{exit} {print}' "$f" \
            | grep -vE '^\s*//' \
            | grep -qE '\.(write|append|create|truncate)\(true\)|O_WRONLY|O_RDWR|fs::write\(|File::create\(|OpenOptions::new\(\)\.write'; then
            AUSENCIAS+=("aegis-fwaudit abre algo para escribir en $(basename "$f")")
        fi
    done
    # FASE 93: el confinamiento no rompe al cliente. El modo por defecto es el que
    # no bloquea nada, y la confirmacion que exige el obligatorio no tiene valor
    # por defecto ni campos publicos con los que fabricarla.
    if ! grep -B1 -A1 '#\[default\]' crates/aegis-confinar/src/modo.rs 2>/dev/null | grep -q 'Aprendiendo,'; then
        AUSENCIAS+=("aegis-confinar::Modo no tiene Aprendiendo como modo por defecto")
    fi
    if awk '/^pub struct Confirmacion/,/^}/' crates/aegis-confinar/src/modo.rs 2>/dev/null | grep -qE '^\s+pub '; then
        AUSENCIAS+=("aegis-confinar::Confirmacion tiene campos publicos: se puede fabricar sin autor ni motivo")
    fi
    if grep -qE 'impl Default for Confirmacion|derive\(.*Default.*\)\]\s*$' <(grep -B3 'pub struct Confirmacion' crates/aegis-confinar/src/modo.rs 2>/dev/null); then
        AUSENCIAS+=("aegis-confinar::Confirmacion tiene valor por defecto")
    fi
    if [ ${#AUSENCIAS[@]} -eq 0 ] && [ "$SALIDAS" = "2" ]; then
        veredicto 12 "la ausencia es la frontera" si "6 tipos sin su variante peligrosa (la auditoria de firmware no puede escribir; el confinamiento no nace obligatorio ni se confirma sin autor); la salida de la detonacion tiene 2 y ninguna es red real"
        porque "Es la unica clase de garantia que no depende de que el codigo de"
        porque "comprobacion este bien: si la variante no existe, no hay configuracion,"
        porque "error ni atacante que la produzca. Por eso se verifica por lo que FALTA."
    else
        veredicto 12 "la ausencia es la frontera" no "${AUSENCIAS[*]:-la salida de la detonacion tiene $SALIDAS variantes}"
    fi
fi

# ── 13. EL IDENTIFICADOR UNICO ─────────────────────────────────────────────────
if toca 13; then
    titulo 13 "EL IDENTIFICADOR UNICO · la union de la FASE 79 se mantiene"
    if pruebas servidor aegis-tejido "--test circuito" "" /tmp/inv-identificador.log; then
        veredicto 13 "el identificador unico" si "$(pasadas /tmp/inv-identificador.log) prueba(s): once subsistemas, un identificador"
        porque "Es lo que un conjunto de productos integrados no puede dar: cada uno nombra"
        porque "las cosas a su manera y la correlacion acaba siendo una heuristica sobre"
        porque "cadenas de texto que casi acierta. Aqui el identificador se DERIVA de los"
        porque "hechos, asi que dos observadores llegan al mismo nombre sin hablar — que es"
        porque "justo lo que hace falta durante un corte de red."
    else
        veredicto 13 "el identificador unico" no "ver /tmp/inv-identificador.log"
        tail -25 /tmp/inv-identificador.log | sed 's/^/     | /'
    fi
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s==> Las trece invariantes siguen en pie%s\n' "$VERDE" "$FIN"
else
    printf '%s==> %s invariante(s) ROTAS%s\n' "$ROJO" "$FALLOS" "$FIN"
    for r in "${ROTAS[@]}"; do
        printf '%s    %s%s\n' "$ROJO" "$r" "$FIN"
    done
    printf '%s    Esta puerta tiene derecho de veto: se arregla DE RAIZ antes de dar el%s\n' "$ROJO" "$FIN"
    printf '%s    trabajo por terminado, aunque obligue a volver sobre una fase anterior.%s\n' "$ROJO" "$FIN"
fi
exit "$FALLOS"
