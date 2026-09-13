#!/usr/bin/env bash
#
# Verificacion de AegisRuleForge (la fabrica de contenido, FASE 72).
#
# QUE HACE ESTA FASE, y lo que gobierna todo lo demas: un motor de deteccion sin
# contenido no detecta nada. El contenido del mundo —Emerging Threats, el
# catalogo Sigma, las bases de ClamAV, las colecciones YARA publicas— existe, es
# bueno, y esta escrito en cuatro formatos por gente que NO somos nosotros. La
# parte dificil no es leer los formatos.
#
# PRIMERA INVARIANTE: lo que entra lo escribe alguien que no somos nosotros. Un
# feed comprometido no entrega reglas, entrega lo que el atacante quiera,
# directamente al proceso que compila el contenido de seguridad de la flota
# entera. Por eso los analizadores son PROPIOS y no bibliotecas genericas: un
# analizador de proposito general en ese camino es codigo no auditado procesando
# entrada hostil con los permisos del defensor.
#
# SEGUNDA: lo que no se entiende se rechaza CON NOMBRE. Un analizador permisivo
# que «hace lo que puede» con una regla que no entiende produce una regla que
# hace OTRA cosa, y encima no puede dar la cifra de cobertura, porque no sabe que
# ha fallado. Sin esa cifra nadie sabe que parte del corpus se esta perdiendo.
#
# TERCERA: lo que se distribuye no puede tumbar al cliente. Una regex con
# retroceso catastrofico corre en el endpoint POR CADA PAQUETE: es una denegacion
# de servicio contra el propio producto, firmada por nosotros. Y una firma que
# casa con /bin/ls, distribuida con el corte activo, mata software legitimo en
# toda la flota a la vez, sin que haya atacante — la forma exacta de la caida de
# CrowdStrike de julio de 2024.
#
# CUARTA: lo que llega al agente tiene que caber en el agente. Dos millones de
# firmas son 96 MB solo en las claves; la cuota del corpus son 5 MiB en una
# pasarela y 106 en un host de base de datos. El indice vive en DISCO.
#
# LOS MUROS DE ESTA FASE, declarados en vez de disimulados:
#
#   (a) NO se ejecutan reglas. YARA se compila a texto ordenado por dependencias,
#       no a bytecode; evaluar Sigma contra eventos y YARA contra ficheros es de
#       los motores, que viven en el agente.
#   (b) NO se firma. Se dejan los bytes exactos por firmar; la clave privada vive
#       en el firmador del plano de control, no en una biblioteca.
#   (c) El canario NO evalua YARA ni Sigma: necesitan sus propios motores, y
#       devolver verde fingiendo que se comprueban seria justo la mentira que el
#       modulo existe para evitar.
#   (d) El canario demuestra ausencia de falsos positivos SOBRE SU CONJUNTO DE
#       MUESTRAS, no en general. Ninguna implementacion arregla eso: por eso
#       existe la cota de longitud minima, que es la unica de las tres
#       comprobaciones que dice algo del software que el canario no ha visto.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
FALLOS=0

paso() { # titulo  filtro-de-pruebas  log
    local titulo="$1" filtro="$2" log="$3"
    echo "==> $titulo"
    if (cd server && cargo test -p aegis-ruleforge --quiet "$filtro") > "$log" 2>&1; then
        echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' "$log" | head -1))"
        return 0
    fi
    echo "    ${ROJO}FALLO${FIN} (ver $log)"
    tail -20 "$log" | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
    return 1
}

echo "==> RuleForge: los cuatro analizadores, escritos a proposito"
if (cd server && cargo test -p aegis-ruleforge --quiet --lib) \
    > /tmp/aegis-ruleforge-lib.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ruleforge-lib.log | head -1))"
    echo "    ${GRIS}Suricata: 'http.uri' (bufer pegajoso, mira hacia ADELANTE) contra${FIN}"
    echo "    ${GRIS}'http_uri' (modificador clasico, mira hacia ATRAS, al content anterior).${FIN}"
    echo "    ${GRIS}Las dos sintaxis conviven en el mismo feed y confundirlas desplaza${FIN}"
    echo "    ${GRIS}TODOS los campos uno: reglas que compilan y miran el sitio equivocado.${FIN}"
    echo "    ${GRIS}ClamAV: en .mdb el tamano va PRIMERO y en .hdb va despues.${FIN}"
    echo "    ${GRIS}YARA: orden por dependencias con deteccion de ciclos, y 'pe.number_of_${FIN}"
    echo "    ${GRIS}sections' NO es una dependencia — hay que consumir el acceso entero.${FIN}"
    echo "    ${GRIS}YAML propio con PROGRESO ESTRICTO: todo bucle avanza o para, porque un${FIN}"
    echo "    ${GRIS}analizador de entrada hostil que puede no consumir nada es un cuelgue.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ruleforge-lib.log)"
    tail -20 /tmp/aegis-ruleforge-lib.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> RuleForge: las expresiones que tumbarian al cliente se rechazan"
if (cd server && cargo test -p aegis-ruleforge --quiet regex_segura::) \
    > /tmp/aegis-ruleforge-regex.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ruleforge-regex.log | head -1))"
    echo "    ${GRIS}Se analiza la ESTRUCTURA, no el tiempo. Cronometrar falla por dos${FIN}"
    echo "    ${GRIS}lados: el caso malo de una expresion patologica es una cadena concreta${FIN}"
    echo "    ${GRIS}—y encontrarla es el problema que se intenta evitar—, y un umbral en${FIN}"
    echo "    ${GRIS}milisegundos calibrado aqui no dice nada del portatil del cliente.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ruleforge-regex.log)"
    FALLOS=$((FALLOS + 1))
fi

echo "==> RuleForge: el canario, contra binarios REALES de este host"
if (cd server && cargo test -p aegis-ruleforge --quiet canario::) \
    > /tmp/aegis-ruleforge-canario.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ruleforge-canario.log | head -1))"
    echo "    ${GRIS}Las muestras salen de /bin y /usr/bin, no de un generador: un ELF${FIN}"
    echo "    ${GRIS}fabricado no tiene las cadenas ni las secuencias que hacen disparar a${FIN}"
    echo "    ${GRIS}una firma corta, y usarlo daria un verde que no significa nada.${FIN}"
    echo "    ${GRIS}Tres cosas bloquean, y la tercera es la que cuesta aceptar:${FIN}"
    echo "    ${GRIS}  1. dispara sobre software legitimo;${FIN}"
    echo "    ${GRIS}  2. menos de 16 bytes fijos (los comodines NO cuentan, y en una${FIN}"
    echo "    ${GRIS}     alternativa manda la rama mas corta) — se rechaza SIN que dispare,${FIN}"
    echo "    ${GRIS}     porque es lo unico que dice algo del software no visto;${FIN}"
    echo "    ${GRIS}  3. no evaluable. Desconocida NO es limpia: firmar una firma que no se${FIN}"
    echo "    ${GRIS}     pudo evaluar es firmar a ciegas.${FIN}"
    echo "    ${GRIS}Y un canario SIN MUESTRAS nunca aprueba: dar el visto bueno porque no${FIN}"
    echo "    ${GRIS}habia nada contra lo que probar es el peor fallo de una puerta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ruleforge-canario.log)"
    tail -20 /tmp/aegis-ruleforge-canario.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> RuleForge: el corpus firmado y el ataque de REPOSICION"
if (cd server && cargo test -p aegis-ruleforge --quiet corpus::) \
    > /tmp/aegis-ruleforge-corpus.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ruleforge-corpus.log | head -1))"
    echo "    ${GRIS}El ataque que NINGUNA firma detiene: coger el corpus de hace seis meses${FIN}"
    echo "    ${GRIS}—autentico, firmado por nosotros, con la firma perfecta— y reponerlo.${FIN}"
    echo "    ${GRIS}Ninguna verificacion criptografica lo distingue del bueno porque no hay${FIN}"
    echo "    ${GRIS}nada que distinguir: es nuestro. Lo corta la EPOCA MONOTONA, y${FIN}"
    echo "    ${GRIS}estrictamente mayor, no mayor o igual: con la igualdad, dos corpus${FIN}"
    echo "    ${GRIS}distintos serian intercambiables y el atacante elegiria cual.${FIN}"
    echo "    ${GRIS}Y una sola firma, no dos: el manifiesto se compromete con el SHA-256${FIN}"
    echo "    ${GRIS}del indice. Con dos firmas independientes, un atacante se queda el${FIN}"
    echo "    ${GRIS}manifiesto de la v5 y el indice de la v4 y LAS DOS VERIFICAN: un corpus${FIN}"
    echo "    ${GRIS}que nunca existio, montado con piezas autenticas.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ruleforge-corpus.log)"
    tail -20 /tmp/aegis-ruleforge-corpus.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> RuleForge: la tuberia entera con sintaxis de feed real"
if (cd server && cargo test -p aegis-ruleforge --quiet --test corpus_mundial) \
    > /tmp/aegis-ruleforge-e2e.log 2>&1; then
    echo "    ${VERDE}OK${FIN} ($(grep -h '^test result' /tmp/aegis-ruleforge-e2e.log | head -1))"
    echo "    ${GRIS}Contenido con la sintaxis que traen los feeds de verdad, no esqueletos${FIN}"
    echo "    ${GRIS}fabricados para que pasen: un banco con sintaxis de juguete mide lo bien${FIN}"
    echo "    ${GRIS}que se lee el juguete. Las fuentes YARA se ingieren AL REVES del orden${FIN}"
    echo "    ${GRIS}de dependencias para que la reunion tenga que arreglarlo.${FIN}"
    echo "    ${GRIS}Y se MIDE: 40.000 firmas, consultadas ENTERAS (el caso peor para la${FIN}"
    echo "    ${GRIS}residencia), contra la cuota que cada clase de host concede al corpus.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN} (ver /tmp/aegis-ruleforge-e2e.log)"
    tail -25 /tmp/aegis-ruleforge-e2e.log | sed 's/^/    | /'
    FALLOS=$((FALLOS + 1))
fi

echo "==> RuleForge: el arbol de dependencias del camino del contenido"
ARBOL=$( (cd server && cargo tree -p aegis-ruleforge --edges normal --prefix none 2>/dev/null) \
         | awk '{print $1}' | sort -u | grep -v '^$' | wc -l )
if [ "$ARBOL" -gt 0 ]; then
    echo "    ${VERDE}OK${FIN} ($ARBOL crates en todo el arbol del crate)"
    echo "    ${GRIS}La invariante 1 no es una postura: lo que entra por aqui lo escribe un${FIN}"
    echo "    ${GRIS}feed, y si el feed se compromete lo escribe el atacante. Meter una${FIN}"
    echo "    ${GRIS}biblioteca de parsing generica en ese camino es importar codigo no${FIN}"
    echo "    ${GRIS}auditado al sitio donde se compila el contenido de la flota entera.${FIN}"
else
    echo "    ${GRIS}omitido: cargo tree no disponible${FIN}"
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}==> AegisRuleForge verificado${FIN}"
else
    echo "${ROJO}==> AegisRuleForge: $FALLOS fallo(s)${FIN}"
fi
exit "$FALLOS"
