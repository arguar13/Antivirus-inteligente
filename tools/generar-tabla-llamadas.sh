#!/usr/bin/env bash
#
# Genera `crates/aegis-sandbox/src/tabla_x86_64.rs` a partir de la cabecera
# REAL del kernel (`asm/unistd_64.h`).
#
# POR QUE GENERADA Y NO ESCRITA A MANO
#
# Un perfil aprendido nombra cientos de llamadas por su numero. Un numero
# equivocado no da error: confina la llamada que no es y deja pasar la que
# importaba. Escribir 385 numeros de memoria es garantizar alguno mal. Se generan
# de la cabecera, y `aegis-sandbox` tiene una prueba que vuelve a cotejar la
# tabla contra la cabecera de la maquina cada vez que esta existe.
set -euo pipefail
cd "$(dirname "$0")/.."
CAB="${1:-/usr/include/x86_64-linux-gnu/asm/unistd_64.h}"
SAL=crates/aegis-sandbox/src/tabla_x86_64.rs
{
    echo "//! Tabla de llamadas al sistema de x86-64: numero y nombre."
    echo "//!"
    echo "//! GENERADA por \`tools/generar-tabla-llamadas.sh\` desde \`$(basename "$CAB")\`."
    echo "//! No se edita a mano: un numero equivocado confina la llamada que no es."
    echo "//! La prueba \`la_tabla_casa_con_la_cabecera_del_kernel\` la vuelve a cotejar."
    echo
    echo "/// (numero, nombre), ordenada por numero."
    echo "pub const LLAMADAS: &[(u32, &str)] = &["
    grep -E '^#define __NR_[a-z0-9_]+ [0-9]+$' "$CAB" \
        | awk '{ sub("__NR_", "", $2); printf "    (%d, \"%s\"),\n", $3, $2 }' \
        | sort -t'(' -k2 -n
    echo "];"
} > "$SAL"
echo "$(grep -c '^    (' "$SAL") llamadas escritas en $SAL"
