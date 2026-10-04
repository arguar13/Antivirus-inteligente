#!/usr/bin/env bash
#
# Puerta: todo script de shell versionado se puede ANALIZAR.
#
# `bash -n` lee el script entero sin ejecutar nada y falla ante un error de
# sintaxis. Es la comprobacion mas barata que existe y la unica que ve un script
# que no ejecuta nadie. tools/ci/artifacts.sh estuvo roto desde fd5a55a —un `)`
# huerfano al cambiar la lista escrita a mano por `cargo xtask instalables`— y
# ninguna puerta lo vio: make ci no lo llama, y los dos sitios que si (el
# workflow de GitHub y tools/local_runner.sh) no se ejecutan. Un script roto que
# nadie ejecuta miente sobre lo que hay: dice que existe un job que no puede
# arrancar.
#
# QUE ES UN SCRIPT
# ----------------
# Todo fichero versionado que termina en `.sh` (los que se cargan con `source`,
# como tools/ci/_comun.sh, no llevan shebang y se leen con bash) y todo el que
# empieza por un shebang de sh o bash, plantillas incluidas.
#
# Los de `#!/bin/sh` se analizan con `sh -n` y no con bash: en Debian y Ubuntu
# `sh` es dash, que es donde corren (tools/matriz-kernels/dentro.sh, dentro de
# cada VM de la matriz), y bash acepta sintaxis que dash rechaza.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

# Shebang de un shell POSIX o de bash, directo (`#!/bin/sh`) o por env
# (`#!/usr/bin/env bash`), con o sin opciones detras.
SHEBANG_SHELL='^#!.*[/[:space:]](ba)?sh([[:space:]]|$)'
SHEBANG_SH='^#!.*[/[:space:]]sh([[:space:]]|$)'

TOTAL=0
MALOS=0
while IFS= read -r -d '' f; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    primera=""
    IFS= read -r -n 160 primera < "$f" 2>/dev/null || true
    case "$f" in
        *.sh) ;;
        *) [[ "$primera" =~ $SHEBANG_SHELL ]] || continue ;;
    esac
    if [[ "$primera" =~ $SHEBANG_SH ]]; then
        interprete=sh
    else
        interprete=bash
    fi
    TOTAL=$((TOTAL + 1))
    if ! salida="$("$interprete" -n "$f" 2>&1)"; then
        MALOS=$((MALOS + 1))
        printf '%s (%s -n):\n' "$f" "$interprete"
        printf '%s\n' "$salida" | sed 's/^/    /'
    fi
    # Con `pipefail`, `productor | grep -q` es una carrera: grep sale en la
    # primera coincidencia, el productor que sigue escribiendo muere por SIGPIPE
    # y la tuberia entera cuenta como fallo. Asi tools/empaquetar.sh dijo «el
    # .deb no lleva aegis-agent» justo despues de encontrarlo, y un
    # `if readelf | grep -q INTERP` podia dar por estatico un binario dinamico.
    # Sin -q grep lee toda la entrada y su codigo de salida es el mismo:
    # `productor | grep >/dev/null PATRON`.
    if [ "$interprete" = bash ] && grep -q pipefail "$f"; then
        carreras="$(awk '
            /^[[:space:]]*#/ { previa = $0; next }
            $0 ~ /\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q/ { print FNR ": " $0 }
            previa ~ /\|[[:space:]]*\\?[[:space:]]*$/ && $0 ~ /^[[:space:]]*grep[[:space:]]+-[A-Za-z]*q/ { print FNR ": " $0 }
            { previa = $0 }
        ' "$f")"
        if [ -n "$carreras" ]; then
            MALOS=$((MALOS + 1))
            printf '%s (pipefail y grep -q detras de una tuberia: usa grep >/dev/null):\n' "$f"
            printf '%s\n' "$carreras" | sed 's/^/    /'
        fi
    fi
done < <(git ls-files -z)

if [ "$TOTAL" -eq 0 ]; then
    echo "no se encontro ningun script: git ls-files no responde en $(pwd)"
    exit 1
fi
if [ "$MALOS" -ne 0 ]; then
    echo "$MALOS de $TOTAL scripts no se pueden analizar"
    exit 1
fi
echo "$TOTAL scripts analizados sin errores de sintaxis"
