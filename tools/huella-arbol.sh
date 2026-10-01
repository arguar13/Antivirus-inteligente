#!/usr/bin/env bash
#
# La huella del arbol de trabajo: lo comiteado, lo modificado y lo que no esta en
# el indice. Imprime un SHA-256 y sale con 0, o sale con 1 sin imprimir nada.
#
# Es la UNICA definicion de «este arbol». La usan:
#   - tools/ci-local.sh, para que `--reanudar` no junte verdes de arboles
#     distintos;
#   - tools/ci/hermetico.sh y tools/matriz-kernels/construir-cruzado.sh, que la
#     graban junto a los binarios que construyen (fichero HUELLA);
#   - `cargo xtask kernels ejecutar`, que se niega a arrancar la matriz si el
#     agente que va a probar no se construyo sobre este arbol.
#
# Por que existe como fichero y no como funcion copiada: la matriz de kernels
# llego a probar en x86-64 un agente construido en una tanda anterior —el grupo
# `kernels` tomaba el de dist-hermetico/ sin preguntar de que arbol salia— y los
# motores nuevos no estaban en las VMs (FASE 2 del MP-16). Dos copias de esta
# definicion divergirian igual que divergieron el binario y el arbol.
#
# FALLA EN VEZ DE INVENTARSE UN VALOR: si git no responde sobre este arbol (por
# ejemplo, «dubious ownership» al correr como root sobre un repositorio de otro
# usuario), un valor por defecto haria que dos arboles distintos parecieran el
# mismo. Lo correcto es decirlo y parar.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

git rev-parse HEAD >/dev/null 2>&1 || exit 1
{
    git rev-parse HEAD
    git diff HEAD --binary
    git ls-files --others --exclude-standard | sort | while read -r f; do
        printf '%s ' "$f"
        sha256sum "$f" 2>/dev/null || echo "?"
    done
} | sha256sum | cut -d' ' -f1
