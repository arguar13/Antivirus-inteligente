#!/usr/bin/env bash
#
# Verifica que todos los enlaces relativos de los .md apuntan a ficheros que
# existen. Un blueprint con enlaces rotos deja de ser navegable justo cuando
# alguien nuevo intenta orientarse en el.
set -uo pipefail

cd "$(dirname "$0")/.."
fallos=0
total=0

while IFS= read -r md; do
    dir="$(dirname "$md")"
    # Extrae los destinos de los enlaces markdown, descartando URLs y anclas.
    while IFS= read -r destino; do
        [ -z "$destino" ] && continue
        case "$destino" in
            http://*|https://*|mailto:*|\#*) continue ;;
        esac
        destino="${destino%%#*}"          # quitar ancla
        [ -z "$destino" ] && continue
        total=$((total + 1))
        if [ ! -e "$dir/$destino" ]; then
            echo "ROTO: $md -> $destino" >&2
            fallos=$((fallos + 1))
        fi
    done < <(grep -oE '\]\([^)]+\)' "$md" | sed -E 's/^\]\(//; s/\)$//')
# docs/plantillas/ se salta A PROPOSITO, no por comodidad: la plantilla del
# README se convierte en el README de la raiz, asi que sus enlaces son relativos
# a la raiz y aqui parecerian rotos. Se comprueban de verdad donde valen: en el
# README.md generado, que lleva exactamente los mismos enlaces.
done < <(find . -name '*.md' -not -path './target/*' -not -path './.git/*' \
             -not -path './docs/plantillas/*')

if [ "$fallos" -gt 0 ]; then
    echo "FALLO: $fallos de $total enlaces relativos estan rotos." >&2
    exit 1
fi
echo "OK: $total enlaces relativos verificados."
