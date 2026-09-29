# Utilidades compartidas por los scripts de job del pipeline.
#
# Se carga con `source`. Da un formato de salida uniforme y, sobre todo, una
# semantica clara de tres estados: OK, FALLO y OMITIDO. Un job que no puede
# correr en esta maquina (falta el kernel, falta una herramienta) se OMITE
# diciendolo; jamas se hace pasar por exito.

VERDE=$'\033[32m'; ROJO=$'\033[31m'; AMARILLO=$'\033[33m'
GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'

# Raiz del repositorio, sea cual sea el directorio desde el que se invoque.
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

titulo() { printf '\n%s== %s ==%s\n' "$NEGRITA" "$1" "$FIN"; }
paso()   { printf '%s==>%s %s\n' "$GRIS" "$FIN" "$1"; }
ok()     { printf '    %sOK%s %s\n' "$VERDE" "$FIN" "${1:-}"; }
fallo()  { printf '    %sFALLO%s %s\n' "$ROJO" "$FIN" "${1:-}"; }
omitido(){ printf '    %sOMITIDO%s %s\n' "$AMARILLO" "$FIN" "${1:-}"; }

# Ejecuta un comando mostrando su nombre; devuelve su codigo de salida.
# La salida se guarda en un log y solo se vuelca si falla, para que el pipeline
# sea legible cuando todo va bien y exhaustivo cuando algo se rompe.
correr() {
    local nombre="$1"; shift
    local log; log="$(mktemp)"
    paso "$nombre"
    if "$@" > "$log" 2>&1; then
        ok
        rm -f "$log"
        return 0
    fi
    fallo
    tail -40 "$log" | sed 's/^/      | /'
    rm -f "$log"
    return 1
}

# Indica si un comando existe.
hay() { command -v "$1" >/dev/null 2>&1; }
