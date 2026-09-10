#!/usr/bin/env bash
#
# Runner local del pipeline de GitHub Actions (FASE 36).
#
# POR QUE EXISTE
# --------------
# Un pipeline que solo corre en la infraestructura de un tercero es un punto
# unico de fallo: si la cuenta se bloquea, si los runners se agotan o si la
# plataforma cae, el proyecto se queda SIN puerta de calidad justo cuando mas
# falta hace. Este script ejecuta el MISMO pipeline en local, con tres modos por
# orden de fidelidad:
#
#   1. act     - ejecuta el workflow real en contenedores (maxima fidelidad).
#   2. docker  - ejecuta los scripts de job en un contenedor tipo ubuntu-latest.
#   3. nativo  - ejecuta los scripts de job directamente en esta maquina.
#
# COMO SE EVITA LA DERIVA
# -----------------------
# El YAML y este runner NO duplican comandos: los dos invocan los scripts de
# tools/ci/. Ademas, el runner compara su tabla de jobs con la del workflow y
# ABORTA si divergen. Asi es imposible que alguien anada un job al pipeline
# remoto y el local se quede corto sin que nadie se entere.
#
# USO
#   tools/local_runner.sh                # todos los jobs
#   tools/local_runner.sh --job lint     # un job concreto
#   tools/local_runner.sh --list         # lista los jobs
#   tools/local_runner.sh --modo nativo  # fuerza un modo (act|docker|nativo)
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"
source "$RAIZ/tools/ci/_comun.sh"

WORKFLOW=".github/workflows/aegis_ci.yml"
IMAGEN_DOCKER="rust:1.90-bookworm"

# --- Tabla de jobs: nombre -> comando -------------------------------------
# Es el espejo de los jobs de aegis_ci.yml. `gate` es un job agregador del lado
# de GitHub (no ejecuta comandos), asi que aqui lo representa el veredicto final.
declare -a JOBS=(
    "lint"
    "test"
    "ebpf"
    "sanitizers"
    "fuzz-smoke"
    "supply-chain"
    "docs"
    "servidor"
    "despliegue"
    "artifacts"
    "hermetico"
)

comando_de_job() {
    case "$1" in
        lint)         echo "./tools/ci/lint.sh" ;;
        test)         echo "./tools/ci/test.sh" ;;
        ebpf)         echo "./tools/ci/ebpf.sh" ;;
        sanitizers)   echo "./tools/sanitize.sh" ;;
        fuzz-smoke)   echo "./tools/fuzz.sh 20" ;;
        supply-chain) echo "./tools/ci/supply_chain.sh" ;;
        docs)         echo "./tools/check-links.sh" ;;
        servidor)     echo "./tools/ci/servidor.sh" ;;
        despliegue)   echo "./tools/ci/despliegue.sh" ;;
        hermetico)    echo "./tools/ci/hermetico.sh" ;;
        artifacts)    echo "./tools/ci/artifacts.sh" ;;
        *)            echo "" ;;
    esac
}

# --- Deteccion de deriva contra el workflow --------------------------------
# Si el YAML tiene jobs que este runner no conoce (o al reves), el runner deja
# de ser un espejo fiel y hay que saberlo AHORA, no el dia que GitHub se caiga.
comprobar_deriva() {
    [ -f "$WORKFLOW" ] || { fallo "no existe $WORKFLOW"; return 1; }
    local del_yaml
    if hay python3; then
        del_yaml="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
# `gate` es el agregador del lado de GitHub; no tiene equivalente ejecutable.
print("\n".join(j for j in d.get("jobs", {}) if j != "gate"))
PY
)" || { omitido "no se pudo analizar el YAML (falta PyYAML): se omite la deteccion de deriva"; return 0; }
    else
        omitido "sin python3 no se puede comprobar la deriva contra el workflow"
        return 0
    fi

    local faltan_aqui=() faltan_alla=()
    while IFS= read -r j; do
        [ -z "$j" ] && continue
        printf '%s\n' "${JOBS[@]}" | grep -qx "$j" || faltan_aqui+=("$j")
    done <<< "$del_yaml"
    for j in "${JOBS[@]}"; do
        printf '%s\n' "$del_yaml" | grep -qx "$j" || faltan_alla+=("$j")
    done

    if [ "${#faltan_aqui[@]}" -ne 0 ] || [ "${#faltan_alla[@]}" -ne 0 ]; then
        fallo "el runner local y $WORKFLOW han divergido"
        [ "${#faltan_aqui[@]}" -ne 0 ] && \
            echo "      | jobs en el workflow que el runner NO ejecuta: ${faltan_aqui[*]}"
        [ "${#faltan_alla[@]}" -ne 0 ] && \
            echo "      | jobs del runner que ya NO estan en el workflow: ${faltan_alla[*]}"
        echo "      | corrige la tabla JOBS de tools/local_runner.sh"
        return 1
    fi
    ok "el runner refleja los ${#JOBS[@]} jobs del workflow"
    return 0
}

# --- Eleccion del modo ------------------------------------------------------
docker_vivo() { hay docker && docker info >/dev/null 2>&1; }

elegir_modo() {
    if [ -n "${MODO_FORZADO:-}" ]; then echo "$MODO_FORZADO"; return; fi
    if hay act && docker_vivo; then echo "act"; return; fi
    if docker_vivo; then echo "docker"; return; fi
    echo "nativo"
}

# --- Modos de ejecucion -----------------------------------------------------
ejecutar_act() {
    titulo "Modo act: el workflow real en contenedores"
    paso "act -W $WORKFLOW"
    if act -W "$WORKFLOW" --rm; then ok "el workflow completo paso"; return 0; fi
    fallo "act reporto un fallo"; return 1
}

ejecutar_docker() {
    titulo "Modo docker: los jobs en un contenedor tipo ubuntu-latest"
    local fallos=0
    for job in "${SELECCION[@]}"; do
        local cmd; cmd="$(comando_de_job "$job")"
        paso "job: $job (contenedor)"
        if docker run --rm -v "$RAIZ:/repo" -w /repo "$IMAGEN_DOCKER" \
            bash -lc "$cmd" > "/tmp/aegis-runner-$job.log" 2>&1; then
            ok
        else
            fallo; tail -30 "/tmp/aegis-runner-$job.log" | sed 's/^/      | /'
            fallos=$((fallos+1))
        fi
    done
    return $fallos
}

ejecutar_nativo() {
    titulo "Modo nativo: los jobs directamente en esta maquina"
    local fallos=0
    for job in "${SELECCION[@]}"; do
        local cmd; cmd="$(comando_de_job "$job")"
        printf '\n%s---------- job: %s ----------%s\n' "$NEGRITA" "$job" "$FIN"
        if eval "$cmd"; then
            printf '%s[job %s: OK]%s\n' "$VERDE" "$job" "$FIN"
        else
            printf '%s[job %s: FALLO]%s\n' "$ROJO" "$job" "$FIN"
            fallos=$((fallos+1))
        fi
    done
    return $fallos
}

# --- Argumentos -------------------------------------------------------------
SELECCION=("${JOBS[@]}")
MODO_FORZADO=""
while [ $# -gt 0 ]; do
    case "$1" in
        --job)   SELECCION=("$2"); shift 2 ;;
        --modo)  MODO_FORZADO="$2"; shift 2 ;;
        --list)  printf '%s\n' "${JOBS[@]}"; exit 0 ;;
        -h|--help)
            sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) fallo "argumento desconocido: $1"; exit 2 ;;
    esac
done

# --- Ejecucion --------------------------------------------------------------
printf '%s########## Runner local del pipeline AegisCore ##########%s\n' "$NEGRITA" "$FIN"

titulo "Espejo del workflow"
comprobar_deriva || exit 1

MODO="$(elegir_modo)"
titulo "Modo de ejecucion"
case "$MODO" in
    act)    ok "act disponible con daemon de contenedores" ;;
    docker) ok "docker disponible (act no instalado)" ;;
    nativo)
        ok "nativo"
        if hay docker && ! docker_vivo; then
            omitido "hay CLI de docker pero su daemon no responde: se corre en el anfitrion"
        elif ! hay docker; then
            omitido "sin contenedores en esta maquina: se corre en el anfitrion"
        fi
        ;;
    *) fallo "modo desconocido: $MODO"; exit 2 ;;
esac

INICIO=$(date +%s)
case "$MODO" in
    act)    ejecutar_act;    FALLOS=$? ;;
    docker) ejecutar_docker; FALLOS=$? ;;
    nativo) ejecutar_nativo; FALLOS=$? ;;
esac
DURACION=$(( $(date +%s) - INICIO ))

titulo "Puerta de calidad (equivalente al job 'gate')"
printf '    jobs ejecutados : %s\n' "${#SELECCION[@]}"
printf '    modo            : %s\n' "$MODO"
printf '    duracion        : %dm %ds\n' $((DURACION/60)) $((DURACION%60))
echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sPIPELINE LOCAL SUPERADO.%s Equivalente a la puerta de aegis_ci.yml.\n' \
        "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sPIPELINE LOCAL: %d job(s) fallaron.%s\n' "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
