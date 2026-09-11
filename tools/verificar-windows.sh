#!/usr/bin/env bash
#
# Verificacion de la paridad de defensa en Windows (FASE 47).
#
# QUE SE PUEDE COMPROBAR AQUI Y QUE NO
# ------------------------------------
# El driver solo se compila con el WDK, en Windows. Pero la parte que puede
# estar MAL de forma peligrosa no es la fontaneria del driver: es la DECISION.
# Quitar un bit de acceso de mas deja al usuario sin poder ver su propio gestor
# de tareas —y la reaccion normal a una maquina que parece rota es desinstalar
# el EDR—; quitar uno de menos deja al atacante matar el agente.
#
# Esa decision es C portable y se ejercita aqui, con gcc Y con clang, igual que
# el ABI compartido (tools/abi-check.sh). Los dos compiladores porque un
# comportamiento que dependa del compilador en codigo que decide si el producto
# se defiende es, por si mismo, un defecto.
#
# Ademas se comprueba estaticamente el DESPACHO del driver, que es codigo que no
# se puede ejecutar aqui: que la rama de proceso llama a la politica de proceso
# y la de hilo a la de hilo. Al escribir este modulo, esa comprobacion encontro
# un error de copia-pega real —la rama de DUPLICATE de proceso llamaba a la
# politica de hilo— que habria permitido recuperar derechos peligrosos
# duplicando un handle ya abierto: las mascaras de proceso y de hilo comparten
# numeros pero significan cosas distintas, asi que el recorte no habria fallado
# de forma visible.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

POLITICA=kernel/windows/aegis/aegis_politica.c
SONDA=tools/windows_politica_probe.c
DRIVER=kernel/windows/aegis/obcallbacks.c

RB_POLITICA=kernel/windows/aegis/aegis_rollback_politica.c
RB_SONDA=tools/rollback_politica_probe.c

TAMPER_POLITICA=kernel/windows/aegis/aegis_tamper_politica.c
TAMPER_SONDA=tools/tamper_politica_probe.c

# --- 1. La decision, con los dos compiladores -------------------------------
for CC in gcc clang; do
    command -v "$CC" >/dev/null 2>&1 || { echo "  omitido: no hay $CC"; continue; }
    echo "==> Politica de auto-defensa ($CC)"
    if "$CC" -std=c11 -Wall -Wextra -Werror -o "$OUT/probe-$CC" "$SONDA" "$POLITICA" \
       && "$OUT/probe-$CC"; then
        :
    else
        echo "  ${ROJO}FALLO${FIN}: la politica de auto-defensa no se cumple con $CC" >&2
        FALLOS=$((FALLOS + 1))
    fi

    # La politica del minifilter de rollback (FASE 50): misma logica de
    # separacion que la FASE 47. Decidir mal aqui llena el disco del cliente
    # (interceptar de mas) o deja ficheros sin poder revertir (de menos).
    if [ -f "$RB_SONDA" ]; then
        echo "==> Politica de rollback ($CC)"
        if "$CC" -std=c11 -Wall -Wextra -Werror -o "$OUT/rbprobe-$CC" "$RB_SONDA" "$RB_POLITICA" \
           && "$OUT/rbprobe-$CC"; then
            :
        else
            echo "  ${ROJO}FALLO${FIN}: la politica de rollback no se cumple con $CC" >&2
            FALLOS=$((FALLOS + 1))
        fi
    fi

    # La politica de tamper protection (autodefensa, FASE 55'): misma logica de
    # separacion. Decidir mal aqui deja a un atacante borrar el EDR (de menos) o
    # impide al DUENO desinstalarlo (de mas). La afirmacion central es la linea
    # etica: con el OTP del Control Plane, la eliminacion se permite.
    if [ -f "$TAMPER_SONDA" ]; then
        echo "==> Politica de tamper ($CC)"
        if "$CC" -std=c11 -Wall -Wextra -Werror -o "$OUT/tamperprobe-$CC" "$TAMPER_SONDA" "$TAMPER_POLITICA" \
           && "$OUT/tamperprobe-$CC"; then
            :
        else
            echo "  ${ROJO}FALLO${FIN}: la politica de tamper no se cumple con $CC" >&2
            FALLOS=$((FALLOS + 1))
        fi
    fi
done

# --- 2. El despacho del driver, estaticamente -------------------------------
#
# Se aisla cada rama por su tipo de objeto y se comprueba que solo aparece la
# politica que le corresponde.
echo "==> Despacho del driver (PsProcessType / PsThreadType)"

rama_proceso="$(awk '/Info->ObjectType == \*PsProcessType/,/Info->ObjectType == \*PsThreadType/' "$DRIVER")"
rama_hilo="$(awk '/Info->ObjectType == \*PsThreadType/,/^    }$/' "$DRIVER")"

if printf '%s' "$rama_proceso" | grep -q "aegis_filtrar_acceso_hilo"; then
    echo "  ${ROJO}FALLO${FIN}: la rama de PROCESO llama a la politica de HILO." >&2
    echo "         Un handle de proceso recortado con la mascara de hilo conserva" >&2
    echo "         derechos peligrosos: los numeros coinciden, los significados no." >&2
    FALLOS=$((FALLOS + 1))
fi
if printf '%s' "$rama_hilo" | grep -q "aegis_filtrar_acceso_proceso"; then
    echo "  ${ROJO}FALLO${FIN}: la rama de HILO llama a la politica de PROCESO." >&2
    FALLOS=$((FALLOS + 1))
fi

# Las dos operaciones tienen que estar cubiertas: si solo se recortara CREATE,
# bastaria con duplicar un handle ya abierto para recuperar todos los derechos.
for op in OB_OPERATION_HANDLE_CREATE OB_OPERATION_HANDLE_DUPLICATE; do
    n="$(grep -c "$op" "$DRIVER" || true)"
    # Una vez en el registro de cada tipo de objeto y una en cada despacho.
    if [ "$n" -lt 4 ]; then
        echo "  ${ROJO}FALLO${FIN}: $op aparece $n veces; hace falta cubrir proceso e hilo." >&2
        FALLOS=$((FALLOS + 1))
    fi
done

# Desregistrar es obligatorio: dejar los callbacks puestos con el codigo
# descargado es un pantallazo azul en la siguiente apertura de handle.
if ! grep -q "ObUnRegisterCallbacks" "$DRIVER"; then
    echo "  ${ROJO}FALLO${FIN}: no se desregistran los callbacks al descargar." >&2
    FALLOS=$((FALLOS + 1))
fi

if [ "$FALLOS" -eq 0 ]; then
    echo "  ${VERDE}OK${FIN}"
fi

# --- 3. Lo que NO se pudo comprobar -----------------------------------------
printf '%s==>%s Driver WDK: %sno se compila aqui%s (hace falta WDK y Windows).\n' \
    "$GRIS" "$FIN" "$GRIS" "$FIN"
printf '    La decision SI se comprueba, arriba. La fontaneria del driver no.\n'

exit "$FALLOS"
