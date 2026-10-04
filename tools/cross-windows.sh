#!/usr/bin/env bash
#
# Compilacion cruzada del driver de Windows desde Linux (FASE 48).
#
# EL HUECO QUE CIERRA
# -------------------
# FASE 47 dejo el driver de auto-defensa de Windows sin compilar en el CI: el
# pipeline corre en Linux y el driver "solo se compila con el WDK, en Windows".
# Eso es cierto para la FONTANERIA del driver —lo que incluye <ntddk.h>—, pero
# NO para todo. Aqui se cierra el hueco hasta donde las leyes de este entorno
# permiten, y se declara con exactitud donde esta el muro.
#
# QUE SE COMPILA DE VERDAD AQUI
# -----------------------------
# 1. La POLITICA portable (aegis_politica.c) se compila cruzada a un objeto
#    Windows x64 REAL con clang, y se comprueba que la maquina es AMD64 y que
#    exporta sus simbolos. Es el mismo fichero que decide que acceso se recorta
#    y que evento es inyeccion: la parte que puede estar mal de forma peligrosa.
# 2. La cadena de ENLACE (clang -> lld-link) se demuestra produciendo un .sys
#    PE valido de subsistema NATIVE que CONTIENE el codigo real de la politica,
#    enlazado con un DriverEntry minimo. Esto prueba que la cadena cruzada
#    entera —compilar y enlazar a formato driver— funciona sobre codigo real del
#    proyecto, sin Windows y sin el WDK.
#
# EL MURO, DECLARADO
# ------------------
# El driver de PRODUCCION completo (obcallbacks.c, driver.c) incluye <ntddk.h> y
# <fltKernel.h>, que solo vienen con el Windows Driver Kit. El WDK esta
# licenciado y no es redistribuible dentro de un CI de Linux. Por eso la
# compilacion del .sys completo esta condicionada a $WDK_ROOT: si apunta a un WDK
# montado, se compila; si no, se OMITE con aviso —nunca se finge—.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; ROJO=$'\033[31m'; GRIS=$'\033[90m'; FIN=$'\033[0m'
FALLOS=0
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

TARGET="x86_64-pc-windows-msvc"
DRV=kernel/windows/aegis
POLITICA="$DRV/aegis_politica.c"

command -v clang >/dev/null 2>&1     || { echo "${ROJO}FALLO${FIN}: sin clang"; exit 1; }
command -v lld-link >/dev/null 2>&1  || { echo "${ROJO}FALLO${FIN}: sin lld-link"; exit 1; }

# --- 1. La politica real, a objeto Windows x64 ------------------------------
echo "==> Politica portable -> objeto Windows x64 ($TARGET)"
if clang --target="$TARGET" -ffreestanding -O2 -Wall -Wextra -Werror \
     -c "$POLITICA" -o "$OUT/politica.obj" 2>"$OUT/clang.err"; then
    maquina="$(llvm-readobj --file-headers "$OUT/politica.obj" 2>/dev/null | awk -F'[()]' '/Machine:/{print $2}' | tr -d ' ')"
    if [ "$maquina" = "0x8664" ]; then
        echo "    ${VERDE}OK${FIN}  objeto COFF x86-64 (IMAGE_FILE_MACHINE_AMD64)"
    else
        echo "    ${ROJO}FALLO${FIN}: maquina inesperada '$maquina' (se esperaba 0x8664)"; FALLOS=$((FALLOS+1))
    fi
    for sim in aegis_filtrar_acceso_proceso aegis_filtrar_acceso_hilo aegis_clasificar_etwti; do
        if ! llvm-nm "$OUT/politica.obj" 2>/dev/null | grep >/dev/null " T $sim$"; then
            echo "    ${ROJO}FALLO${FIN}: el objeto no exporta $sim"; FALLOS=$((FALLOS+1))
        fi
    done
else
    echo "    ${ROJO}FALLO${FIN}: la politica no compila para Windows"; sed 's/^/      /' "$OUT/clang.err"; FALLOS=$((FALLOS+1))
fi

# --- 2. La cadena de enlace, a un .sys PE real ------------------------------
#
# Un DriverEntry minimo que LLAMA a la politica real, para forzar que el codigo
# de la politica entre en el binario enlazado. No es el driver de produccion
# —ese necesita el WDK—; es la prueba de que la cadena clang->lld-link produce
# un driver PE valido a partir de codigo real de este proyecto.
echo "==> Cadena de enlace clang -> lld-link -> .sys PE (subsistema NATIVE)"
cat > "$OUT/entry.c" <<'CEOF'
#include "aegis_politica.h"
/* Firma real de un punto de entrada de driver de Windows, sin depender del WDK:
 * NTSTATUS(*)(PDRIVER_OBJECT, PUNICODE_STRING). Se modelan como punteros opacos
 * para no necesitar <ntddk.h>. Llama a la politica real para enlazarla. */
long __stdcall DriverEntry(void *driver, void *registro)
{
    aegis_contexto_acceso ctx = {0};
    ctx.objetivo_protegido = 1;
    ctx.solicitada = (unsigned)(unsigned long long)driver ^ (unsigned)(unsigned long long)registro;
    /* Devuelve 0 (STATUS_SUCCESS) pero referencia la politica para forzar el
     * enlace de su codigo en el .sys. */
    return (long)(aegis_filtrar_acceso_proceso(&ctx) & 0) ;
}
CEOF
if clang --target="$TARGET" -ffreestanding -O2 -I "$DRV/include" \
     -c "$OUT/entry.c" -o "$OUT/entry.obj" 2>"$OUT/entry.err"; then
    if lld-link "/out:$OUT/aegis-probe.sys" /dll /driver /subsystem:native \
         /entry:DriverEntry /nodefaultlib "$OUT/entry.obj" "$OUT/politica.obj" \
         2>"$OUT/link.err"; then
        fmt="$(llvm-readobj --file-headers "$OUT/aegis-probe.sys" 2>/dev/null)"
        subsis="$(printf '%s' "$fmt" | awk -F'[()]' '/Subsystem:/{print $2}' | tr -d ' ')"
        maq="$(printf '%s' "$fmt" | awk -F'[()]' '/Machine:/{print $2}' | tr -d ' ')"
        if printf '%s' "$fmt" | grep >/dev/null "Format: COFF-x86-64" && [ "$maq" = "0x8664" ]; then
            echo "    ${VERDE}OK${FIN}  .sys PE x86-64 enlazado (subsistema=$subsis); contiene el codigo real de la politica"
        else
            echo "    ${ROJO}FALLO${FIN}: el .sys enlazado no es PE x86-64 (maquina=$maq)"; FALLOS=$((FALLOS+1))
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: lld-link no produjo el .sys"; sed 's/^/      /' "$OUT/link.err"; FALLOS=$((FALLOS+1))
    fi
else
    echo "    ${ROJO}FALLO${FIN}: el punto de entrada no compila"; sed 's/^/      /' "$OUT/entry.err"; FALLOS=$((FALLOS+1))
fi

# --- 2b. La politica del minifilter de rollback (FASE 50), a objeto Windows --
RB_POLITICA="$DRV/aegis_rollback_politica.c"
if [ -f "$RB_POLITICA" ]; then
    echo "==> Politica de rollback -> objeto Windows x64 ($TARGET)"
    if clang --target="$TARGET" -ffreestanding -O2 -Wall -Wextra -Werror \
         -c "$RB_POLITICA" -o "$OUT/rollback.obj" 2>"$OUT/rbclang.err"; then
        maq="$(llvm-readobj --file-headers "$OUT/rollback.obj" 2>/dev/null | awk -F'[()]' '/Machine:/{print $2}' | tr -d ' ')"
        if [ "$maq" = "0x8664" ] && llvm-nm "$OUT/rollback.obj" 2>/dev/null | grep >/dev/null " T aegis_rb_decidir$"; then
            echo "    ${VERDE}OK${FIN}  objeto COFF x86-64 con la decision del minifilter"
        else
            echo "    ${ROJO}FALLO${FIN}: la politica de rollback no cross-compilo bien (maquina=$maq)"; FALLOS=$((FALLOS+1))
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: la politica de rollback no compila para Windows"; sed 's/^/      /' "$OUT/rbclang.err"; FALLOS=$((FALLOS+1))
    fi
fi

# --- 2c. La politica de tamper (autodefensa, FASE 55'), a objeto Windows -----
TAMPER_POLITICA="$DRV/aegis_tamper_politica.c"
if [ -f "$TAMPER_POLITICA" ]; then
    echo "==> Politica de tamper -> objeto Windows x64 ($TARGET)"
    if clang --target="$TARGET" -ffreestanding -O2 -Wall -Wextra -Werror \
         -c "$TAMPER_POLITICA" -o "$OUT/tamper.obj" 2>"$OUT/tamperclang.err"; then
        maq="$(llvm-readobj --file-headers "$OUT/tamper.obj" 2>/dev/null | awk -F'[()]' '/Machine:/{print $2}' | tr -d ' ')"
        if [ "$maq" = "0x8664" ] && llvm-nm "$OUT/tamper.obj" 2>/dev/null | grep >/dev/null " T aegis_decidir_tamper$"; then
            echo "    ${VERDE}OK${FIN}  objeto COFF x86-64 con la decision de tamper"
        else
            echo "    ${ROJO}FALLO${FIN}: la politica de tamper no cross-compilo bien (maquina=$maq)"; FALLOS=$((FALLOS+1))
        fi
    else
        echo "    ${ROJO}FALLO${FIN}: la politica de tamper no compila para Windows"; sed 's/^/      /' "$OUT/tamperclang.err"; FALLOS=$((FALLOS+1))
    fi
fi

# --- 3. El driver de produccion completo: gated por $WDK_ROOT ----------------
echo "==> Driver de produccion completo (obcallbacks.c + driver.c)"
if [ -n "${WDK_ROOT:-}" ] && [ -d "$WDK_ROOT" ]; then
    KM_INC="$WDK_ROOT/Include"
    echo "    WDK_ROOT=$WDK_ROOT — compilando el driver completo"
    # Invocacion real de compilacion de driver KMDF con clang-cl. Las rutas de
    # include del WDK varian por version; se toma la mas reciente bajo Include.
    ver_km="$(ls "$KM_INC" 2>/dev/null | sort -V | tail -1)"
    inc=(-I "$KM_INC/$ver_km/km" -I "$KM_INC/$ver_km/shared" -I "$DRV/include")
    ok=1
    for src in "$DRV/obcallbacks.c" "$DRV/driver.c" "$POLITICA"; do
        obj="$OUT/$(basename "$src" .c).obj"
        if ! clang-cl --target="$TARGET" /kernel /GS- /W4 "${inc[@]}" /c "$src" /Fo"$obj" 2>>"$OUT/wdk.err"; then
            ok=0
        fi
    done
    if [ "$ok" = 1 ] && lld-link "/out:$OUT/aegis.sys" /driver /subsystem:native \
         /entry:DriverEntry "$OUT"/*.obj 2>>"$OUT/wdk.err"; then
        echo "    ${VERDE}OK${FIN}  aegis.sys compilado y enlazado desde Linux (listo para firmar con el EKU antimalware)"
    else
        echo "    ${ROJO}FALLO${FIN}: el driver completo no compilo con el WDK dado"; sed 's/^/      /' "$OUT/wdk.err"; FALLOS=$((FALLOS+1))
    fi
else
    printf '    %sOMITIDO%s: $WDK_ROOT no apunta a un WDK. El .sys completo necesita\n' "$GRIS" "$FIN"
    printf '             <ntddk.h>/<fltKernel.h> del Windows Driver Kit, licenciado y no\n'
    printf '             redistribuible en este CI. La POLITICA (lo que puede estar mal de\n'
    printf '             forma peligrosa) SI se compilo y enlazo arriba, sobre codigo real.\n'
fi

echo
if [ "$FALLOS" -eq 0 ]; then
    echo "${VERDE}Cross-compilacion de Windows: la cadena real funciona sobre codigo real.${FIN}"
else
    echo "${ROJO}Cross-compilacion de Windows: $FALLOS comprobacion(es) fallaron.${FIN}"
fi
exit "$FALLOS"
