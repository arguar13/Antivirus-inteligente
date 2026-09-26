#!/usr/bin/env bash
#
# Verificacion de AegisConfine (FASE 93): confinamiento derivado del
# comportamiento, ensayado en permisivo, impuesto solo con confirmacion, y que se
# retira solo si rompe algo.
#
# QUE SE AFIRMA, Y CONTRA QUE
#
#   1. La supervision por notificacion de seccomp funciona sobre procesos REALES:
#      cada llamada llega, se deja seguir, y el programa hace exactamente lo mismo
#      que sin supervision. Las estructuras miden lo que el kernel dice que miden.
#   2. La tabla de llamadas sale de la cabecera del kernel y se vuelve a cotejar
#      con ella; la lista blanca y su interprete de BPF, comprobados llamada a
#      llamada sobre la tabla entera.
#   3. El ciclo entero contra el KERNEL: se aprende un programa real, el ensayo
#      permisivo no bloquea nada y anota lo que habria bloqueado, el perfil
#      impuesto deja funcionar lo aprendido y el kernel bloquea lo demas —seccomp
#      el socket, Landlock el fichero—, las capacidades no usadas desaparecen, y
#      un perfil malo se retira solo.
#   4. AUTOATAQUE: el confinamiento como denegacion de servicio. El motor no puede
#      ni construir el objetivo para el propio agente, init o un activo protegido,
#      y el modo obligatorio no se puede construir sin confirmacion (compile_fail).
#   5. El ciclo sobre un programa REAL del sistema, con la superficie cerrada y el
#      coste medidos.
#
# EL MURO, DECLARADO: la comparativa con SELinux y AppArmor no se puede EJECUTAR
# aqui. En este kernel el LSM activo es SELinux sin politica cargada y AppArmor no
# esta activo; activarlo exige cambiar la linea de arranque del kernel. gVisor y
# Kata no estan instalados. Se comparan propiedades, y lo propio se mide.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d -t aegis-confinar-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fallo() {
    printf '    %sFALLO%s: %s\n' "$ROJO" "$FIN" "$1"
    [ -n "${2:-}" ] && sed 's/^/    | /' "$2" | tail -30
    exit 1
}

echo "==> AegisConfine: supervision por notificacion de seccomp sobre procesos reales"
if cargo test -p aegis-sandbox --lib -- --nocapture >"$TMP/sup.log" 2>"$TMP/sup.err"; then
    L=$(grep -E '^llamadas vistas' "$TMP/sup.err" | head -1)
    echo "    ${VERDE}OK${FIN} (${L:-supervision real}; tabla cotejada con la cabecera del kernel;"
    echo "    ${VERDE}  ${FIN} lista blanca comprobada con el interprete de BPF sobre la tabla entera)"
else
    fallo "la supervision o la lista blanca no pasan" "$TMP/sup.err"
fi

echo "==> AegisConfine: aprender, ensayar, imponer y retirarse, contra el kernel"
if cargo test -p aegis-confinar -- --nocapture >"$TMP/ciclo.log" 2>"$TMP/ciclo.err"; then
    grep -E 'socket=|passwd=|CapEff bajo|aprendido en' "$TMP/ciclo.err" | head -6 \
        | sed "s/^/    ${GRIS}/;s/\$/${FIN}/"
    echo "    ${VERDE}OK${FIN} (lo aprendido funciona; lo no aprendido lo bloquea el kernel —seccomp"
    echo "    ${VERDE}  ${FIN} el socket, Landlock el fichero—; permisivo no bloquea nada y anota; un"
    echo "    ${VERDE}  ${FIN} perfil malo se retira solo a los tres fallos y no vuelve sin aprender)"
else
    fallo "el ciclo de confinamiento no pasa" "$TMP/ciclo.err"
fi

echo "==> AegisConfine: AUTOATAQUE — el confinamiento no puede volverse contra el producto"
N=$(grep -c 'compile fail ... ok' "$TMP/ciclo.log")
if [ "$N" -ge 2 ] && grep -q 'el_motor_no_puede_confinar_al_agente_ni_a_los_activos_protegidos ... ok' "$TMP/ciclo.log"; then
    echo "    ${VERDE}OK${FIN} (el propio agente, un binario aegis-*, init y los activos protegidos no"
    echo "    ${VERDE}  ${FIN} son ni construibles como objetivo; el modo obligatorio sin confirmacion"
    echo "    ${VERDE}  ${FIN} no compila: $N pruebas compile_fail con codigo de error)"
else
    fallo "el autoataque no se sostiene (compile_fail: $N)" "$TMP/ciclo.log"
fi

echo "==> AegisConfine: el ciclo sobre un programa REAL del sistema, medido"
if cargo run -q -p aegis-confinar --example confinar_support >"$TMP/vivo.log" 2>&1; then
    sed 's/^/    | /' "$TMP/vivo.log"
    echo "    ${VERDE}OK${FIN}"
else
    fallo "el programa real no funciona con su propio perfil aprendido" "$TMP/vivo.log"
fi
exit 0
