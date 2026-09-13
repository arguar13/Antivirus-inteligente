#!/usr/bin/env bash
#
# Verificacion de AegisIPS (prevencion en linea, FASE 71).
#
# LA FRASE QUE GOBIERNA LA FASE ENTERA, y de la que salen todas las decisiones
# que este script comprueba:
#
#   Un falso positivo en un IDS es una alerta que alguien descarta.
#   Un falso positivo en un IPS es una INTERRUPCION DE SERVICIO.
#
# Por eso aqui las salvaguardas no son un anadido al motor de bloqueo: son EL
# diseno, y el motor de bloqueo es la parte facil. Son cuatro:
#
#   1. Solo una regla de confianza ALTA puede cortar. Las heuristicas alertan.
#      No es configurable: esta en el tipo, y no hay via para saltarselo.
#   2. Lista de NUNCA BLOQUEAR: plano de control, controladores de dominio, DNS
#      de la organizacion. Cortar esas maquinas convierte un incidente en un
#      apagon, y es lo que un atacante querria que hicieramos por el.
#   3. MODO, por defecto Solo Deteccion. Un IPS que llega bloqueando tira la
#      produccion del cliente el primer dia.
#   4. TOPE de bloqueos con degradacion automatica. Si el motor esta bloqueando
#      media red, el motor esta mal, no la red.
#
# LAS DOS DEL MEDIO SE COMPRUEBAN OTRA VEZ EN EL KERNEL, antes de cortar. No es
# redundancia por gusto: una salvaguarda que depende de que el codigo de decision
# este bien no protege del caso que importa, que es justamente que el codigo de
# decision este mal.
#
# EL MURO DE ESTA FASE, declarado: que una NIC real descarte el paquete al
# recibir TC_ACT_SHOT es comportamiento del kernel, no de este codigo, y cortar a
# velocidad de 10 GbE se mide en hardware con carga real, no en un contenedor de
# CI. Lo que SI se ejerce aqui es el programa de kernel de verdad, contra
# paquetes de verdad, devolviendo su veredicto de verdad.
set -uo pipefail
cd "$(dirname "$0")/.."

VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'

echo "==> AegisIPS: las cuatro salvaguardas, en el motor de decision"
if cargo test -p aegis-ips --quiet --lib \
    >/tmp/aegis-ips-decision.log 2>&1; then
    echo "    ${VERDE}OK${FIN} (1) una heuristica NO corta ni en modo bloqueo: solo la confianza"
    echo "    ${VERDE}  ${FIN} alta puede, y eso esta en el tipo y no en una opcion, porque una"
    echo "    ${VERDE}  ${FIN} politica que se puede aflojar se afloja el dia que alguien tiene"
    echo "    ${VERDE}  ${FIN} prisa; (2) un activo protegido no se corta ni con la regla de maxima"
    echo "    ${VERDE}  ${FIN} confianza, en modo bloqueo y con el limitador libre; (3) el modo de"
    echo "    ${VERDE}  ${FIN} aprendizaje REGISTRA lo que habria cortado y no corta; y (4) al"
    echo "    ${VERDE}  ${FIN} pasarse del tope el motor se degrada solo y lo DECLARA)"
    echo "    ${GRIS}La degradacion es PEGAJOSA: no se re-arma sola al bajar el ritmo. Si lo${FIN}"
    echo "    ${GRIS}hiciera, la red iria y vendria, que es peor de diagnosticar que una red${FIN}"
    echo "    ${GRIS}cortada del todo. Reactivarla exige una intervencion deliberada.${FIN}"
    echo "    ${GRIS}Y la ventana es DESLIZANTE: con un contador que se reinicia cada minuto,${FIN}"
    echo "    ${GRIS}el tope entero justo antes del corte y otro tanto justo despues pasarian${FIN}"
    echo "    ${GRIS}desapercibidos. Hay una prueba con esa rafaga exacta.${FIN}"
else
    echo "    ${ROJO}FALLO${FIN}: las salvaguardas del motor de decision no se sostienen"
    sed 's/^/    | /' /tmp/aegis-ips-decision.log | tail -30
    exit 1
fi

echo "==> AegisIPS: los programas eBPF pasan el verificador REAL del kernel"
if make -C drivers/linux/aegis-bpf build verify \
    >/tmp/aegis-ips-verificador.log 2>&1; then
    if grep -q "aegis_ips_ingreso" /tmp/aegis-ips-verificador.log \
        && grep -q "aegis_ips_egreso" /tmp/aegis-ips-verificador.log; then
        echo "    ${VERDE}OK${FIN} (compilar no demuestra nada en eBPF: el verificador rechaza"
        echo "    ${VERDE}  ${FIN} programas que compilan perfectamente. Aqui pasan los DOS, ingreso y"
        echo "    ${VERDE}  ${FIN} egreso, con sus cuatro mapas)"
        echo "    ${GRIS}Y pasan porque TODO acceso al paquete se comprueba contra data_end:${FIN}"
        echo "    ${GRIS}el verificador rechaza el programa si falta una sola comprobacion,${FIN}"
        echo "    ${GRIS}porque el contenido del paquete lo escribe el atacante.${FIN}"
    else
        echo "    ${ROJO}FALLO${FIN}: el verificador paso pero no vio los programas del IPS"
        sed 's/^/    | /' /tmp/aegis-ips-verificador.log | tail -20
        exit 1
    fi
else
    echo "    ${ROJO}FALLO${FIN}: los programas eBPF no pasan el verificador"
    sed 's/^/    | /' /tmp/aegis-ips-verificador.log | tail -30
    exit 1
fi

echo "==> AegisIPS: el CORTE, contra el programa de kernel de verdad"
if cargo test -p aegis-ips --quiet --test corte_vivo -- --nocapture \
    >/tmp/aegis-ips-corte.log 2>&1; then
    if grep -q 'OMITIDA' /tmp/aegis-ips-corte.log; then
        echo "    ${GRIS}OMITIDO: no se pudo cargar el programa eBPF (hace falta CAP_BPF o root).${FIN}"
        echo "    ${GRIS}El CORTE no se ejercio aqui. La DECISION de cortar SI se prueba, arriba,${FIN}"
        echo "    ${GRIS}sin privilegios. 'No se pudo mirar' y 'se miro y estaba bien' no son lo${FIN}"
        echo "    ${GRIS}mismo, y confundirlos es como se acaba creyendo que un IPS corta.${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (contra el kernel REAL, por BPF_PROG_RUN: el flujo marcado se corta"
        echo "    ${VERDE}  ${FIN} y el limpio no; el corte alcanza los DOS sentidos, porque la vuelta"
        echo "    ${VERDE}  ${FIN} es por donde responde el C2; y funciona en EGRESO, que es el sentido"
        echo "    ${VERDE}  ${FIN} que XDP no puede cubrir y el que mas importa en un endpoint)"
        echo "    ${GRIS}Un activo protegido NO se corta aunque el veredicto de corte este${FIN}"
        echo "    ${GRIS}escrito en el mapa: es la segunda capa, la que aguanta cuando el${FIN}"
        echo "    ${GRIS}codigo de decision de arriba falla — que es el caso que importa.${FIN}"
        echo "    ${GRIS}Y no se pierde NI UN PAQUETE: todo lo que entra sale contado en${FIN}"
        echo "    ${GRIS}alguna categoria, medido con los contadores del propio programa.${FIN}"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: el corte no se comporta como debe"
    sed 's/^/    | /' /tmp/aegis-ips-corte.log | tail -30
    exit 1
fi

echo "==> AegisIPS: el circuito entero (paquete -> hecho -> decision -> corte)"
if cargo test -p aegis-ips --quiet --test circuito_vivo -- --nocapture \
    >/tmp/aegis-ips-circuito.log 2>&1; then
    if grep -q 'OMITIDA' /tmp/aegis-ips-circuito.log; then
        echo "    ${GRIS}OMITIDO: no se pudo cargar el programa eBPF. El CIRCUITO no se ejercio.${FIN}"
        echo "    ${GRIS}Sus dos mitades si: la decision arriba, y el corte cuando hay kernel.${FIN}"
    else
        echo "    ${VERDE}OK${FIN} (un paquete DNS de verdad entra por aegis-wire, el motor lo juzga,"
        echo "    ${VERDE}  ${FIN} el veredicto baja al kernel, y el siguiente paquete de esa"
        echo "    ${VERDE}  ${FIN} conversacion se corta. Eso demuestra lo que ninguna prueba de pieza"
        echo "    ${VERDE}  ${FIN} suelta puede: que la clave de flujo del disector, la que escribe"
        echo "    ${VERDE}  ${FIN} userland y la que busca el kernel son LA MISMA)"
        echo "    ${GRIS}Si esas tres no coincidieran, cada pieza pasaria sus pruebas por${FIN}"
        echo "    ${GRIS}separado y el producto no cortaria nada — sin un solo error visible.${FIN}"
        echo "    ${GRIS}Y la degradacion llega HASTA EL KERNEL: con los veredictos ya escritos${FIN}"
        echo "    ${GRIS}en el mapa, al degradarse deja de cortar. No es una nota en un${FIN}"
        echo "    ${GRIS}registro: cambia lo que hace el plano de datos.${FIN}"
    fi
else
    echo "    ${ROJO}FALLO${FIN}: el circuito entero no pasa"
    sed 's/^/    | /' /tmp/aegis-ips-circuito.log | tail -30
    exit 1
fi

echo "==> AegisIPS: el modo por defecto NO corta (lo que recibe un cliente nuevo)"
POR_DEFECTO=$(cargo test -p aegis-ips --quiet --lib \
    modo::pruebas::el_modo_por_defecto_no_corta_nada 2>&1 | grep -c "1 passed" || true)
if [ "$POR_DEFECTO" -ge 1 ]; then
    echo "    ${VERDE}OK${FIN} (Solo Deteccion. El camino al bloqueo es escalonado: primero se ve"
    echo "    ${VERDE}  ${FIN} lo que hay, luego se registra lo que se HABRIA cortado, y solo cuando"
    echo "    ${VERDE}  ${FIN} esa lista ya no tiene sorpresas se activa el corte. El paso del medio"
    echo "    ${VERDE}  ${FIN} es lo que hace posible el ultimo sin apostar sobre la red de otro)"
else
    echo "    ${ROJO}FALLO${FIN}: el valor por defecto ya no es el seguro"
    exit 1
fi
exit 0
