/*
 * AegisCore - contrato de los eventos L7 en claro (FASE 66).
 *
 * Este fichero es el ABI entre el programa eBPF que engancha SSL_read/SSL_write
 * en Ring 3 y el analizador en Rust. Lo incluyen los dos lados: el .bpf.c
 * directamente, y `aegis-l7hunter::abi` reproduce el layout con aserciones de
 * compilacion.
 *
 * POR QUE UN ABI EXPLICITO Y VERIFICADO
 * ------------------------------------
 * El ring buffer entrega bytes crudos. Si el struct de C y el de Rust
 * divergieran en un solo byte de relleno, el analizador leeria el `pid` donde
 * hay una longitud y la carga util donde hay una marca de tiempo. Eso no rompe
 * la compilacion ni la carga: produce un EDR que no detecta nada, que es el
 * peor fallo posible. De ahi que cada campo lleve su desplazamiento fijado y
 * comprobado a los dos lados (ver tools/abi-check.sh, mismo criterio que el
 * ABI principal del producto).
 */
#ifndef AEGIS_SSLSNIFF_H
#define AEGIS_SSLSNIFF_H

#ifndef AEGIS_SSLSNIFF_STATIC_ASSERT
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#    define AEGIS_SSLSNIFF_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#  else
#    define AEGIS_SSLSNIFF_STATIC_ASSERT(cond, msg)
#  endif
#endif

/*
 * Bytes de carga util que viajan por evento.
 *
 * POR QUE 1024 Y NO EL BUFFER ENTERO
 * ----------------------------------
 * Tres razones, y las tres son duras:
 *
 *  1. EL VERIFICADOR. Una copia desde memoria de usuario con longitud variable
 *     solo pasa el verificador si el limite es una constante que el puede
 *     probar. Con un tamano dinamico sin cota, el programa se rechaza.
 *
 *  2. EL RING. A 1 KiB por evento, un ring de 8 MiB absorbe ocho mil mensajes
 *     antes de descartar. Con 16 KiB por evento serian quinientos, y una sola
 *     descarga por HTTPS llenaria el ring y tiraria la telemetria de todo lo
 *     demas. El recurso escaso no es la CPU, es el ancho de banda del ring.
 *
 *  3. NO HACE FALTA MAS. Lo que delata a un C2 esta en la CABECERA: el metodo,
 *     el Host, la URI, el User-Agent y las cookies. Un KiB cubre de sobra la
 *     cabecera de cualquier baliza. El cuerpo —que es donde va el volumen— no
 *     aporta a la clasificacion y si al coste.
 *
 * `longitud_total` conserva el tamano REAL de la operacion aunque la carga se
 * recorte, porque el volumen si importa para la matematica de balizas (una
 * baliza envia poco y recibe poco; una exfiltracion envia mucho).
 */
#define AEGIS_L7_CARGA_MAX 1024u

/* Longitud maxima del nombre de proceso (`comm` del kernel, que son 16). */
#define AEGIS_L7_COMM_MAX 16u

/* Direccion del trafico respecto al proceso observado. */
enum aegis_l7_direccion {
    /* El proceso ENVIA: capturado en la ENTRADA de SSL_write, cuando el buffer
     * todavia esta en claro y aun no ha pasado por el cifrado. */
    AEGIS_L7_SALIENTE = 0,
    /* El proceso RECIBE: capturado en el RETORNO de SSL_read, cuando el buffer
     * ya ha sido descifrado. */
    AEGIS_L7_ENTRANTE = 1,
};

/*
 * Un evento L7 en claro.
 *
 * El orden de los campos NO es arbitrario: van de mayor a menor alineacion para
 * que no haya relleno interno. Con los campos mezclados, el compilador inserta
 * huecos y el layout pasa a depender de decisiones suyas, que es justo lo que
 * un ABI no puede permitirse.
 */
struct aegis_l7_evento {
    /* Marca monotona del kernel (bpf_ktime_get_ns). Es la que sostiene toda la
     * matematica de balizas: los intervalos entre mensajes. Monotona y no de
     * pared a proposito: un atacante que mueve el reloj del sistema no puede
     * falsear la periodicidad de su propio C2. */
    __u64 tiempo_ns;
    /* Identidad estable del proceso: el PID se recicla, el par (pid, instante de
     * arranque) no. Ver `aegis_inicio_de_tarea` en aegis_bpf_common.h. */
    __u64 inicio_tarea_ns;
    /* Bytes REALES de la operacion, aunque la carga se haya recortado. */
    __u64 longitud_total;
    __u32 pid;
    __u32 tid;
    /* enum aegis_l7_direccion, como u32 para que el layout sea explicito: el
     * ancho de un enum en C depende del compilador y de sus banderas. */
    __u32 direccion;
    /* Bytes utiles en `carga` (<= AEGIS_L7_CARGA_MAX). */
    __u32 carga_len;
    char comm[AEGIS_L7_COMM_MAX];
    /* El texto en claro, antes de cifrar o despues de descifrar. */
    __u8 carga[AEGIS_L7_CARGA_MAX];
};

/* --- Contrato de ABI, fijado y comprobado ------------------------------- */
AEGIS_SSLSNIFF_STATIC_ASSERT(sizeof(struct aegis_l7_evento) == 1080,
                             "el tamano del evento L7 cambio: actualiza abi.rs");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, tiempo_ns) == 0, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, inicio_tarea_ns) == 8, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, longitud_total) == 16, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, pid) == 24, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, tid) == 28, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, direccion) == 32, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, carga_len) == 36, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, comm) == 40, "");
AEGIS_SSLSNIFF_STATIC_ASSERT(__builtin_offsetof(struct aegis_l7_evento, carga) == 56, "");

#endif /* AEGIS_SSLSNIFF_H */
