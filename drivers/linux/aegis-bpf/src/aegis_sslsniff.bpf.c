// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * AegisCore - inspeccion L7 de TLS por uprobes (FASE 66).
 *
 * EL PROBLEMA
 * -----------
 * El malware moderno cifra su canal de Comando y Control. Un IDS de red ve
 * bytes opacos: puede contar paquetes y mirar el SNI, pero no el contenido. La
 * respuesta clasica —un proxy que hace Man-In-The-Middle— rompe el
 * `certificate pinning`, y ademas obliga a poner una CA de interceptacion en
 * cada endpoint, que es en si misma una superficie de ataque enorme: quien
 * robe esa clave descifra el trafico de toda la organizacion.
 *
 * LA VIA CORRECTA
 * ---------------
 * No interceptar: OBSERVAR EN EL ORIGEN. Las bibliotecas TLS exponen dos
 * funciones de usuario por las que pasa, en claro, todo lo que se va a cifrar y
 * todo lo que se acaba de descifrar:
 *
 *   SSL_write(ssl, buf, num)  -> `buf` esta EN CLARO al ENTRAR
 *   SSL_read(ssl, buf, num)   -> `buf` esta EN CLARO al SALIR
 *
 * Un uprobe en la entrada de la primera y un uretprobe en el retorno de la
 * segunda dan el texto plano sin tocar el cifrado, sin romper el pinning y sin
 * ninguna clave de interceptacion que robar. El cifrado sigue siendo de
 * extremo a extremo; simplemente, uno de los extremos es un endpoint que
 * defendemos y en el que el dueno ha instalado un EDR.
 *
 * EL DETALLE QUE HAY QUE ACERTAR: LA CORRELACION DE SSL_read
 * ---------------------------------------------------------
 * En la ENTRADA de `SSL_read`, el buffer todavia no tiene nada: son datos
 * cifrados por recibir. El texto plano solo existe al RETORNAR. Pero en el
 * retorno ya no estan los argumentos: la ABI no los conserva.
 *
 * Asi que hay que recordar el puntero entre las dos sondas, y la clave de ese
 * recuerdo tiene que ser el **TID** (hilo) y no el PID: un proceso con varios
 * hilos hace `SSL_read` a la vez desde todos, y con el PID como clave la
 * entrada de un hilo pisaria la de otro y se leeria el buffer equivocado, con
 * datos de otra conexion. Es un fallo que no se ve en pruebas de un solo hilo
 * y que en produccion mezcla el trafico de dos sesiones.
 *
 * LO QUE EL VERIFICADOR EXIGE
 * ---------------------------
 *   - Cero bucles no acotados.
 *   - Toda copia desde memoria de usuario, con longitud acotada por una
 *     constante que el verificador pueda probar. De ahi AEGIS_L7_CARGA_MAX.
 *   - Toda lectura de memoria ajena, por helper (bpf_probe_read_user), nunca
 *     por dereferencia directa.
 *
 * HONESTIDAD: este fichero SE COMPILA Y SE SOMETE AL VERIFICADOR REAL DEL
 * KERNEL en cada `make ci`. Lo que NO se ejercita ahi es el enganche sobre un
 * proceso vivo que hable TLS, que necesita privilegios y una victima real.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "aegis_bpf_common.h"
#include "aegis_sslsniff.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ------------------------------------------------------------------------
 * Mapas
 * ------------------------------------------------------------------------ */

/*
 * 8 MiB, igual que el ring de telemetria general. A 1 KiB por evento son ocho
 * mil mensajes de margen: suficiente para absorber una rafaga de un navegador
 * mientras el agente drena.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} aegis_l7_eventos SEC(".maps");

/*
 * Lo que se recuerda entre la entrada y el retorno de SSL_read.
 *
 * La clave es el TID, no el PID: ver la nota de cabecera. 10240 entradas cubren
 * con holgura los hilos simultaneos en TLS de una maquina real; si se
 * desbordara, la entrada nueva se descarta y se pierde ESE mensaje, nunca se
 * corrompe otro.
 */
struct lectura_pendiente {
    __u64 buffer;   /* puntero al buffer del usuario */
    __u64 momento;  /* instante de la ENTRADA, para medir la latencia real */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   /* TID */
    __type(value, struct lectura_pendiente);
} aegis_l7_lecturas SEC(".maps");

/*
 * Filtro de PIDs a observar.
 *
 * La entrada 0 es un COMODIN que significa "observar todo". El filtrado ocurre
 * DENTRO del kernel a proposito: emitir todo el trafico TLS de una maquina y
 * filtrar en Ring 3 desperdiciaria el ancho de banda del ring, que es el recurso
 * escaso, y ademas haria que el texto plano de procesos que no interesan cruzara
 * al espacio de usuario sin necesidad. Eso ultimo no es solo rendimiento: es el
 * correo, la banca y las sesiones de trabajo de la persona que usa la maquina.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   /* PID */
    __type(value, __u8);  /* 1 = observar */
} aegis_l7_objetivos SEC(".maps");

/*
 * PIDs que NUNCA se observan, comprobado ANTES que el comodin.
 *
 * POR QUE ESTO NO ES OPCIONAL
 * --------------------------
 * El propio agente habla TLS con su Control Plane. Con el comodin activo se
 * observaria a si mismo: cada evento que emite viaja por TLS, ese envio dispara
 * el uprobe, que emite otro evento, que viaja por TLS... Es una realimentacion
 * positiva que satura el ring, la CPU y el enlace, y que ademas mete el contenido
 * del canal de gestion —incluidos los veredictos— dentro de la propia telemetria.
 *
 * No se resuelve "acordandose" de excluirlo desde Ring 3: si el agente engancha
 * primero y puebla el filtro despues, la realimentacion ya arranco. Por eso la
 * exclusion es un mapa aparte que se consulta PRIMERO y que el agente escribe
 * ANTES de adjuntar ninguna sonda.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   /* PID excluido */
    __type(value, __u8);
} aegis_l7_excluidos SEC(".maps");

/*
 * Contadores de salud. Un EDR tiene que saber cuanto NO vio: un ring que
 * descarta en silencio se parece mucho a una maquina limpia.
 */
enum aegis_l7_contador {
    AEGIS_L7_CNT_EMITIDOS = 0,
    AEGIS_L7_CNT_RING_LLENO = 1,
    AEGIS_L7_CNT_LECTURA_FALLIDA = 2,
    AEGIS_L7_CNT_SIN_CORRELACION = 3,
    AEGIS_L7_CNT_MAX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AEGIS_L7_CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} aegis_l7_contadores SEC(".maps");

static __always_inline void contar(__u32 cual)
{
    __u64 *c = bpf_map_lookup_elem(&aegis_l7_contadores, &cual);
    if (c)
        __sync_fetch_and_add(c, 1);
}

/* `true` si este PID hay que observarlo. */
static __always_inline int observado(__u32 pid)
{
    /* La EXCLUSION va primero, y gana siempre. Es lo que impide que el agente se
     * observe a si mismo y entre en realimentacion (ver `aegis_l7_excluidos`). */
    if (bpf_map_lookup_elem(&aegis_l7_excluidos, &pid))
        return 0;

    /* La entrada 0 es el comodin "observar todo". */
    __u32 comodin = 0;
    if (bpf_map_lookup_elem(&aegis_l7_objetivos, &comodin))
        return 1;
    return bpf_map_lookup_elem(&aegis_l7_objetivos, &pid) != 0;
}

/*
 * Emite un evento con la carga util recortada.
 *
 * `bpf_probe_read_user` copia desde el espacio de usuario del proceso
 * observado. La longitud va acotada por AEGIS_L7_CARGA_MAX, que es una
 * constante: sin esa cota el verificador rechaza el programa, y con razon —una
 * copia de longitud arbitraria desde memoria que controla el usuario es
 * exactamente como se desborda el kernel—.
 */
static __always_inline void emitir(__u64 buffer, __u64 total, __u32 direccion, __u64 momento)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    if (!observado(pid))
        return;

    struct aegis_l7_evento *ev = bpf_ringbuf_reserve(&aegis_l7_eventos, sizeof(*ev), 0);
    if (!ev) {
        /* Ring lleno: se descarta y se cuenta. JAMAS se aplica contrapresion
         * sobre el proceso observado; un EDR que ralentiza el TLS de la maquina
         * del cliente se desinstala el mismo dia. */
        contar(AEGIS_L7_CNT_RING_LLENO);
        return;
    }

    ev->tiempo_ns = momento;
    ev->longitud_total = total;
    ev->pid = pid;
    ev->tid = tid;
    ev->direccion = direccion;
    ev->carga_len = 0;

    struct task_struct *tarea = (struct task_struct *)bpf_get_current_task();
    ev->inicio_tarea_ns = tarea ? aegis_inicio_de_tarea(tarea) : 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    /* El recorte: el minimo entre lo que hay y lo que cabe. Se calcula con una
     * comparacion contra la constante para que el verificador pueda acotar el
     * argumento de la copia. */
    __u32 cuanto = AEGIS_L7_CARGA_MAX;
    if (total < (__u64)AEGIS_L7_CARGA_MAX)
        cuanto = (__u32)total;

    if (cuanto > 0) {
        if (bpf_probe_read_user(&ev->carga, cuanto, (void *)buffer) == 0) {
            ev->carga_len = cuanto;
        } else {
            /* El buffer puede haberse quedado sin residencia, o la direccion
             * ser invalida. Se emite el evento IGUAL, con carga vacia: los
             * metadatos (cuando, cuanto, quien) sostienen por si solos la
             * matematica de balizas, que es lo que delata a un C2 con jitter.
             * Perder el evento entero por no poder leer el cuerpo dejaria
             * agujeros justo en la serie temporal. */
            contar(AEGIS_L7_CNT_LECTURA_FALLIDA);
        }
    }

    bpf_ringbuf_submit(ev, 0);
    contar(AEGIS_L7_CNT_EMITIDOS);
}

/* ------------------------------------------------------------------------
 * SSL_write: el texto plano esta en el buffer AL ENTRAR
 * ------------------------------------------------------------------------ */

/*
 * int SSL_write(SSL *ssl, const void *buf, int num);
 *   PT_REGS_PARM2 = buf
 *   PT_REGS_PARM3 = num
 *
 * Se captura en la entrada y no en el retorno a proposito: al entrar, `num` es
 * lo que el programa QUIERE escribir; al salir, el valor devuelto es lo que se
 * escribio, que puede ser menos. Para la deteccion de balizas interesa la
 * intencion y el instante en que se produce, y ademas el retorno obligaria a
 * recordar el puntero, que es coste y una via mas de perder eventos.
 */
SEC("uprobe/SSL_write")
int BPF_KPROBE(aegis_ssl_write, void *ssl, const void *buf, int num)
{
    if (num <= 0)
        return 0;
    emitir((__u64)buf, (__u64)num, AEGIS_L7_SALIENTE, bpf_ktime_get_ns());
    return 0;
}

/*
 * int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);
 * La variante moderna de OpenSSL 3. Misma captura; solo cambia el tipo de
 * `num`. Sin esta, una aplicacion compilada contra la API nueva —que es la
 * recomendada desde 3.0— pasaria entera desapercibida.
 */
SEC("uprobe/SSL_write_ex")
int BPF_KPROBE(aegis_ssl_write_ex, void *ssl, const void *buf, __u64 num)
{
    if (num == 0)
        return 0;
    emitir((__u64)buf, num, AEGIS_L7_SALIENTE, bpf_ktime_get_ns());
    return 0;
}

/* ------------------------------------------------------------------------
 * SSL_read: el texto plano solo existe AL RETORNAR
 * ------------------------------------------------------------------------ */

/*
 * Entrada: se recuerda el puntero al buffer, con el TID como clave.
 *
 * La clave es el TID y no el PID porque un proceso con varios hilos lee a la
 * vez desde todos: con el PID, la entrada de un hilo pisaria la de otro y en el
 * retorno se leeria el buffer de una conexion distinta. Es el fallo que no
 * aparece con un solo hilo y que en produccion mezcla dos sesiones.
 */
SEC("uprobe/SSL_read")
int BPF_KPROBE(aegis_ssl_read_entrada, void *ssl, void *buf, int num)
{
    if (num <= 0)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_pendiente p = {
        .buffer = (__u64)buf,
        .momento = bpf_ktime_get_ns(),
    };
    /* BPF_ANY: si ya habia una entrada para este TID es que la anterior nunca
     * retorno (la llamada se interrumpio). Sobrescribir es lo correcto: la
     * pendiente vieja ya no va a completarse nunca. */
    bpf_map_update_elem(&aegis_l7_lecturas, &tid, &p, BPF_ANY);
    return 0;
}

/*
 * Retorno: el buffer ya trae el texto descifrado, y el valor devuelto dice
 * cuantos bytes son.
 */
SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(aegis_ssl_read_retorno, int devuelto)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_pendiente *p = bpf_map_lookup_elem(&aegis_l7_lecturas, &tid);
    if (!p) {
        /* Retorno sin entrada: el uprobe se engancho entre medias, o la entrada
         * se perdio por desbordamiento del mapa. Se cuenta para que el agente
         * SEPA que hay un hueco, en vez de creerse una serie temporal completa
         * a la que le faltan mensajes. */
        contar(AEGIS_L7_CNT_SIN_CORRELACION);
        return 0;
    }

    __u64 buffer = p->buffer;
    bpf_map_delete_elem(&aegis_l7_lecturas, &tid);

    /* Un retorno <= 0 es error o cierre: no hay texto plano que leer. */
    if (devuelto <= 0)
        return 0;

    emitir(buffer, (__u64)devuelto, AEGIS_L7_ENTRANTE, bpf_ktime_get_ns());
    return 0;
}

/*
 * int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
 *
 * En la variante `_ex` el numero de bytes leidos NO es el valor devuelto (que
 * es 1 o 0), sino lo que queda escrito en `*readbytes`. Por eso hay que
 * recordar TAMBIEN ese puntero y leerlo en el retorno; tratarla como la
 * clasica emitiria siempre longitud 1 y la matematica de volumen quedaria
 * falseada.
 */
struct lectura_ex_pendiente {
    __u64 buffer;
    __u64 leidos_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct lectura_ex_pendiente);
} aegis_l7_lecturas_ex SEC(".maps");

SEC("uprobe/SSL_read_ex")
int BPF_KPROBE(aegis_ssl_read_ex_entrada, void *ssl, void *buf, __u64 num, __u64 *leidos)
{
    if (num == 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_ex_pendiente p = {
        .buffer = (__u64)buf,
        .leidos_ptr = (__u64)leidos,
    };
    bpf_map_update_elem(&aegis_l7_lecturas_ex, &tid, &p, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_KRETPROBE(aegis_ssl_read_ex_retorno, int devuelto)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_ex_pendiente *p = bpf_map_lookup_elem(&aegis_l7_lecturas_ex, &tid);
    if (!p) {
        contar(AEGIS_L7_CNT_SIN_CORRELACION);
        return 0;
    }
    __u64 buffer = p->buffer;
    __u64 leidos_ptr = p->leidos_ptr;
    bpf_map_delete_elem(&aegis_l7_lecturas_ex, &tid);

    /* SSL_read_ex devuelve 1 en exito, 0 en fallo. */
    if (devuelto != 1 || leidos_ptr == 0)
        return 0;

    __u64 cuantos = 0;
    if (bpf_probe_read_user(&cuantos, sizeof(cuantos), (void *)leidos_ptr) != 0) {
        contar(AEGIS_L7_CNT_LECTURA_FALLIDA);
        return 0;
    }
    if (cuantos == 0)
        return 0;

    emitir(buffer, cuantos, AEGIS_L7_ENTRANTE, bpf_ktime_get_ns());
    return 0;
}

/* ------------------------------------------------------------------------
 * GnuTLS: la otra pila TLS mayoritaria en Linux
 * ------------------------------------------------------------------------
 *
 * ssize_t gnutls_record_send(gnutls_session_t s, const void *data, size_t len);
 * ssize_t gnutls_record_recv(gnutls_session_t s, void *data, size_t len);
 *
 * Misma forma que OpenSSL: el envio esta en claro al entrar, la recepcion al
 * salir. Se cubre porque en una distribucion tipica la mitad del trafico TLS
 * —wget, apt, glib-networking y todo lo que pase por GnuTLS— no toca `libssl`
 * en absoluto, y un cazador que solo mire OpenSSL seria ciego a la mitad de la
 * maquina sin que nadie lo notara.
 */
SEC("uprobe/gnutls_record_send")
int BPF_KPROBE(aegis_gnutls_send, void *sesion, const void *datos, __u64 largo)
{
    if (largo == 0)
        return 0;
    emitir((__u64)datos, largo, AEGIS_L7_SALIENTE, bpf_ktime_get_ns());
    return 0;
}

SEC("uprobe/gnutls_record_recv")
int BPF_KPROBE(aegis_gnutls_recv_entrada, void *sesion, void *datos, __u64 largo)
{
    if (largo == 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_pendiente p = {
        .buffer = (__u64)datos,
        .momento = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&aegis_l7_lecturas, &tid, &p, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int BPF_KRETPROBE(aegis_gnutls_recv_retorno, long devuelto)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct lectura_pendiente *p = bpf_map_lookup_elem(&aegis_l7_lecturas, &tid);
    if (!p) {
        contar(AEGIS_L7_CNT_SIN_CORRELACION);
        return 0;
    }
    __u64 buffer = p->buffer;
    bpf_map_delete_elem(&aegis_l7_lecturas, &tid);

    if (devuelto <= 0)
        return 0;

    emitir(buffer, (__u64)devuelto, AEGIS_L7_ENTRANTE, bpf_ktime_get_ns());
    return 0;
}
