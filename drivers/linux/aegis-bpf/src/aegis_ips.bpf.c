// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * AegisCore - prevencion en linea (AegisIPS, FASE 71).
 *
 * POR QUE TC Y NO XDP
 * -------------------
 * XDP es mas barato y corre antes, y por eso el filtro de barridos vive alli.
 * Pero XDP **solo existe en el camino de recepcion**: no hay hook XDP de
 * salida. Y para un EDR el sentido que mas importa cortar es justamente el
 * SALIENTE: la baliza que sale hacia el C2, la exfiltracion, el movimiento
 * lateral hacia otra maquina de la propia red. Un IPS que solo filtre lo que
 * entra deja pasar el trafico que confirma que la maquina ya esta comprometida.
 *
 * TC con `clsact` tiene los dos ganchos, ingreso y egreso, asi que un unico
 * programa cubre la conversacion entera. Ademas convive con el filtro XDP en la
 * misma interfaz —son ganchos distintos—, de modo que esta fase NO tiene que
 * quitar ni reescribir la deteccion de barridos que ya funciona.
 *
 * QUE DECIDE EL KERNEL Y QUE DECIDE USERLAND
 * ------------------------------------------
 *   - USERLAND JUZGA. Recibe los hechos de aegis-wire, aplica las reglas con su
 *     confianza, y escribe UN veredicto por flujo.
 *   - EL KERNEL APLICA. Busca el veredicto del flujo y corta o deja pasar.
 *
 * Ese reparto es lo que hace que bloquear no cueste rendimiento: el primer
 * paquete de un flujo sospechoso sube, se juzga una vez, y el veredicto baja.
 * El resto del flujo se corta con una busqueda de mapa. Un IPS que consultara a
 * userland por cada paquete pagaria exactamente el coste que existe para
 * evitar.
 *
 * LAS TRES SALVAGUARDAS, Y POR QUE ESTAN AQUI ABAJO
 * ------------------------------------------------
 * Un falso positivo en un IPS no es una alerta molesta: es una INTERRUPCION DE
 * SERVICIO. Las tres salvaguardas se comprueban en el kernel y no en userland,
 * porque una salvaguarda que dependa de que el codigo de arriba este bien no
 * protege del caso que importa, que es justamente que el codigo de arriba este
 * mal:
 *
 *   1. LISTA DE PROTEGIDOS, consultada ANTES que el veredicto. Ningun veredicto,
 *      venga de la regla que venga, puede cortar al plano de control, a un
 *      controlador de dominio o al DNS de la organizacion. Cortar esas maquinas
 *      convierte un incidente en un apagon, y es lo que un atacante querria que
 *      hicieramos por el.
 *   2. MODO, comprobado aqui. En `SOLO_DETECCION` y en `APRENDIZAJE` este
 *      programa NO puede cortar aunque el mapa de veredictos diga que si. Asi
 *      «modo aprendizaje» es una promesa sostenible y no una intencion.
 *   3. CADUCIDAD. Un veredicto sin caducidad util es un bloqueo permanente por
 *      accidente. Al caducar se deja de aplicar solo, sin que nadie intervenga.
 *
 * Todo acceso al paquete se comprueba contra data_end antes de leerlo. El
 * verificador rechaza el programa si falta una sola comprobacion, porque el
 * contenido del paquete lo controla el atacante.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "aegis_bpf_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Valores de retorno de un clasificador TC. vmlinux.h no los trae porque son
 * macros de UAPI, no tipos del BTF. */
#define AEGIS_TC_ACT_OK   0
#define AEGIS_TC_ACT_SHOT 2

/* ------------------------------------------------------------------------
 * Estado compartido con userland
 * ------------------------------------------------------------------------ */

/* LA CACHE DE VEREDICTOS. LRU y no HASH a proposito: si se llena, expulsa lo
 * mas antiguo en vez de empezar a fallar las escrituras. Un IPS que deja de
 * aceptar veredictos nuevos porque el mapa esta lleno se queda ciego justo
 * cuando mas trafico hay, que es cuando el atacante prefiere actuar. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct aegis_ips_flujo);
    __type(value, struct aegis_ips_veredicto);
} aegis_ips_veredictos SEC(".maps");

/* Lista de nunca-bloquear, por IPv4. HASH y no LRU: estas entradas NO pueden
 * expulsarse solas. Una salvaguarda que desaparece por presion de memoria es
 * peor que no tenerla, porque nadie se entera de que ya no esta. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct aegis_ips_protegido);
} aegis_ips_protegidos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_ips_config);
} aegis_ips_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AEGIS_IPS_STAT__MAX);
    __type(key, __u32);
    __type(value, __u64);
} aegis_ips_stats SEC(".maps");

/* ------------------------------------------------------------------------
 * Utilidades
 * ------------------------------------------------------------------------ */

static __always_inline void ips_stat_inc(__u32 cual)
{
    __u64 *ranura = bpf_map_lookup_elem(&aegis_ips_stats, &cual);
    if (ranura)
        (*ranura)++;
}

/* Normaliza un par (ip, puerto) en una clave de flujo estable.
 *
 * Ordenar por (ip, puerto) hace que los dos sentidos de la conversacion den la
 * MISMA clave. Sin esto, un veredicto escrito viendo el sentido de ida no
 * cortaria el de vuelta, que es por donde llega la respuesta del C2. */
static __always_inline void ips_clave(struct aegis_ips_flujo *f,
                                      __u32 ip_o, __u16 pto_o,
                                      __u32 ip_d, __u16 pto_d,
                                      __u8 protocolo)
{
    __builtin_memset(f, 0, sizeof(*f));
    f->protocolo = protocolo;
    /* Comparacion en orden de red: da igual cual sea el criterio mientras sea
     * el MISMO en los dos sentidos y el mismo que usa userland. */
    if (ip_o < ip_d || (ip_o == ip_d && pto_o <= pto_d)) {
        f->ip_a = ip_o;
        f->puerto_a = pto_o;
        f->ip_b = ip_d;
        f->puerto_b = pto_d;
    } else {
        f->ip_a = ip_d;
        f->puerto_a = pto_d;
        f->ip_b = ip_o;
        f->puerto_b = pto_o;
    }
}

/* ------------------------------------------------------------------------
 * Programa TC
 * ------------------------------------------------------------------------ */

static __always_inline int ips_procesar(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    ips_stat_inc(AEGIS_IPS_STAT_PAQUETES);

    __u32 cfg_key = 0;
    struct aegis_ips_config *cfg = bpf_map_lookup_elem(&aegis_ips_config, &cfg_key);
    if (!cfg || !(cfg->flags & AEGIS_IPS_CFG_ENABLED))
        return AEGIS_TC_ACT_OK;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return AEGIS_TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != AEGIS_ETH_P_IP) {
        /* IPv6 todavia no se juzga aqui. Se cuenta en vez de callarlo: un punto
         * ciego que nadie mide es un punto ciego que nadie arregla. */
        ips_stat_inc(AEGIS_IPS_STAT_NO_CLASIFICADOS);
        return AEGIS_TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return AEGIS_TC_ACT_OK;

    /* ihl lo controla el emisor: una cabecera declarada mas corta que el minimo
     * legal se usa para descolocar a los analizadores que no lo comprueban. */
    if (ip->ihl < 5)
        return AEGIS_TC_ACT_OK;
    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end)
        return AEGIS_TC_ACT_OK;

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;

    /* --- LA CLAVE DE FLUJO, UNA SOLA VEZ ---
     *
     * Se calcula antes de cualquier decision y en un unico sitio. Tenerla
     * duplicada por rama obligaria a que las dos copias coincidieran para
     * siempre, y dos analizadores del mismo paquete que tienen que coincidir
     * acaban no coincidiendo. */
    __u16 pto_o = 0, pto_d = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) {
            ips_stat_inc(AEGIS_IPS_STAT_NO_CLASIFICADOS);
            return AEGIS_TC_ACT_OK;
        }
        pto_o = bpf_ntohs(tcp->source);
        pto_d = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) {
            ips_stat_inc(AEGIS_IPS_STAT_NO_CLASIFICADOS);
            return AEGIS_TC_ACT_OK;
        }
        pto_o = bpf_ntohs(udp->source);
        pto_d = bpf_ntohs(udp->dest);
    } else {
        /* Sin puertos no hay flujo que juzgar. Se deja pasar y se cuenta. */
        ips_stat_inc(AEGIS_IPS_STAT_NO_CLASIFICADOS);
        return AEGIS_TC_ACT_OK;
    }

    struct aegis_ips_flujo f;
    ips_clave(&f, saddr, pto_o, daddr, pto_d, ip->protocol);
    struct aegis_ips_veredicto *v = bpf_map_lookup_elem(&aegis_ips_veredictos, &f);

    /* --- SALVAGUARDA 1: LOS PROTEGIDOS, ANTES QUE NADA ---
     *
     * Se miran los DOS extremos. Proteger solo el destino dejaria sin cubrir el
     * trafico que SALE de un controlador de dominio, y cortarle la salida lo
     * deja igual de inutil que cortarle la entrada.
     *
     * Va antes que el modo y antes que la caducidad a proposito: asi el contador
     * de «salvadas» mide de verdad cuantas veces esta lista ha tapado un
     * veredicto de corte, que es la cifra que dice si el motor de decision se
     * esta equivocando en algo grave. */
    struct aegis_ips_protegido *prot = bpf_map_lookup_elem(&aegis_ips_protegidos, &saddr);
    if (!prot)
        prot = bpf_map_lookup_elem(&aegis_ips_protegidos, &daddr);
    if (prot) {
        /* Solo cuenta como «salvada» si de verdad habia algo que cortar. Si
         * subiera con cada paquete normal del DNS dejaria de significar nada. */
        if (v && v->veredicto == AEGIS_IPS_VEREDICTO_CORTAR) {
            prot->salvadas++;
            ips_stat_inc(AEGIS_IPS_STAT_PROTEGIDOS);
        }
        /* Pase lo que pase, un protegido NO se corta. */
        return AEGIS_TC_ACT_OK;
    }

    if (!v) {
        ips_stat_inc(AEGIS_IPS_STAT_CACHE_FALLO);
        return AEGIS_TC_ACT_OK;
    }
    ips_stat_inc(AEGIS_IPS_STAT_CACHE_ACIERTO);

    /* --- SALVAGUARDA 3: CADUCIDAD --- */
    if (v->until_ns != 0 && bpf_ktime_get_boot_ns() >= v->until_ns) {
        ips_stat_inc(AEGIS_IPS_STAT_CADUCADOS);
        /* La entrada se deja para que userland la limpie: un map_delete por
         * paquete en la ruta caliente cuesta mas que la comparacion. */
        return AEGIS_TC_ACT_OK;
    }

    if (v->veredicto != AEGIS_IPS_VEREDICTO_CORTAR)
        return AEGIS_TC_ACT_OK;

    v->hits++;

    /* --- SALVAGUARDA 2: EL MODO, COMPROBADO AQUI ---
     *
     * En cualquier modo que no sea BLOQUEO, esto NO corta. Se cuenta lo que se
     * habria cortado, que es la cifra que un cliente mira antes de atreverse a
     * activar el bloqueo de verdad. */
    if (cfg->modo != AEGIS_IPS_MODO_BLOQUEO) {
        ips_stat_inc(AEGIS_IPS_STAT_HABRIA_CORTADO);
        return AEGIS_TC_ACT_OK;
    }

    ips_stat_inc(AEGIS_IPS_STAT_CORTADOS);
    return AEGIS_TC_ACT_SHOT;
}

/* Ingreso: lo que llega a esta maquina. */
SEC("tc")
int aegis_ips_ingreso(struct __sk_buff *skb)
{
    return ips_procesar(skb);
}

/* Egreso: lo que SALE de esta maquina.
 *
 * Es el sentido que XDP no puede cubrir y el que mas importa en un EDR: la
 * baliza hacia el C2, la exfiltracion y el movimiento lateral salen por aqui.
 */
SEC("tc")
int aegis_ips_egreso(struct __sk_buff *skb)
{
    return ips_procesar(skb);
}
