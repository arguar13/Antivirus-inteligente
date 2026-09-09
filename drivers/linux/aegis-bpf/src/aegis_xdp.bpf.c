// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * AegisCore - filtro de red XDP (eXpress Data Path).
 *
 * XDP corre en el driver de red, ANTES de que el kernel construya un sk_buff y
 * antes de netfilter. Eso importa por dos razones: descartar aqui cuesta
 * ~50 ns en vez de los microsegundos de una regla de iptables, y un paquete
 * descartado aqui nunca toca el stack TCP/IP, asi que no puede explotar un
 * fallo en el.
 *
 * Reparto de responsabilidades entre kernel y userland:
 *   - El KERNEL cuenta y aplica. Mantiene contadores baratos por IP origen y
 *     consulta la lista de bloqueo.
 *   - USERLAND decide. Recibe los eventos, correlaciona y escribe en la lista
 *     de bloqueo.
 * Poner la decision aqui obligaria a meter politica en un programa que corre
 * por cada paquete y que el verificador limita; poner la aplicacion arriba
 * significaria que el paquete ya entro al stack antes de descartarse.
 *
 * Todo acceso al paquete se comprueba contra data_end antes de leerlo. No es
 * defensa en profundidad: el verificador rechaza el programa si falta una sola
 * comprobacion, porque el contenido del paquete lo controla el atacante.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "aegis_bpf_common.h"
#include "aegis_abi.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ------------------------------------------------------------------------
 * Estado compartido con userland
 * ------------------------------------------------------------------------ */

/* Estado de deteccion de barrido, por IP origen. */
struct aegis_scan_state {
    __u64 window_start_ns;
    /* Firma de los puertos vistos en la ventana.
     *
     * Contar puertos DISTINTOS de verdad exigiria un conjunto por IP, que en
     * un programa XDP no cabe. Se usa un mapa de bits de 64 posiciones
     * indexado por (puerto % 64): sobreestima la coincidencia (dos puertos
     * distintos pueden caer en el mismo bit) pero nunca inventa puertos que no
     * se han visto, asi que el recuento resultante es una COTA INFERIOR del
     * numero real de puertos distintos. Para detectar barridos eso es lo que
     * hace falta: preferimos subestimar y no alertar, antes que sobreestimar y
     * bloquear a un cliente legitimo.
     */
    __u64 port_bitmap;
    __u32 syn_count;
    __u32 reported;   /* ya se notifico este barrido: no repetir por paquete */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   /* IPv4 origen, en orden de red */
    __type(value, struct aegis_block_entry);
} aegis_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct aegis_scan_state);
} aegis_scan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} aegis_net_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aegis_xdp_config);
} aegis_xdp_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AEGIS_XDP_STAT__MAX);
    __type(key, __u32);
    __type(value, __u64);
} aegis_xdp_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} aegis_xdp_seq SEC(".maps");

/* ------------------------------------------------------------------------
 * Utilidades
 * ------------------------------------------------------------------------ */

static __always_inline void xdp_stat_inc(__u32 which)
{
    __u64 *slot = bpf_map_lookup_elem(&aegis_xdp_stats, &which);
    if (slot)
        (*slot)++;
}

static __always_inline __u64 xdp_next_seq(void)
{
    __u32 key = 0;
    __u64 *slot = bpf_map_lookup_elem(&aegis_xdp_seq, &key);
    if (!slot)
        return 0;
    return ++(*slot);
}

/* Emite un evento de red en el formato del ABI comun. */
static __always_inline void emit_net_event(__u16 type, __u32 saddr_be, __u32 daddr_be,
                                           __u16 sport, __u16 dport, __u8 proto,
                                           __u32 flags)
{
    void *rec = bpf_ringbuf_reserve(&aegis_net_events, AEGIS_BPF_EVT_SMALL, 0);
    if (!rec) {
        xdp_stat_inc(AEGIS_XDP_STAT_EVENT_DROPPED);
        return;
    }

    aegis_evt_hdr_t *hdr = (aegis_evt_hdr_t *)rec;
    hdr->magic = AEGIS_EVT_MAGIC;
    hdr->abi_version = AEGIS_ABI_VERSION;
    hdr->type = type;
    hdr->total_len = AEGIS_BPF_EVT_SMALL;
    hdr->flags = 0;
    hdr->seq = xdp_next_seq();
    hdr->ts_ns = bpf_ktime_get_boot_ns();
    /* En XDP no hay proceso asociado: el paquete aun no se ha entregado a
     * ningun socket. La atribucion a proceso, si procede, la hace Ring 3
     * correlacionando con los eventos de la sonda de sockets. */
    hdr->actor_key = 0;
    hdr->target_key = 0;
    hdr->cpu = bpf_get_smp_processor_id();
    hdr->verdict_id = 0;
    hdr->reserved = 0;

    aegis_net_conn_t *n = (aegis_net_conn_t *)((char *)rec + AEGIS_BPF_PAYLOAD_OFF);
    __builtin_memset(n, 0, sizeof(*n));
    __builtin_memcpy(n->saddr, &saddr_be, 4);
    __builtin_memcpy(n->daddr, &daddr_be, 4);
    n->pid = 0;
    n->sport = sport;
    n->dport = dport;
    n->family = AEGIS_AF_INET;
    n->protocol = proto;
    n->flags = flags | AEGIS_NET_F_XDP | AEGIS_NET_F_INBOUND;

    xdp_stat_inc(AEGIS_XDP_STAT_EVENTS);
    bpf_ringbuf_submit(rec, 0);
}

/* ------------------------------------------------------------------------
 * Programa XDP
 * ------------------------------------------------------------------------ */

SEC("xdp")
int aegis_xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    xdp_stat_inc(AEGIS_XDP_STAT_PACKETS);

    __u32 cfg_key = 0;
    struct aegis_xdp_config *cfg = bpf_map_lookup_elem(&aegis_xdp_config, &cfg_key);
    if (!cfg || !(cfg->flags & AEGIS_XDP_CFG_ENABLED))
        return XDP_PASS;

    /* --- Ethernet --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto_l3 = bpf_ntohs(eth->h_proto);
    if (proto_l3 != ETH_P_IP) {
        /* IPv6 y el resto de protocolos pasan sin inspeccionar. Decirlo en un
         * contador y no en silencio: un punto ciego que nadie mide es un punto
         * ciego que nadie arregla. */
        if (proto_l3 == ETH_P_IPV6)
            xdp_stat_inc(AEGIS_XDP_STAT_IPV6_UNINSPECTED);
        return XDP_PASS;
    }

    /* --- IPv4 --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* ihl viene en palabras de 32 bits y lo controla el emisor: una cabecera
     * declarada mas corta que el minimo legal se usa para confundir a los
     * analizadores que no lo comprueban. */
    if (ip->ihl < 5)
        return XDP_PASS;
    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    __u32 saddr = ip->saddr;   /* orden de red */
    __u32 daddr = ip->daddr;

    /* --- Lista de bloqueo: lo primero, para que cueste lo minimo --- */
    struct aegis_block_entry *bloqueo = bpf_map_lookup_elem(&aegis_blocklist, &saddr);
    if (bloqueo) {
        __u64 ahora = bpf_ktime_get_boot_ns();
        if (bloqueo->until_ns == 0 || ahora < bloqueo->until_ns) {
            bloqueo->hits++;
            xdp_stat_inc(AEGIS_XDP_STAT_DROPPED);
            /* Solo se notifica el primer descarte de cada entrada: un bloqueo
             * efectivo contra una inundacion generaria millones de eventos
             * identicos y ahogaria el ring. El contador `hits` lleva la cuenta
             * real y userland lo lee cuando quiere. */
            if (bloqueo->hits == 1)
                emit_net_event(AEGIS_EVT_NET_BLOCKED, saddr, daddr, 0, 0,
                               ip->protocol, AEGIS_NET_F_DROPPED);
            return XDP_DROP;
        }
        /* Entrada caducada: se deja para que userland la limpie. Borrarla aqui
         * obligaria a un map_delete por paquete en la ruta caliente. */
    }

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* --- TCP --- */
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Solo interesa la apertura de conexion: SYN sin ACK. El resto del flujo
     * no aporta nada a la deteccion de barridos y multiplicaria el coste. */
    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    __u64 ahora = bpf_ktime_get_boot_ns();

    xdp_stat_inc(AEGIS_XDP_STAT_SYN);

    /* --- Deteccion de barrido --- */
    struct aegis_scan_state *st = bpf_map_lookup_elem(&aegis_scan, &saddr);
    if (!st) {
        struct aegis_scan_state nuevo = {
            .window_start_ns = ahora,
            .port_bitmap = 1ULL << (dport & 63),
            .syn_count = 1,
            .reported = 0,
        };
        bpf_map_update_elem(&aegis_scan, &saddr, &nuevo, BPF_ANY);
        return XDP_PASS;
    }

    /* Ventana deslizante simple: al vencer, se reinicia. Una ventana con
     * historia exigiria mantener muestras por IP, y en XDP el presupuesto de
     * memoria por paquete no lo permite. */
    if (ahora - st->window_start_ns > cfg->scan_window_ns) {
        st->window_start_ns = ahora;
        st->port_bitmap = 0;
        st->syn_count = 0;
        st->reported = 0;
    }

    st->syn_count++;
    st->port_bitmap |= 1ULL << (dport & 63);

    /* Cota inferior del numero de puertos distintos vistos en la ventana. */
    __u32 puertos_distintos = 0;
    __u64 bm = st->port_bitmap;
#pragma unroll
    for (int i = 0; i < 64; i++) {
        puertos_distintos += (__u32)(bm & 1);
        bm >>= 1;
    }

    __u32 flags = AEGIS_NET_F_SYN;

    if (!st->reported && puertos_distintos >= cfg->scan_port_threshold
        && st->syn_count >= cfg->scan_syn_threshold) {
        st->reported = 1;
        xdp_stat_inc(AEGIS_XDP_STAT_SCANS);
        emit_net_event(AEGIS_EVT_NET_SCAN, saddr, daddr, sport, dport,
                       IPPROTO_TCP, flags | AEGIS_NET_F_SCAN_SYN);

        /* Bloqueo automatico solo si userland lo ha habilitado. Por defecto el
         * kernel detecta y userland decide: un bloqueo automatico en la ruta
         * de paquetes es exactamente el mecanismo que un atacante abusa
         * falsificando la IP origen para que bloqueemos a un tercero. */
        if (cfg->flags & AEGIS_XDP_CFG_AUTOBLOCK) {
            struct aegis_block_entry b = {
                .until_ns = ahora + cfg->autoblock_ns,
                .hits = 0,
                .reason = AEGIS_BLOCK_REASON_PORT_SCAN,
                .pad = 0,
            };
            bpf_map_update_elem(&aegis_blocklist, &saddr, &b, BPF_ANY);
        }
        return (cfg->flags & AEGIS_XDP_CFG_AUTOBLOCK) ? XDP_DROP : XDP_PASS;
    }

    /* Muestreo de SYN hacia userland, para que pueda correlacionar sin recibir
     * un evento por paquete. */
    if (cfg->syn_sample_rate && (st->syn_count % cfg->syn_sample_rate) == 0)
        emit_net_event(AEGIS_EVT_NET_CONNECT, saddr, daddr, sport, dport,
                       IPPROTO_TCP, flags);

    return XDP_PASS;
}
