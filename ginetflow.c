/* GInetFlow - IP Flow Manager
 *
 * Copyright (C) 2017 ECLB Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include "ginetflow.h"
#include "ginettuple.h"

#include <netinet/in.h>

#define DEBUG(fmt, args...)
//#define DEBUG(fmt, args...) {g_printf("%s: ",__func__);g_printf (fmt, ## args);}
#define CHECK_BIT(__v,__p) ((__v) & (1<<(__p)))

#define TIMESTAMP_RESOLUTION_US    1000000

/** GInetFlow */
struct _GInetFlow {
    GObject parent;
    struct _GInetFlowTable *table;
    GList list;
    guint64 timestamp;
    guint64 lifetime;
    guint64 packets;
    GInetFlowState state;
    guint family;
    guint16 hash;
    guint16 flags;
    guint8 direction;
    guint16 server_port;
    guint32 server_ip[4];
    GInetTuple tuple;
    gpointer context;
};

struct _GInetFlowClass {
    GObjectClass parent;
};
G_DEFINE_TYPE(GInetFlow, g_inet_flow, G_TYPE_OBJECT);

static int lifetime_values[] = {
    G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT,
    G_INET_FLOW_DEFAULT_NEW_TIMEOUT,
    G_INET_FLOW_DEFAULT_OPEN_TIMEOUT,
};

#define LIFETIME_COUNT (sizeof(lifetime_values) / sizeof(lifetime_values[0]))

/** GInetFlowTable */
struct _GInetFlowTable {
    GObject parent;
    GHashTable *table;
    GQueue *expire_queue[LIFETIME_COUNT];
    GInetFragList *frag_info_list;
    guint64 hits;
    guint64 misses;
    guint64 max;
};
struct _GInetFlowTableClass {
    GObjectClass parent;
};
G_DEFINE_TYPE(GInetFlowTable, g_inet_flow_table, G_TYPE_OBJECT);

/* Packet */
#define ETH_PROTOCOL_8021Q      0x8100
#define ETH_PROTOCOL_8021AD     0x88A8
#define ETH_PROTOCOL_MPLS_UC    0x8847
#define ETH_PROTOCOL_MPLS_MC    0x8848
#define ETH_PROTOCOL_IP         0x0800
#define ETH_PROTOCOL_IPV6       0x86DD
#define ETH_PROTOCOL_PPPOE_SESS 0x8864

typedef struct ethernet_hdr_t {
    guint8 destination[6];
    guint8 source[6];
    guint16 protocol;
} __attribute__ ((packed)) ethernet_hdr_t;

typedef struct vlan_hdr_t {
    guint16 tci;
    guint16 protocol;
} __attribute__ ((packed)) vlan_hdr_t;

typedef struct pppoe_sess_hdr {
    guint8 ver_type;
    guint8 code;
    guint16 session_id;
    guint16 payload_length;
    guint16 ppp_protocol_id;
} __attribute__ ((packed)) pppoe_sess_hdr_t;

#define GRE_HEADER_CSUM         0x8000
#define GRE_HEADER_ROUTING      0x4000
#define GRE_HEADER_KEY          0x2000
#define GRE_HEADER_SEQ          0x1000

typedef struct gre_hdr_t {
    guint16 flags_version;
    guint16 protocol;
} __attribute__ ((packed)) gre_hdr_t;

#define IP_PROTOCOL_HBH_OPT     0
#define IP_PROTOCOL_ICMP        1
#define IP_PROTOCOL_IPV4        4
#define IP_PROTOCOL_TCP         6
#define IP_PROTOCOL_UDP         17
#define IP_PROTOCOL_IPV6        41
#define IP_PROTOCOL_ROUTING     43
#define IP_PROTOCOL_FRAGMENT    44
#define IP_PROTOCOL_GRE         47
#define IP_PROTOCOL_ESP         50
#define IP_PROTOCOL_AUTH        51
#define IP_PROTOCOL_ICMPV6      58
#define IP_PROTOCOL_NO_NEXT_HDR 59
#define IP_PROTOCOL_DEST_OPT    60
#define IP_PROTOCOL_SCTP        132
#define IP_PROTOCOL_MOBILITY    135
#define IP_PROTOCOL_HIPV2       139
#define IP_PROTOCOL_SHIM6       140

#define IPV6_FIRST_8_OCTETS     1
#define AH_HEADER_LEN_ADD       2
#define FOUR_BYTE_UNITS         4
#define EIGHT_OCTET_UNITS       8

/* PPP protocol IDs */
#define PPP_PROTOCOL_IPV4          0x0021
#define PPP_PROTOCOL_IPV6          0x0057

typedef struct ip_hdr_t {
    guint8 ihl_version;
    guint8 tos;
    guint16 tot_len;
    guint16 id;
    guint16 frag_off;
    guint8 ttl;
    guint8 protocol;
    guint16 check;
    guint32 saddr;
    guint32 daddr;
} __attribute__ ((packed)) ip_hdr_t;

typedef struct ip6_hdr_t {
    guint32 ver_tc_fl;
    guint16 pay_len;
    guint8 next_hdr;
    guint8 hop_limit;
    guint8 saddr[16];
    guint8 daddr[16];
} __attribute__ ((packed)) ip6_hdr_t;

typedef struct tcp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 seq;
    guint32 ack;
    guint16 flags;
    guint16 window;
    guint16 check;
    guint16 urg_ptr;
} __attribute__ ((packed)) tcp_hdr_t;

typedef struct udp_hdr_t {
    guint16 source;
    guint16 destination;
    guint16 length;
    guint16 check;
} __attribute__ ((packed)) udp_hdr_t;

typedef struct frag_hdr_t {
    guint8 next_hdr;
    guint8 res;
    guint16 fo_res_mflag;
    guint32 id;
} __attribute__ ((packed)) frag_hdr_t;

typedef struct auth_hdr_t {
    guint8 next_hdr;
    guint8 payload_len;
    guint16 reserved;
    guint64 spi_seq;
    guint64 icv;
} __attribute__ ((packed)) auth_hdr_t;

typedef struct sctp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 ver_tag;
    guint32 checksum;
} __attribute__ ((packed)) sctp_hdr_t;

typedef struct ipv6_partial_ext_hdr_t {
    guint8 next_hdr;
    guint8 hdr_ext_len;
} __attribute__ ((packed)) ipv6_partial_ext_hdr_t;

static gboolean flow_parse_ipv4(GInetTuple * f, const guint8 * data, guint32 length,
                                GInetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * flags, gboolean tunnel);
static gboolean flow_parse_ipv6(GInetTuple * f, const guint8 * data, guint32 length,
                                GInetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * flags, gboolean tunnel);

static inline guint64 get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * (guint64) TIMESTAMP_RESOLUTION_US + tv.tv_usec);
}

static guint32 get_hdr_len(guint8 hdr_ext_len)
{
    return (hdr_ext_len + IPV6_FIRST_8_OCTETS) * EIGHT_OCTET_UNITS;
}

static guint32 flow_hash(GInetFlow * f)
{
    if (f->hash)
        return f->hash;

    f->hash = g_inet_tuple_hash(&f->tuple);

    return f->hash;
}

static gboolean flow_compare(GInetFlow * f1, GInetFlow * f2)
{
    return g_inet_tuple_equal(&f1->tuple, &f2->tuple);
}

static gboolean flow_parse_tcp(GInetTuple * f, const guint8 * data, guint32 length,
                               guint16 * flags)
{
    tcp_hdr_t *tcp = (tcp_hdr_t *) data;
    if (length < sizeof(tcp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(tcp->source);
    guint16 dport = GUINT16_FROM_BE(tcp->destination);

    ((struct sockaddr_in *) &f->src)->sin_port = sport;
    ((struct sockaddr_in *) &f->dst)->sin_port = dport;

    if (flags) {
        *flags = GUINT16_FROM_BE(tcp->flags);
    }
    return TRUE;
}

static gboolean flow_parse_udp(GInetTuple * f, const guint8 * data, guint32 length)
{
    udp_hdr_t *udp = (udp_hdr_t *) data;
    if (length < sizeof(udp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(udp->source);
    guint16 dport = GUINT16_FROM_BE(udp->destination);

    ((struct sockaddr_in *) &f->src)->sin_port = sport;
    ((struct sockaddr_in *) &f->dst)->sin_port = dport;

    return TRUE;
}

static gboolean flow_parse_sctp(GInetTuple * f, const guint8 * data, guint32 length)
{
    sctp_hdr_t *sctp = (sctp_hdr_t *) data;
    if (length < sizeof(sctp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(sctp->source);
    guint16 dport = GUINT16_FROM_BE(sctp->destination);

    ((struct sockaddr_in *) &f->src)->sin_port = sport;
    ((struct sockaddr_in *) &f->dst)->sin_port = dport;

    return TRUE;
}

static gboolean flow_parse_gre(GInetTuple * f, const guint8 * data, guint32 length,
                               GInetFragList * fragments, const uint8_t ** iphr, guint64 ts,
                               guint16 * tcp_flags)
{
    gre_hdr_t *gre = (gre_hdr_t *) data;
    if (length < sizeof(gre_hdr_t))
        return FALSE;
    int offset = sizeof(gre_hdr_t);
    guint16 flags = GUINT16_FROM_BE(gre->flags_version);
    guint16 proto = GUINT16_FROM_BE(gre->protocol);

    if (flags & (GRE_HEADER_CSUM | GRE_HEADER_ROUTING))
        offset += 4;
    if (flags & GRE_HEADER_KEY)
        offset += 4;
    if (flags & GRE_HEADER_SEQ)
        offset += 4;
    if (length < offset)
        return FALSE;

    DEBUG("Protocol: %d\n", proto);
    switch (proto) {
    case ETH_PROTOCOL_IP:
        if (!flow_parse_ipv4
            (f, data + offset, length - offset, fragments, iphr, ts, tcp_flags, TRUE))
            return FALSE;
        break;
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ipv6
            (f, data + offset, length - offset, fragments, iphr, ts, tcp_flags, TRUE))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

static gboolean flow_parse_ipv4(GInetTuple * f, const guint8 * data, guint32 length,
                                GInetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * tcp_flags, gboolean tunnel)
{
    ip_hdr_t *iph = (ip_hdr_t *) data;
    if (length < sizeof(ip_hdr_t))
        return FALSE;
    if (iphr) {
        *iphr = data;
    }

    ((struct sockaddr_in *) &f->src)->sin_family = AF_INET;
    ((struct sockaddr_in *) &f->dst)->sin_family = AF_INET;

    memcpy(&((struct sockaddr_in *) &f->src)->sin_addr, (char *) &iph->saddr,
           sizeof(((struct sockaddr_in *) & f->src)->sin_addr));
    memcpy(&((struct sockaddr_in *) &f->dst)->sin_addr, (char *) &iph->daddr,
           sizeof(((struct sockaddr_in *) & f->dst)->sin_addr));

    DEBUG("Protocol: %d\n", iph->protocol);
    g_inet_tuple_set_protocol(f, iph->protocol);

    /* Don't bother with this for non-first fragments */
    if ((GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) == 0)
    {
        switch (iph->protocol) {
        case IP_PROTOCOL_TCP:
            if (!flow_parse_tcp
                (f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t), tcp_flags))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp(f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_GRE:
            if (tunnel) {
                if (!flow_parse_gre(f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t),
                                    fragments, iphr, ts, tcp_flags))
                    return FALSE;
            }
            break;
        case IP_PROTOCOL_ICMP:
        default:
            ((struct sockaddr_in *) &f->src)->sin_port = 0;
            ((struct sockaddr_in *) &f->dst)->sin_port = 0;
            break;
        }
    }

    /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
     * to find sport and dport. First fragments need to be saved.
     */
    if (fragments && (GUINT16_FROM_BE(iph->frag_off) & 0x3FFF)) {
        GInetFragment entry = { 0 };
        entry.id = iph->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments = ! !(GUINT16_FROM_BE(iph->frag_off) & 0x2000);

        gboolean result = g_inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ipv6(GInetTuple * f, const guint8 * data, guint32 length,
                                GInetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * tcp_flags, gboolean tunnel)
{
    ip6_hdr_t *iph = (ip6_hdr_t *) data;
    frag_hdr_t *fragment_hdr = NULL;
    auth_hdr_t *auth_hdr;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr;

    if (length < sizeof(ip6_hdr_t))
        return FALSE;
    if (iphr)
        *iphr = data;

    ((struct sockaddr_in *) &f->src)->sin_family = AF_INET6;
    ((struct sockaddr_in *) &f->dst)->sin_family = AF_INET6;
    memcpy(&((struct sockaddr_in6 *) &f->src)->sin6_addr, (char *) &iph->saddr,
           sizeof(((struct sockaddr_in6 *) & f->src)->sin6_addr));
    memcpy(&((struct sockaddr_in6 *) &f->dst)->sin6_addr, (char *) &iph->daddr,
           sizeof(((struct sockaddr_in6 *) & f->dst)->sin6_addr));
    g_inet_tuple_set_protocol(f, iph->next_hdr);

    data += sizeof(ip6_hdr_t);
    length -= sizeof(ip6_hdr_t);

  next_header:
    DEBUG("Next Header: %u\n", g_inet_tuple_get_protocol(f));
    switch (g_inet_tuple_get_protocol(f)) {
    case IP_PROTOCOL_TCP:
        if (!flow_parse_tcp(f, data, length, tcp_flags)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_UDP:
        if (!flow_parse_udp(f, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_SCTP:
        if (!flow_parse_sctp(f, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_IPV4:
        if (tunnel)
            if (!flow_parse_ipv4(f, data, length, fragments, iphr, ts, tcp_flags, tunnel)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_IPV6:
        if (tunnel)
            if (!flow_parse_ipv6(f, data, length, fragments, iphr, ts, tcp_flags, tunnel)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_GRE:
        if (tunnel)
            if (!flow_parse_gre(f, data, length, fragments, iphr, ts, tcp_flags)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        if (length < sizeof(ipv6_partial_ext_hdr_t))
            return FALSE;
        ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) data;
        if (length < get_hdr_len(ipv6_part_hdr->hdr_ext_len))
            return FALSE;
        g_inet_tuple_set_protocol(f, ipv6_part_hdr->next_hdr);
        data += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        length -= get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        goto next_header;
    case IP_PROTOCOL_FRAGMENT:
        if (length < sizeof(frag_hdr_t))
            return FALSE;
        fragment_hdr = (frag_hdr_t *) data;
        g_inet_tuple_set_protocol(f, fragment_hdr->next_hdr);

        data += sizeof(frag_hdr_t);
        length -= sizeof(frag_hdr_t);

        /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
         * to find sport and dport - there's no point continuing to parse.
         */
        if ((GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0xFFF8)) {
            break;
        }

        goto next_header;
    case IP_PROTOCOL_AUTH:
        if (length < sizeof(auth_hdr_t))
            return FALSE;
        auth_hdr = (auth_hdr_t *) data;
        if (length < (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS)
            return FALSE;
        g_inet_tuple_set_protocol(f, auth_hdr->next_hdr);
        data += (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
        length -= (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
        goto next_header;
    case IP_PROTOCOL_ESP:
    case IP_PROTOCOL_NO_NEXT_HDR:
    case IP_PROTOCOL_ICMPV6:
    default:
        break;
    }

    /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
     * to find sport and dport. First IP fragments need to be added to the list.
     */
    if (fragments && fragment_hdr)
    {
        GInetFragment entry = { 0 };
        entry.id = fragment_hdr->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments =
         ! !(GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0x1);

        gboolean result = g_inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ip(GInetTuple * f, const guint8 * data, guint32 length,
                              guint16 hash, GInetFragList * fragments,
                              const uint8_t ** iphr, guint64 ts, guint16 * flags,
                              gboolean tunnel)
{
    guint8 version;

    if (length < sizeof(version))
        return FALSE;

    version = *data;
    version = 0x0f & (version >> 4);

    if (version == 4) {
        if (!flow_parse_ipv4(f, data, length, fragments, iphr, ts, flags, tunnel))
            return FALSE;
    } else if (version == 6) {
        if (!flow_parse_ipv6(f, data, length, fragments, iphr, ts, flags, tunnel))
            return FALSE;
    } else {
        DEBUG("Unsupported ip version: %d\n", version);
        return FALSE;
    }
    return TRUE;
}

static gboolean flow_parse(GInetTuple * f, const guint8 * data, guint32 length,
                           guint16 hash, GInetFragList * fragments, const uint8_t ** iphr,
                           guint64 ts, guint16 * flags, gboolean tunnel)
{
    ethernet_hdr_t *e;
    vlan_hdr_t *v;
    pppoe_sess_hdr_t *pppoe;
    guint32 label;
    int labels = 0;
    guint16 type;
    int tags = 0;

    if (!f || !data || !length) {
        DEBUG("Invalid parameters: f:%p data:%p length:%u\n", f, data, length);
        return FALSE;
    }

    if (length < sizeof(ethernet_hdr_t)) {
        DEBUG("Frame too short: %u\n", length);
        return FALSE;
    }

    e = (ethernet_hdr_t *) data;
    data += sizeof(ethernet_hdr_t);
    length -= sizeof(ethernet_hdr_t);
    type = GUINT16_FROM_BE(e->protocol);
  try_again:
    switch (type) {
    case ETH_PROTOCOL_8021Q:
    case ETH_PROTOCOL_8021AD:
        tags++;
        if (tags > 2)
            return FALSE;
        if (length < sizeof(vlan_hdr_t))
            return FALSE;
        v = (vlan_hdr_t *) data;
        type = GUINT16_FROM_BE(v->protocol);
        data += sizeof(vlan_hdr_t);
        length -= sizeof(vlan_hdr_t);
        goto try_again;
    case ETH_PROTOCOL_MPLS_UC:
    case ETH_PROTOCOL_MPLS_MC:
        labels++;
        if (labels > 3)
            return FALSE;
        if (length < sizeof(guint32))
            return FALSE;
        label = GUINT32_FROM_BE(*((guint32 *) data));
        data += sizeof(guint32);
        length -= sizeof(guint32);
        if ((label & 0x100) != 0x100)
            type = ETH_PROTOCOL_MPLS_UC;
        else
            type = ETH_PROTOCOL_IP;
        goto try_again;
    case ETH_PROTOCOL_IP:
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ip(f, data, length, hash, fragments, iphr, ts, flags, tunnel))
            return FALSE;
        break;
    case ETH_PROTOCOL_PPPOE_SESS:
        if (length < sizeof(pppoe_sess_hdr_t))
            return FALSE;
        pppoe = (pppoe_sess_hdr_t *) data;
        if (pppoe->ppp_protocol_id == g_htons(PPP_PROTOCOL_IPV4)) {
            type = ETH_PROTOCOL_IP;
        } else if (pppoe->ppp_protocol_id == g_htons(PPP_PROTOCOL_IPV6)) {
            type = ETH_PROTOCOL_IPV6;
        } else {
            DEBUG("Unsupported PPPOE protocol: 0x%04x\n", g_ntohs(pppoe->ppp_protocol_id));
            return FALSE;
        }
        data += sizeof(pppoe_sess_hdr_t);
        length -= sizeof(pppoe_sess_hdr_t);
        goto try_again;
    default:
        DEBUG("Unsupported ethernet protocol: 0x%04x\n", type);
        return FALSE;
    }
    return TRUE;
}

enum {
    FLOW_STATE = 1,
    FLOW_PACKETS,
    FLOW_HASH,
    FLOW_PROTOCOL,
    FLOW_LPORT,
    FLOW_UPORT,
    FLOW_SERVER_PORT,
    FLOW_LIP,
    FLOW_UIP,
    FLOW_SERVER_IP,
    FLOW_TUPLE,
    FLOW_DIRECTION,
    FLOW_LIFETIME,
    FLOW_TIMESTAMP,
};

static int find_expiry_index(guint64 lifetime)
{
    int i;

    for (i = 0; i < LIFETIME_COUNT; i++) {
        if (lifetime == lifetime_values[i]) {
            return i;
        }
    }
    return 0;
}

static void remove_flow_by_expiry(GInetFlowTable * table, GInetFlow * flow,
                                  guint64 lifetime)
{
    int index = find_expiry_index(lifetime);
    g_queue_unlink(table->expire_queue[index], &flow->list);
}

static void insert_flow_by_expiry(GInetFlowTable * table, GInetFlow * flow,
                                  guint64 lifetime)
{
    int index = find_expiry_index(lifetime);
    g_queue_push_tail_link(table->expire_queue[index], &flow->list);
}

static void g_inet_flow_get_property(GObject * object, guint prop_id,
                                     GValue * value, GParamSpec * pspec)
{
    GInetFlow *flow = G_INET_FLOW(object);
    switch (prop_id) {
    case FLOW_STATE:
        g_value_set_uint(value, flow->state);
        break;
    case FLOW_LIFETIME:
        g_value_set_uint64(value, flow->lifetime);
        break;
    case FLOW_TIMESTAMP:
        g_value_set_uint64(value, flow->timestamp);
        break;
    case FLOW_PACKETS:
        g_value_set_uint64(value, flow->packets);
        break;
    case FLOW_HASH:
        g_value_set_uint(value, flow->hash);
        break;
    case FLOW_PROTOCOL:
        g_value_set_uint(value, g_inet_tuple_get_protocol(&flow->tuple));
        break;
    case FLOW_DIRECTION:
        g_value_set_schar(value, flow->direction);
        break;
    case FLOW_LPORT:
    case FLOW_SERVER_PORT:
        {
            struct sockaddr_in *lower =
                (struct sockaddr_in *) g_inet_tuple_get_lower(&flow->tuple);
            g_value_set_uint(value, lower->sin_port);
            break;
        }
    case FLOW_UPORT:
        {
            struct sockaddr_in *upper =
                (struct sockaddr_in *) g_inet_tuple_get_upper(&flow->tuple);
            g_value_set_uint(value, upper->sin_port);
            break;
        }
    case FLOW_LIP:
    case FLOW_SERVER_IP:
        {
            struct sockaddr_in *lower =
                (struct sockaddr_in *) g_inet_tuple_get_lower(&flow->tuple);
            g_value_set_pointer(value, lower);
            break;
        }
    case FLOW_UIP:
        {
            struct sockaddr_in *upper =
                (struct sockaddr_in *) g_inet_tuple_get_upper(&flow->tuple);
            g_value_set_pointer(value, upper);
            break;
        }
    case FLOW_TUPLE:
        {
            g_value_set_pointer(value, &flow->tuple);
            break;
        }
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(flow, prop_id, pspec);
        break;
    }
}

static void g_inet_flow_finalize(GObject * object)
{
    GInetFlow *flow = G_INET_FLOW(object);
    int index = find_expiry_index(flow->lifetime);
    g_queue_unlink(flow->table->expire_queue[index], &flow->list);
    g_hash_table_steal(flow->table->table, flow);
    G_OBJECT_CLASS(g_inet_flow_parent_class)->finalize(object);
}

static void g_inet_flow_class_init(GInetFlowClass * class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(class);
    object_class->get_property = g_inet_flow_get_property;
    g_object_class_install_property(object_class, FLOW_STATE,
                                    g_param_spec_uint("state", "State",
                                                      "State of the flow",
                                                      FLOW_NEW, FLOW_CLOSED,
                                                      0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_LIFETIME,
                                    g_param_spec_uint64("lifetime", "Lifetime",
                                                      "Lifetime of flow",
                                                      0, G_MAXUINT64, 0,
                                                      G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_TIMESTAMP,
                                    g_param_spec_uint64("timestamp", "Timestamp",
                                                      "Timestamp of flow",
                                                      0, G_MAXUINT64, 0,
                                                      G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_PACKETS,
                                    g_param_spec_uint64("packets", "Packets",
                                                        "Number of packets seen",
                                                        0, G_MAXUINT64, 0,
                                                        G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_HASH,
                                    g_param_spec_uint("hash", "Hash",
                                                      "Tuple hash for the flow",
                                                      0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_PROTOCOL,
                                    g_param_spec_uint("protocol", "Protocol",
                                                      "IP Protocol for the flow",
                                                      0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_DIRECTION,
                                    g_param_spec_char("direction", "Direction",
                                                      "Original or Reply",
                                                      G_MININT8, G_MAXINT8, 0,
                                                      G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_LPORT,
                                    g_param_spec_uint("lport", "LPort",
                                                      "Lower L4 port (smaller value)",
                                                      0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_UPORT,
                                    g_param_spec_uint("uport", "UPort",
                                                      "Upper L4 port (larger value)",
                                                      0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_SERVER_PORT,
                                    g_param_spec_uint("serverport", "ServerPort",
                                                      "Server port (lower port)",
                                                      0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_LIP,
                                    g_param_spec_pointer("lip", "LIP",
                                                         "Lower IP address (smaller value)",
                                                         G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_UIP,
                                    g_param_spec_pointer("uip", "UIP",
                                                         "Upper IP address (larger value)",
                                                         G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_SERVER_IP,
                                    g_param_spec_pointer("serverip", "ServerIP",
                                                         "Server IP address (device with lower port)",
                                                         G_PARAM_READABLE));
    g_object_class_install_property(object_class, FLOW_TUPLE,
                                    g_param_spec_pointer("tuple", "Tuple pointer",
                                                         "Full GInetTuple*",
                                                         G_PARAM_READABLE));
    object_class->finalize = g_inet_flow_finalize;
}

void g_inet_flow_update_tcp(GInetFlow * flow, GInetFlow * packet)
{
    /* FIN */
    if (CHECK_BIT(packet->flags, 0)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->state = FLOW_CLOSED;
            flow->lifetime = G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT;
        }
    }
    /* SYN */
    else if (CHECK_BIT(packet->flags, 1)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->state = FLOW_OPEN;
            flow->lifetime = G_INET_FLOW_DEFAULT_OPEN_TIMEOUT;
        } else {
            flow->state = FLOW_NEW;
            flow->lifetime = G_INET_FLOW_DEFAULT_NEW_TIMEOUT;
            flow->server_port = g_inet_tuple_get_dst_port(&packet->tuple);
        }
    }
    /* RST */
    else if (CHECK_BIT(packet->flags, 2)) {
        flow->state = FLOW_CLOSED;
        flow->lifetime = G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT;
    }

    if (packet->direction == FLOW_DIRECTION_UNKNOWN) {
        packet->direction = g_inet_tuple_get_dst_port(&packet->tuple) == flow->server_port ?
            FLOW_DIRECTION_ORIGINAL : FLOW_DIRECTION_REPLY;
    }
}

void g_inet_flow_update_udp(GInetFlow * flow, GInetFlow * packet)
{
    packet->direction =
            g_inet_tuple_get_dst_port(&packet->tuple) <
            g_inet_tuple_get_src_port(&packet->
                                      tuple) ? FLOW_DIRECTION_ORIGINAL : FLOW_DIRECTION_REPLY;

    if (flow->direction && packet->direction && packet->direction != flow->direction) {
        flow->state = FLOW_OPEN;
        flow->lifetime = G_INET_FLOW_DEFAULT_OPEN_TIMEOUT;
    }
}

void g_inet_flow_update(GInetFlow * flow, GInetFlow * packet)
{
    if (g_inet_tuple_get_protocol(&flow->tuple) == IP_PROTOCOL_TCP) {
        g_inet_flow_update_tcp(flow, packet);
    } else if (g_inet_tuple_get_protocol(&flow->tuple) == IP_PROTOCOL_UDP) {
        g_inet_flow_update_udp(flow, packet);
    }
    flow->direction = packet->direction;
}

static void g_inet_flow_init(GInetFlow * flow)
{
    memset(&flow->tuple, 0, sizeof(flow->tuple));
    flow->state = FLOW_NEW;
}

GInetFlow *g_inet_flow_expire(GInetFlowTable * table, guint64 ts)
{
    GList *iter;
    int i;

    for (i = 0; i < LIFETIME_COUNT; i++) {
        guint64 timeout = (lifetime_values[i] * TIMESTAMP_RESOLUTION_US);
        GList *first = g_queue_peek_head_link(table->expire_queue[i]);
        if (first) {
            GInetFlow *flow = (GInetFlow *) first->data;
            if (flow->timestamp + timeout <= ts) {
                return flow;
            }
        }
    }
    return NULL;
}

GInetFlow *g_inet_flow_get(GInetFlowTable * table, const guint8 * frame, guint length)
{
    return g_inet_flow_get_full(table, frame, length, 0, 0, FALSE, TRUE, FALSE, NULL, NULL);
}

GInetFlow *g_inet_flow_get_full(GInetFlowTable * table,
                                const guint8 * frame, guint length,
                                guint16 hash, guint64 timestamp, gboolean update,
                                gboolean l2, gboolean inspect_tunnel, const uint8_t ** iphr,
                                GInetTuple **ret_tuple)
{
    GInetFlow packet = {.timestamp = timestamp };
    GInetTuple *tuple = NULL;
    GInetTuple tmp_tuple = { 0 };
    GInetFlow *flow = NULL;

    if (ret_tuple) {
        tuple = calloc(1, sizeof(GInetTuple));
        *ret_tuple = tuple;
    }
    else
    {
        tuple = &tmp_tuple;
    }

    if (l2) {
        if (!flow_parse
            (tuple, frame, length, hash, table->frag_info_list, iphr, timestamp,
             &packet.flags, inspect_tunnel)) {
            goto exit;
        }
    } else
        if (!flow_parse_ip
            (tuple, frame, length, hash, table->frag_info_list, iphr, timestamp,
             &packet.flags, inspect_tunnel)) {
        goto exit;
    }

    packet.tuple = *tuple;
    packet.hash = 0;

    flow = (GInetFlow *) g_hash_table_lookup(table->table, &packet);
    if (flow) {
        if (update) {
            remove_flow_by_expiry(table, flow, flow->lifetime);
            g_inet_flow_update(flow, &packet);
            insert_flow_by_expiry(table, flow, flow->lifetime);
            flow->timestamp = timestamp ? : get_time_us();
            flow->packets++;
        }
        table->hits++;
    } else {
        /* Check if max table size is reached */
        if (table->max > 0 && g_hash_table_size(table->table) >= table->max) {
            goto exit;
        }

        flow = (GInetFlow *) g_object_new(G_INET_TYPE_FLOW, NULL);
        flow->table = table;
        flow->list.data = flow;
        /* Set default lifetime before processing further - this may be over written */
        flow->lifetime = G_INET_FLOW_DEFAULT_NEW_TIMEOUT;
        flow->family = packet.family;
        flow->direction = packet.direction;
        flow->hash = packet.hash;
        flow->tuple = packet.tuple;
        if (packet.server_port)
        {
            flow->server_port = packet.server_port;
        }
        memcpy(flow->server_ip, packet.server_ip, sizeof(packet.server_ip));
        g_hash_table_replace(table->table, (gpointer) flow, (gpointer) flow);
        table->misses++;
        flow->timestamp = timestamp ? : get_time_us();
        g_inet_flow_update(flow, &packet);
        insert_flow_by_expiry(table, flow, flow->lifetime);
        flow->packets++;
    }
  exit:
    return flow;
}

GInetFlow *g_inet_flow_create(GInetFlowTable * table, GInetTuple * tuple)
{
    GInetFlow *flow;

    /* Check if max table size is reached */
    if (table->max > 0 && g_hash_table_size(table->table) >= table->max) {
        return NULL;
    }

    flow = (GInetFlow *) g_object_new(G_INET_TYPE_FLOW, NULL);
    flow->table = table;
    flow->list.data = flow;
    /* Set default lifetime before processing further */
    flow->lifetime = G_INET_FLOW_DEFAULT_NEW_TIMEOUT;
    flow->family = ((struct sockaddr *) &(tuple->src))->sa_family;
    flow->hash = g_inet_tuple_hash(tuple);
    flow->tuple = *tuple;
    g_hash_table_replace(table->table, (gpointer) flow, (gpointer) flow);
    flow->timestamp = get_time_us();
    insert_flow_by_expiry(table, flow, flow->lifetime);

    return flow;
}

static void g_inet_flow_table_finalize(GObject * object)
{
    int i;

    GInetFlowTable *table = G_INET_FLOW_TABLE(object);
    g_hash_table_remove_all(table->table);
    g_hash_table_destroy(table->table);
    g_inet_frag_list_free(table->frag_info_list);
    for (i = 0; i < LIFETIME_COUNT; i++) {
        g_queue_free(table->expire_queue[i]);
    }
    G_OBJECT_CLASS(g_inet_flow_table_parent_class)->finalize(object);
}

enum {
    TABLE_SIZE = 1,
    TABLE_HITS,
    TABLE_MISSES,
    TABLE_MAX
};

static void g_inet_flow_table_get_property(GObject * object, guint prop_id,
                                           GValue * value, GParamSpec * pspec)
{
    GInetFlowTable *table = G_INET_FLOW_TABLE(object);
    switch (prop_id) {
    case TABLE_SIZE:
        g_value_set_uint64(value, g_hash_table_size(table->table));
        break;
    case TABLE_HITS:
        g_value_set_uint64(value, table->hits);
        break;
    case TABLE_MISSES:
        g_value_set_uint64(value, table->misses);
        break;
    case TABLE_MAX:
        g_value_set_uint64(value, table->max);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(table, prop_id, pspec);
        break;
    }
}

static void g_inet_flow_table_class_init(GInetFlowTableClass * class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(class);
    object_class->get_property = g_inet_flow_table_get_property;
    g_object_class_install_property(object_class, TABLE_SIZE,
                                    g_param_spec_uint64("size", "Size",
                                                        "Total number of flows",
                                                        0, 0, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, TABLE_HITS,
                                    g_param_spec_uint64("hits", "Hits",
                                                        "Total number of packets that matched an existing flow",
                                                        0, 0, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, TABLE_MISSES,
                                    g_param_spec_uint64("misses", "Misses",
                                                        "Total number of packets that did not match an existing flow",
                                                        0, 0, 0, G_PARAM_READABLE));
    g_object_class_install_property(object_class, TABLE_MAX,
                                    g_param_spec_uint64("max", "Max",
                                                        "Maximum number of flows allowed in the table",
                                                        0, 0, 0, G_PARAM_READABLE));
    object_class->finalize = g_inet_flow_table_finalize;
}

static void g_inet_flow_table_init(GInetFlowTable * table)
{
    int i;

    table->table = g_hash_table_new_full((GHashFunc) flow_hash, (GEqualFunc) flow_compare, NULL, g_object_unref);
    table->frag_info_list = g_inet_frag_list_new();

    for (i = 0; i < LIFETIME_COUNT; i++) {
        table->expire_queue[i] = g_queue_new();
    }
}

GInetFlowTable *g_inet_flow_table_new(void)
{
    return (GInetFlowTable *) g_object_new(G_INET_TYPE_FLOW_TABLE, NULL);
}

void g_inet_flow_table_max_set(GInetFlowTable * table, guint64 value)
{
    table->max = value;
}

void g_inet_flow_foreach(GInetFlowTable * table, GIFFunc func, gpointer user_data)
{
    int i;

    for (i = 0; i < LIFETIME_COUNT; i++) {
        g_queue_foreach(table->expire_queue[i], (GFunc) func, user_data);
    }
}

GInetTuple *g_inet_flow_parse(const guint8 * frame, guint length, GInetFragList * fragments,
                              GInetTuple * result, gboolean inspect_tunnel)
{
    if (!result)
        result = calloc(1, sizeof(GInetTuple));
    flow_parse(result, frame, length, 0, fragments, NULL, 0, NULL, inspect_tunnel);
    return result;
}

GInetFlow *g_inet_flow_lookup(GInetFlowTable * table, GInetTuple * tuple)
{
    GInetFlow packet;

    packet.tuple = *tuple;
    packet.hash = 0;
    return (GInetFlow *) g_hash_table_lookup(table->table, &packet);
}

void g_inet_flow_establish(GInetFlowTable * table, GInetFlow * flow)
{
    remove_flow_by_expiry(table, flow, flow->lifetime);
    flow->state = FLOW_OPEN;
    flow->lifetime = G_INET_FLOW_DEFAULT_OPEN_TIMEOUT;
    insert_flow_by_expiry(table, flow, flow->lifetime);
}
