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
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include "ginetflow.h"

#define DEBUG(fmt, args...)
//#define DEBUG(fmt, args...) {g_printf("%s: ",__func__);g_printf (fmt, ## args);}

/** GInetFlow */
struct _GInetFlow
{
    GObject parent;
    guint64 timestamp;
    guint64 packets;
    GInetFlowState state;
    guint family;
    guint16 hash;
    struct
    {
        guint16 protocol;
        guint16 lower_port;
        guint16 upper_port;
        guint32 lower_ip[4];
        guint32 upper_ip[4];
    } tuple;
    gpointer context;
};
struct _GInetFlowClass
{
    GObjectClass parent;
};
G_DEFINE_TYPE (GInetFlow, g_inet_flow, G_TYPE_OBJECT);

/** GInetFlowTable */
struct _GInetFlowTable
{
    GObject parent;
    GHashTable *table;
    GList *list;
    guint64 hits;
    guint64 misses;
};
struct _GInetFlowTableClass
{
    GObjectClass parent;
};
G_DEFINE_TYPE (GInetFlowTable, g_inet_flow_table, G_TYPE_OBJECT);

/* Packet */
#define ETH_PROTOCOL_8021Q      0x8100
#define ETH_PROTOCOL_8021AD     0x88A8
#define ETH_PROTOCOL_IP         0x0800
#define ETH_PROTOCOL_IPV6       0x86DD
#define ETH_PROTOCOL_PPPOE_SESS 0x8864

typedef struct ethernet_hdr_t
{
    guint8 destination[6];
    guint8 source[6];
    guint16 protocol;
} __attribute__((packed)) ethernet_hdr_t;

typedef struct vlan_hdr_t {
    guint16  tci;
    guint16  protocol;
} __attribute__((packed)) vlan_hdr_t;

typedef struct pppoe_sess_hdr
{
    u_int8_t ver_type;
    u_int8_t code;
    u_int16_t session_id;
    u_int16_t payload_length;
    u_int16_t ppp_protocol_id;
} __attribute__ ((packed)) pppoe_sess_hdr_t;

#define IP_PROTOCOL_ICMP        1
#define IP_PROTOCOL_TCP         6
#define IP_PROTOCOL_UDP         17
/* PPP protocol IDs */
#define PPP_PROTOCOL_IPV4          0x0021
#define PPP_PROTOCOL_IPV6          0x0057

typedef struct ip_hdr_t
{
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
} __attribute__((packed)) ip_hdr_t;

typedef struct ip6_hdr_t
{
    guint32 ver_tc_fl;
    guint16 pay_len;
    guint8 next_hdr;
    guint8 hop_limit;
    guint8 saddr[16];
    guint8 daddr[16];
} __attribute__((packed)) ip6_hdr_t;

typedef struct tcp_hdr_t
{
    guint16 source;
    guint16 destination;
    guint32 seq;
    guint32 ack;
    guint16 flags;
    guint16 window;
    guint16 check;
    guint16 urg_ptr;
} __attribute__((packed)) tcp_hdr_t;

typedef struct udp_hdr_t
{
    guint16 source;
    guint16 destination;
    guint16 length;
    guint16 check;
} __attribute__((packed)) udp_hdr_t;

static inline guint64
get_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (tv.tv_sec * (guint64) 1000000 + tv.tv_usec);
}

static inline guint16
crc16 (guint16 iv, guint64 p)
{
    int i;
    int j;
    guint32 b;
    guint16 poly = 0x1021;
    for (i=7; i>=0; i--)
    {
        b = (p >> (i*8)) & 0xff;
        for (j=7; j>=0; j--)
        {
            iv = ((iv << 1) ^ ((((iv >> 15)&1) ^ ((b >> j)&1)) ? poly : 0)) & 0xffff;
        }
    }
    return iv;
}

static guint16
flow_hash (GInetFlow *f)
{
    if (f->hash)
        return f->hash;

    guint16 src_crc = 0xffff;
    guint16 dst_crc = 0xffff;
    guint16 prot_crc = 0xffff;
    src_crc = crc16 (src_crc, ((guint64)f->tuple.lower_ip[0]) << 32 | f->tuple.lower_ip[1]);
    src_crc = crc16 (src_crc, ((guint64)f->tuple.lower_ip[2]) << 32 | f->tuple.lower_ip[3]);
    src_crc = crc16 (src_crc, ((guint64)f->tuple.lower_port) << 48);
    dst_crc = crc16 (dst_crc, ((guint64)f->tuple.upper_ip[0]) << 32 | f->tuple.upper_ip[1]);
    dst_crc = crc16 (dst_crc, ((guint64)f->tuple.upper_ip[2]) << 32 | f->tuple.upper_ip[3]);
    dst_crc = crc16 (dst_crc, ((guint64)f->tuple.upper_port) << 48);
    prot_crc = crc16 (prot_crc, ((guint64)f->tuple.protocol) << 56);
    f->hash = (src_crc ^ dst_crc ^ prot_crc);
    g_printf ("%s", "");
    return f->hash;
}

static gboolean
flow_compare (GInetFlow *f1, GInetFlow *f2)
{
    if (f1->tuple.protocol != f2->tuple.protocol)
        return FALSE;
    if (f1->tuple.lower_port != f2->tuple.lower_port)
        return FALSE;
    if (f1->tuple.upper_port != f2->tuple.upper_port)
        return FALSE;
    if (memcmp (f1->tuple.upper_ip, f2->tuple.upper_ip, 16) != 0)
        return FALSE;
    if (memcmp (f1->tuple.lower_ip, f2->tuple.lower_ip, 16) != 0)
        return FALSE;
    return TRUE;
}

static gboolean
flow_parse_tcp (GInetFlow *f, const guint8 *data, guint32 length)
{
    tcp_hdr_t *tcp = (tcp_hdr_t *) data;
    if (length < sizeof (tcp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE (tcp->source);
    guint16 dport = GUINT16_FROM_BE (tcp->destination);
    if (sport < dport)
    {
        f->tuple.lower_port= sport;
        f->tuple.upper_port= dport;
    }
    else
    {
        f->tuple.upper_port= sport;
        f->tuple.lower_port = dport;
    }
    return TRUE;
}

static gboolean
flow_parse_udp (GInetFlow *f, const guint8 *data, guint32 length)
{
    udp_hdr_t *udp = (udp_hdr_t *) data;
    if (length < sizeof (udp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE (udp->source);
    guint16 dport = GUINT16_FROM_BE (udp->destination);
    if (sport < dport)
    {
        f->tuple.lower_port= sport;
        f->tuple.upper_port= dport;
    }
    else
    {
        f->tuple.upper_port= sport;
        f->tuple.lower_port = dport;
    }
    return TRUE;
}

static gboolean
flow_parse_ipv4 (GInetFlow *f, const guint8 *data, guint32 length)
{
    ip_hdr_t *iph = (ip_hdr_t *) data;
    if (length < sizeof (ip_hdr_t))
        return FALSE;
    guint32 sip = GINT32_FROM_BE (iph->saddr);
    guint32 dip = GINT32_FROM_BE (iph->daddr);
    if (sip < dip)
    {
        f->tuple.lower_ip[0] = iph->saddr;
        f->tuple.upper_ip[0] = iph->daddr;
    }
    else
    {
        f->tuple.upper_ip[0] = iph->saddr;
        f->tuple.lower_ip[0] = iph->daddr;
    }
    f->tuple.protocol = iph->protocol;
    switch (iph->protocol)
    {
        case IP_PROTOCOL_TCP:
            if (!flow_parse_tcp (f, data + sizeof (ip_hdr_t), length - sizeof (ip_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp (f, data + sizeof (ip_hdr_t), length - sizeof (ip_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_ICMP:
            f->tuple.lower_port= 0;
            f->tuple.upper_port= 0;
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

static gboolean
flow_parse_ipv6 (GInetFlow *f, const guint8 *data, guint32 length)
{
    ip6_hdr_t *iph = (ip6_hdr_t *) data;
    if (length < sizeof (ip6_hdr_t))
        return FALSE;
    if (memcmp (iph->saddr, iph->daddr, 16) < 0)
    {
        memcpy (f->tuple.lower_ip, iph->saddr, 16);
        memcpy (f->tuple.upper_ip, iph->daddr, 16);
    }
    else
    {
        memcpy (f->tuple.upper_ip, iph->saddr, 16);
        memcpy (f->tuple.lower_ip, iph->daddr, 16);
    }
    f->tuple.protocol = iph->next_hdr;
    switch (iph->next_hdr)
    {
        case IP_PROTOCOL_TCP:
            if (!flow_parse_tcp (f, data + sizeof (ip6_hdr_t), length - sizeof (ip6_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp (f, data + sizeof (ip6_hdr_t), length - sizeof (ip6_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_ICMP:
            f->tuple.lower_port= 0;
            f->tuple.upper_port= 0;
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

static gboolean
flow_parse (GInetFlow *f, const guint8 *data, guint32 length, guint16 hash)
{
    ethernet_hdr_t *e;
    vlan_hdr_t *v;
    pppoe_sess_hdr_t *pppoe_hdr;
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
    switch (type)
    {
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
        case ETH_PROTOCOL_IP:
            f->family = G_SOCKET_FAMILY_IPV4;
            f->hash = hash;
            if (!flow_parse_ipv4 (f, data, length))
                return FALSE;
            break;
        case ETH_PROTOCOL_IPV6:
            f->family = G_SOCKET_FAMILY_IPV6;
            f->hash = hash;
            if (!flow_parse_ipv6 (f, data, length))
                return FALSE;
            break;
        case ETH_PROTOCOL_PPPOE_SESS:
            pppoe_hdr = (pppoe_sess_hdr_t *) data;

            if (g_ntohs (pppoe_hdr->ppp_protocol_id) == PPP_PROTOCOL_IPV4 ||
                g_ntohs (pppoe_hdr->ppp_protocol_id) == PPP_PROTOCOL_IPV6)
            {
                data += sizeof (pppoe_sess_hdr_t);
                length -= sizeof (pppoe_sess_hdr_t);

                if (g_ntohs (pppoe_hdr->ppp_protocol_id) == PPP_PROTOCOL_IPV4)
                {
                    f->family = G_SOCKET_FAMILY_IPV4;
                    f->hash = hash;
                    if (!flow_parse_ipv4 (f, data, length))
                        return FALSE;
                }
                else
                {
                    f->family = G_SOCKET_FAMILY_IPV6;
                    f->hash = hash;
                    if (!flow_parse_ipv6 (f, data, length))
                        return FALSE;
                }
            }
            break;
        default:
            DEBUG("Unsupported ethernet protocol: 0x%04x\n", type);
            return FALSE;
    }
    return TRUE;
}

static void
g_inet_flow_finalize (GObject *object)
{
    G_OBJECT_CLASS (g_inet_flow_parent_class)->finalize (object);
}

enum
{
    FLOW_STATE = 1,
    FLOW_PACKETS,
    FLOW_HASH,
    FLOW_PROTOCOL,
    FLOW_LPORT,
    FLOW_UPORT,
    FLOW_LIP,
    FLOW_UIP,
};

static void
g_inet_flow_get_property (GObject *object,
                guint prop_id, GValue *value, GParamSpec *pspec)
{
    GInetFlow *flow = G_INET_FLOW (object);
    switch (prop_id)
    {
    case FLOW_STATE:
        g_value_set_uint (value, flow->state);
        break;
    case FLOW_PACKETS:
        g_value_set_uint64 (value, flow->packets);
        break;
    case FLOW_HASH:
        g_value_set_uint (value, flow->hash);
        break;
    case FLOW_PROTOCOL:
        g_value_set_uint (value, flow->tuple.protocol);
        break;
    case FLOW_LPORT:
        g_value_set_uint (value, flow->tuple.lower_port);
        break;
    case FLOW_UPORT:
        g_value_set_uint (value, flow->tuple.upper_port);
        break;
    case FLOW_LIP:
    {
        GInetAddress *gaddress = g_inet_address_new_from_bytes (
                (guint8 *)flow->tuple.lower_ip, flow->family);
        gchar *address = g_inet_address_to_string (gaddress);
        g_value_set_string (value, address);
        g_free (address);
        g_object_unref (gaddress);
        break;
    }
    case FLOW_UIP:
    {
        GInetAddress *gaddress = g_inet_address_new_from_bytes (
                (guint8 *)flow->tuple.upper_ip, flow->family);
        gchar *address = g_inet_address_to_string (gaddress);
        g_value_set_string (value, address);
        g_free (address);
        g_object_unref (gaddress);
        break;
    }
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (flow, prop_id, pspec);
        break;
      }
}

static void
g_inet_flow_class_init (GInetFlowClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (class);
    object_class->get_property = g_inet_flow_get_property;
    g_object_class_install_property (object_class, FLOW_STATE,
        g_param_spec_uint ("state", "State",
                "State of the flow",
                FLOW_NEW, FLOW_CLOSED, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_PACKETS,
        g_param_spec_uint64 ("packets", "Packets",
                "Number of packets seen",
                0, G_MAXUINT64, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_HASH,
        g_param_spec_uint ("hash", "Hash",
                "Tuple hash for the flow",
                0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_PROTOCOL,
        g_param_spec_uint ("protocol", "Protocol",
                "IP Protocol for the flow",
                0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_LPORT,
        g_param_spec_uint ("lport", "LPort",
                "Lower L4 port (smaller value)",
                0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_UPORT,
        g_param_spec_uint ("uport", "UPort",
                "Upper L4 port (larger value)",
                0, G_MAXUINT16, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_LIP,
        g_param_spec_string ("lip", "LIP",
                "Lower IP address (smaller value)",
                NULL, G_PARAM_READABLE));
    g_object_class_install_property (object_class, FLOW_UIP,
        g_param_spec_string ("uip", "UIP",
                "Upper IP address (larger value)",
                NULL, G_PARAM_READABLE));
    object_class->finalize = g_inet_flow_finalize;
}

static void
g_inet_flow_init (GInetFlow *flow)
{
    flow->state = FLOW_NEW;
}

GInetFlow *
g_inet_flow_get_full (GInetFlowTable *table, const guint8 *frame, guint length,
        guint16 hash, guint64 timestamp, gboolean update)
{
    GInetFlow packet = {};
    GInetFlow *flow;

    if (!flow_parse (&packet, frame, length, hash))
    {
        return NULL;
    }

    flow = (GInetFlow *) g_hash_table_lookup (table->table, &packet);
    if (flow)
    {
        if (update)
        {
            table->list = g_list_remove (table->list, flow);
            table->list = g_list_prepend (table->list, flow);
        }
        table->hits++;
    }
    else
    {
        flow = (GInetFlow *) g_object_new (G_INET_TYPE_FLOW, NULL);
        flow->family = packet.family;
        flow->hash = packet.hash;
        flow->tuple = packet.tuple;
        g_hash_table_replace (table->table, (gpointer) flow, (gpointer) flow);
        table->list = g_list_prepend (table->list, flow);
        table->misses++;
    }
    if (update)
    {
        flow->timestamp = timestamp ?: get_time_us ();
        flow->packets++;
    }
    return flow;
}

GInetFlow *
g_inet_flow_get (GInetFlowTable *table, const guint8 *frame, guint length)
{
    return g_inet_flow_get_full (table, frame, length, 0, 0, FALSE);
}

GInetFlow *
g_inet_flow_expire (GInetFlowTable *table, guint64 ts)
{
    GList *iter;

    for (iter = g_list_first (table->list); iter; iter = g_list_next (iter))
    {
        GInetFlow *flow = (GInetFlow *) iter->data;
        guint64 timeout = (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
        if (flow->timestamp + timeout <= ts)
        {
            table->list = g_list_remove (table->list, flow);
            g_hash_table_remove (table->table, (gpointer) flow);
            return flow;
        }
    }
    return NULL;
}

static void
g_inet_flow_table_finalize (GObject *object)
{
    GInetFlowTable *table = G_INET_FLOW_TABLE (object);
    g_list_free (table->list);
    g_hash_table_destroy (table->table);
    G_OBJECT_CLASS (g_inet_flow_table_parent_class)->finalize (object);
}

enum
{
    TABLE_SIZE = 1,
    TABLE_HITS,
    TABLE_MISSES
};

static void
g_inet_flow_table_get_property (GObject *object,
                guint prop_id, GValue *value, GParamSpec *pspec)
{
    GInetFlowTable *table = G_INET_FLOW_TABLE (object);
    switch (prop_id)
    {
    case TABLE_SIZE:
        g_value_set_uint64 (value, g_hash_table_size (table->table));
        break;
    case TABLE_HITS:
        g_value_set_uint64 (value, table->hits);
        break;
    case TABLE_MISSES:
        g_value_set_uint64 (value, table->misses);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (table, prop_id, pspec);
        break;
      }
}

static void
g_inet_flow_table_class_init (GInetFlowTableClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (class);
    object_class->get_property = g_inet_flow_table_get_property;
    g_object_class_install_property (object_class, TABLE_SIZE,
        g_param_spec_uint64 ("size", "Size",
                "Total number of flows",
                0, 0, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, TABLE_HITS,
        g_param_spec_uint64 ("hits", "Hits",
                "Total number of packets that matched an existing flow",
                0, 0, 0, G_PARAM_READABLE));
    g_object_class_install_property (object_class, TABLE_MISSES,
        g_param_spec_uint64 ("misses", "Misses",
                "Total number of packets that did not match an existing flow",
                0, 0, 0, G_PARAM_READABLE));
    object_class->finalize = g_inet_flow_table_finalize;
}

static void
g_inet_flow_table_init (GInetFlowTable *table)
{
    table->table = g_hash_table_new_full ((GHashFunc) flow_hash, (GEqualFunc) flow_compare, NULL, g_object_unref);
}

GInetFlowTable *
g_inet_flow_table_new (void)
{
    return (GInetFlowTable *) g_object_new (G_INET_TYPE_FLOW_TABLE, NULL);
}

void
g_inet_flow_foreach (GInetFlowTable *table, GIFFunc func, gpointer user_data)
{
    g_list_foreach (table->list, (GFunc) func, user_data);
}
