/* GInetFlow - Unit tests
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
#include "ginetflow.c"
#include <np.h>

static GInetFlow test_flow;
#define MAX_BUFFER_SIZE     1600
static guint8 test_buffer[MAX_BUFFER_SIZE];
static guint8 test_src[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static guint8 test_dst[] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };

static guint make_pkt(guint8 * buffer, guint family, guint protocol)
{
    guint8 *p = buffer;
    ethernet_hdr_t *eth = (ethernet_hdr_t *) p;
    memcpy(eth->destination, test_src, 6);
    memcpy(eth->source, test_dst, 6);
    eth->protocol = g_htons(ETH_PROTOCOL_IP);
    p += sizeof(ethernet_hdr_t);
    if (family == 4) {
        ip_hdr_t *ip = (ip_hdr_t *) p;
        ip->ihl_version = 0x45;
        ip->tos = 0x00;
        ip->tot_len = 0x0000;
        ip->id = 0x1234;
        ip->frag_off = 0x0000;
        ip->ttl = 0xff;
        ip->protocol = protocol;
        ip->check = 0x00;
        ip->saddr = 0x12345678;
        ip->daddr = 0x87654321;
        p += sizeof(ip_hdr_t);
    } else {
        ip6_hdr_t *ip = (ip6_hdr_t *) p;
        //TODO
        p += sizeof(ip6_hdr_t);
    }
    if (protocol == IP_PROTOCOL_TCP) {
        tcp_hdr_t *tcp = (tcp_hdr_t *) p;
        tcp->source = 0x1111;
        tcp->destination = 0x2222;
        tcp->seq = 0;
        tcp->ack = 0;
        tcp->flags = 0;
        tcp->window = 0;
        tcp->check = 0;
        tcp->urg_ptr = 0;
        p += sizeof(tcp_hdr_t);
    } else {
        udp_hdr_t *udp = (udp_hdr_t *) p;
        udp->source = 0x0000;
        udp->destination = 0x0000;
        udp->length = 0x0000;
        udp->check = 0x0000;
        p += sizeof(udp_hdr_t);
    }
    return (guint) (p - buffer);
}

static void setup_test()
{
    memset(&test_flow, 0, sizeof(GInetFlow));
    memset(test_buffer, 0, MAX_BUFFER_SIZE);
}

void test_flow_parse_null_flow()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(NULL, test_buffer, 64, 0));
}

void test_flow_parse_null_buffer()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, NULL, 64, 0));
}

void test_flow_parse_0_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, 0, 0));
}

void test_flow_parse_less_than_eth_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, sizeof(ethernet_hdr_t) - 1, 0));
}

void test_flow_parse_udp()
{
    setup_test();
    guint len = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_create()
{
    GInetFlowTable *table = g_inet_flow_table_new();
    guint64 now = get_time_us();
    setup_test();
    NP_ASSERT_NOT_NULL(table);
    guint len = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    GInetFlow *flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE);
    NP_ASSERT_NOT_NULL(flow);
    guint64 size;
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(table);
}

void test_flow_table_size()
{
    GInetFlowTable *table = g_inet_flow_table_new();
    setup_test();
    NP_ASSERT_NOT_NULL(table);

    guint64 max;
    g_object_get(table, "max", &max, NULL);
    NP_ASSERT_EQUAL(max, 0);

    g_inet_flow_table_max_set(table, 1);
    g_object_get(table, "max", &max, NULL);
    NP_ASSERT_EQUAL(max, 1);

    guint pk1 = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    GInetFlow *flow1 = g_inet_flow_get_full(table, test_buffer, pk1, 0, get_time_us(), TRUE);
    NP_ASSERT_NOT_NULL(flow1);

    guint pk2 = make_pkt(test_buffer, 4, IP_PROTOCOL_TCP);
    GInetFlow *flow2 = g_inet_flow_get_full(table, test_buffer, pk2, 0, get_time_us(), TRUE);
    NP_ASSERT_NULL(flow2);

    g_object_unref(table);
}

void test_flow_not_expired()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE)));
    NP_ASSERT_NULL(g_inet_flow_expire
                   (table, now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000) - 1));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(table);
}

void test_flow_expired()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE)));
    NP_ASSERT_NOT_NULL(g_inet_flow_expire
                       (table, now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000)));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);
    g_object_unref(table);
}

void test_flow_tcp_new()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, 4, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow = g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);
    g_object_unref(table);
}
