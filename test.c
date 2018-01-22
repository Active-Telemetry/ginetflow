/* GInetFlow / GInetTuple - Unit tests
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
#include "ginettuple.c"
#include "ginetfraglist.c"
#include <arpa/inet.h>
#include <np.h>

static GInetTuple *test_tuple = NULL;
#define MAX_BUFFER_SIZE     1600

#define TEST_SPORT 0x1111
#define TEST_DPORT 0x2222
#define TEST_SADDR 0x12345678
#define TEST_DADDR 0x87654321

#define SYN        0x0002
#define SYN_ACK    0x0012
#define ACK        0x0010
#define FIN        0x0001
#define FIN_ACK    0x0011
#define RST        0x0004

static guint8 test_buffer[MAX_BUFFER_SIZE];
static guint8 test_src[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static guint8 test_dst[] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };

static guint8 test_ip6src[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

static guint8 test_ip6dst[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

typedef struct icmp_hdr_t {
    guint8 type;
    guint8 code;
    guint16 chksum;
} __attribute__ ((packed)) icmp_hdr_t;

static guint8 *build_hdr_eth(guint8 * buffer, guint16 next_eth_protocol)
{
    guint8 *p = buffer;
    ethernet_hdr_t *eth = (ethernet_hdr_t *) p;
    memcpy(eth->destination, test_src, 6);
    memcpy(eth->source, test_dst, 6);
    eth->protocol = g_htons(next_eth_protocol);
    p += sizeof(ethernet_hdr_t);
    return p;
}

static guint8 *build_hdr_vlan(guint8 * buffer,
                              guint16 vlan_protocol, guint16 next_protocol, int count)
{
    guint8 *p = buffer;

    for (int i = 1; i < count; i++) {
        vlan_hdr_t *vlan = (vlan_hdr_t *) p;
        vlan->tci = 0xc7db;
        vlan->protocol = g_htons(vlan_protocol);
        p += sizeof(vlan_hdr_t);
    }

    vlan_hdr_t *vlan = (vlan_hdr_t *) p;
    vlan->tci = 0xc7db;
    vlan->protocol = g_htons(next_protocol);
    p += sizeof(vlan_hdr_t);

    return p;
}

static guint8 *build_hdr_bad_ipv4(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x79;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = 0x1234;
    ip->frag_off = 0x0000;
    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = htonl(TEST_DADDR);
        ip->daddr = htonl(TEST_SADDR);
    } else {
        ip->saddr = htonl(TEST_SADDR);
        ip->daddr = htonl(TEST_DADDR);
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv4(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x45;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = 0x1234;
    ip->frag_off = 0x0000;
    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = htonl(TEST_DADDR);
        ip->daddr = htonl(TEST_SADDR);
    } else {
        ip->saddr = htonl(TEST_SADDR);
        ip->daddr = htonl(TEST_DADDR);
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv6(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip6_hdr_t *ip6 = (ip6_hdr_t *) p;
    ip6->ver_tc_fl = g_htons(0x600d684a);
    ip6->pay_len = 0x28;
    ip6->next_hdr = next_ip_protocol;
    ip6->hop_limit = 0x40;
    if (reverse) {
        memcpy(ip6->saddr, test_ip6dst, 16);
        memcpy(ip6->daddr, test_ip6src, 16);
    } else {
        memcpy(ip6->saddr, test_ip6src, 16);
        memcpy(ip6->daddr, test_ip6dst, 16);
    }
    p += sizeof(ip6_hdr_t);
    return p;
}

static guint8 *build_hdr_sctp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    sctp_hdr_t *sctp_hdr = (sctp_hdr_t *) p;
    if (reverse) {
        sctp_hdr->source = TEST_DPORT;
        sctp_hdr->destination = TEST_SPORT;
    } else {
        sctp_hdr->source = TEST_SPORT;
        sctp_hdr->destination = TEST_DPORT;
    }
    sctp_hdr->ver_tag = 0x0;
    sctp_hdr->checksum = 0x1234;
    p += sizeof(sctp_hdr_t);
    return p;
}

static guint8 *build_hdr_fragment(guint8 * buffer, guint16 next_ip_protocol,
                                  gboolean more_frag_flag_set, guint16 offset, guint16 id)
{
    guint8 *p = buffer;
    frag_hdr_t *fragment_hdr = (frag_hdr_t *) p;
    fragment_hdr->next_hdr = next_ip_protocol;
    fragment_hdr->res = 0x0;
    if (more_frag_flag_set) {
        fragment_hdr->fo_res_mflag = GUINT16_TO_BE((offset << 3) + 1);
    } else {
        fragment_hdr->fo_res_mflag = GUINT16_TO_BE((offset << 3));
    }
    fragment_hdr->id = id;
    p += sizeof(frag_hdr_t);
    return p;
}

static guint8 *build_hdr_auth(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    auth_hdr_t *auth_hdr = (auth_hdr_t *) p;
    auth_hdr->next_hdr = next_ip_protocol;
    auth_hdr->payload_len = 4;
    auth_hdr->reserved;
    auth_hdr->spi_seq;
    auth_hdr->icv;
    p += (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
    return p;
}

static guint8 *build_hdr_ipv6_part(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) p;
    ipv6_part_hdr->next_hdr = next_ip_protocol;
    ipv6_part_hdr->hdr_ext_len = 4;
    p += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
    return p;
}

static guint8 *build_hdr_ipv6_ext(guint8 * buffer,
                                  guint ip_protocol,
                                  guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_IPV4:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_SCTP:
        p = build_hdr_sctp(p, reverse);
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        p = build_hdr_ipv6_part(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_FRAGMENT:
        p = build_hdr_fragment(p, next_ip_protocol, FALSE, 0x0, 0x0);
        break;
    case IP_PROTOCOL_AUTH:
        p = build_hdr_auth(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_ESP:
    case IP_PROTOCOL_NO_NEXT_HDR:
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_pppoe(guint8 * buffer, guint next_ip_protocol, guint16 ppp_proto,
                               gboolean reverse)
{
    guint8 *p = buffer;
    pppoe_sess_hdr_t *pppoe = (pppoe_sess_hdr_t *) p;
    pppoe->ver_type = 0x11;
    pppoe->code = 0x00;
    pppoe->session_id = 0x0001;
    pppoe->payload_length = 0x0032;
    pppoe->ppp_protocol_id = g_htons(ppp_proto);
    p += sizeof(pppoe_sess_hdr_t);
    switch (ppp_proto) {
    case PPP_PROTOCOL_IPV4:
    default:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case PPP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    }
    return p;
}

static guint8 *build_hdr_tcp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    tcp_hdr_t *tcp = (tcp_hdr_t *) p;
    if (reverse) {
        tcp->source = htons(TEST_DPORT);
        tcp->destination = htons(TEST_SPORT);
    } else {
        tcp->source = htons(TEST_SPORT);
        tcp->destination = htons(TEST_DPORT);
    }
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->flags = 0;
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;
    p += sizeof(tcp_hdr_t);
    return p;
}

static guint8 *build_hdr_tcp_detail(guint8 * buffer, guint16 sport, guint16 dport,
                                    guint16 flags)
{
    guint8 *p = buffer;
    tcp_hdr_t *tcp = (tcp_hdr_t *) p;
    tcp->source = GUINT16_FROM_BE(sport);
    tcp->destination = GUINT16_FROM_BE(dport);
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->flags = GUINT16_FROM_BE(flags);
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;
    p += sizeof(tcp_hdr_t);
    return p;
}

static guint8 *build_hdr_udp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    udp_hdr_t *udp = (udp_hdr_t *) p;
    if (reverse) {
        udp->source = htons(TEST_DPORT);
        udp->destination = htons(TEST_SPORT);
    } else {
        udp->source = htons(TEST_SPORT);
        udp->destination = htons(TEST_DPORT);
    }
    udp->length = 0x0020;
    udp->check = 0x0000;
    p += sizeof(udp_hdr_t);
    return p;
}

static guint8 *build_hdr_icmp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    icmp_hdr_t *icmp = (icmp_hdr_t *) p;
    icmp->type = 0x08;
    icmp->code = 0x00;;
    icmp->chksum = 0x4008;
    p += sizeof(icmp_hdr_t);
    return p;
}

static guint8 *build_hdr_gre(guint8 * buffer, guint16 protocol, gboolean reverse)
{
    guint8 *p = buffer;
    gre_hdr_t *gre = (gre_hdr_t *) p;
    gre->flags_version = 0;
    gre->protocol = GUINT16_TO_BE(protocol);
    p += sizeof(gre_hdr_t);
    return p;
}

static guint8 *build_hdr_after_ip(guint8 * buffer, guint ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_TCP:
        p = build_hdr_tcp(p, reverse);
        break;
    case IP_PROTOCOL_UDP:
        p = build_hdr_udp(p, reverse);
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMPV6:
        p = build_hdr_icmp(p, reverse);
        break;
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_ip(guint8 * buffer,
                            guint16 eth_protocol, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (eth_protocol) {
    case ETH_PROTOCOL_IP:
        p = build_hdr_ipv4(buffer, next_ip_protocol, reverse);
        break;
    case ETH_PROTOCOL_IPV6:
        p = build_hdr_ipv6(buffer, next_ip_protocol, reverse);
        break;
    default:
        return buffer;
    }

    return p;
}

static guint8 *build_hdr_ipv4_fragment(guint8 * buffer, guint next_ip_protocol,
                                       gboolean reverse, gboolean more_frag_flag_set,
                                       guint16 offset, guint16 id)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x45;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = id;
    if (more_frag_flag_set) {
        ip->frag_off = GUINT16_TO_BE(0x2000 + offset);
    } else {
        ip->frag_off = GUINT16_TO_BE(offset);
    }

    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = TEST_DADDR;
        ip->daddr = TEST_SADDR;
    } else {
        ip->saddr = TEST_SADDR;
        ip->daddr = TEST_DADDR;
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv6_fragment(guint8 * buffer, guint next_ip_protocol,
                                       gboolean reverse, gboolean more_frag_flag_set,
                                       guint16 offset, guint16 id)
{
    guint8 *p = build_hdr_ip(buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_FRAGMENT, FALSE);
    return build_hdr_fragment(p, next_ip_protocol, more_frag_flag_set, offset, id);
}

static guint8 *build_hdr_ip_fragment(guint8 * buffer,
                                     guint16 eth_protocol, guint next_ip_protocol,
                                     gboolean reverse, gboolean more_frag_flag_set,
                                     guint16 offset, guint16 id)
{
    guint8 *p = buffer;

    switch (eth_protocol) {
    case ETH_PROTOCOL_IP:
        p = build_hdr_ipv4_fragment(buffer, next_ip_protocol, reverse, more_frag_flag_set,
                                    offset, id);
        break;
    case ETH_PROTOCOL_IPV6:
        p = build_hdr_ipv6_fragment(buffer, next_ip_protocol, reverse, more_frag_flag_set,
                                    offset, id);
        break;
    default:
        return buffer;
    }

    return build_hdr_after_ip(p, next_ip_protocol, reverse);
}

static guint8 *build_pkt(guint8 * buffer,
                         guint16 eth_protocol, guint ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, reverse);
    return build_hdr_after_ip(p, ip_protocol, reverse);
}

static guint make_pkt(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_reverse(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, TRUE);
    return (guint) (p - buffer);
}

static guint make_pkt_pppoe(guint8 * buffer, guint ip_protocol, guint16 ppp_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_PPPOE_SESS);
    p = build_hdr_pppoe(p, ip_protocol, ppp_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan(guint8 * buffer,
                           guint16 eth_protocol,
                           guint16 vlan_protocol, guint ip_protocol, int count)
{
    guint8 *p = build_hdr_eth(buffer, vlan_protocol);
    p = build_hdr_vlan(p, vlan_protocol, eth_protocol, count);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan_Q_AD(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_8021Q);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021Q, ETH_PROTOCOL_8021AD, 1);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021AD, eth_protocol, 1);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_mpls(guint8 * buffer, guint32 label, guint16 eth_protocol,
                           guint ip_protocol, int count)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_MPLS_UC);
    while (count > 1) {
        *((guint32 *) p) = g_htonl(((label << 20) | 0xFF));
        p += sizeof(guint32);
        count--;
    };
    *((guint32 *) p) = g_htonl(((label << 20) | 0x1FF));
    p += sizeof(guint32);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_ipv6_ext(guint8 * buffer, guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_ip(buffer, ETH_PROTOCOL_IPV6, next_ip_protocol, FALSE);

    if (next_ip_protocol != IP_PROTOCOL_NO_NEXT_HDR) {
        if (next_ip_protocol == IP_PROTOCOL_IPV4) {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMP, reverse);
        } else {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMPV6, reverse);
        }
        p = build_hdr_after_ip(p, IP_PROTOCOL_ICMPV6, FALSE);
    }
    return (guint) (p - buffer);
}

static guint make_pkt_gre(guint8 * buffer, guint16 eth_protocol, guint16 gre_protocol,
                          guint ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, IP_PROTOCOL_GRE, FALSE);
    p = build_hdr_gre(p, gre_protocol, FALSE);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static void setup_test()
{
    test_tuple = calloc(1, sizeof(*test_tuple));
    memset(test_buffer, 0, MAX_BUFFER_SIZE);
}

void test_flow_parse_null_flow()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(NULL, test_buffer, 64, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_null_buffer()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(test_tuple, NULL, 64, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_0_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(test_tuple, test_buffer, 0, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_less_than_eth_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, sizeof(ethernet_hdr_t) - 1, 0, NULL, NULL, 0,
                     NULL, FALSE));
}

void test_flow_parse_udp()
{
    setup_test();

    GInetTuple *test = calloc(1, sizeof(GInetTuple));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(test, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(test, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(test, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(test, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
    free(test);
}

void test_flow_parse_tcp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_icmp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_pppoe()
{
    setup_test();

    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_vlan()
{
    setup_test();

    guint len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      1);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      2);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 1);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 2);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_vlan_Q_AD(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_mpls()
{
    guint len;
    setup_test();

    len = make_pkt_mpls(test_buffer, 0x1, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP, 1);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_mpls(test_buffer, 0x2, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP, 2);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_mpls(test_buffer, 0x3, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6, 1);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_mpls(test_buffer, 0x4, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6, 2);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_ipv6_ext()
{
    setup_test();

    guint len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HBH_OPT, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_DEST_OPT, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ROUTING, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_MOBILITY, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HIPV2, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SHIM6, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_FRAGMENT, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_AUTH, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, TRUE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV4, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV6, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ESP, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_NO_NEXT_HDR, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_gre()
{
    guint len;
    setup_test();

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, TRUE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_ICMP);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP,
                       ETH_PROTOCOL_PPPOE_SESS, IP_PROTOCOL_ICMP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, TRUE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6,
                       ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, TRUE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_ICMPV6);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6,
                       ETH_PROTOCOL_PPPOE_SESS, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, TRUE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);
}

void test_flow_parse_gre_no_tunnel_inspection()
{
    guint len;
    setup_test();

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6,
                       ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
    NP_ASSERT(g_inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);
}

void test_flow_parse_unsupported_eth_protocols()
{
    setup_test();

    /* ARP */
    guint len = make_pkt(test_buffer, 0x0806, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* AARP */
    len = make_pkt(test_buffer, 0x80F3, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* IPX */
    len = make_pkt(test_buffer, 0x8137, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* PPPoE Discovery */
    len = make_pkt(test_buffer, 0x8863, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_not_ipv6_ext()
{
    setup_test();

    /* KRYPTOLAN */
    guint len = make_pkt_ipv6_ext(test_buffer, 65, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));

    /* IGMP */
    len = make_pkt_ipv6_ext(test_buffer, 2, FALSE);
    NP_ASSERT(flow_parse_ipv6(test_tuple, test_buffer, len, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_unsupported_transport_protocols()
{
    setup_test();

    /* CRUDP */
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 127);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* UDPLite */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 136);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* IL */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, 40);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* IPv4 SCTP */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_SCTP);
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_unsupported_ppp_protocols()
{
    setup_test();

    /* IPCP */
    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8021);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* ATCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8029);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    /* IPXCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x802B);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_more_than_2_vlan_tags()
{
    setup_test();

    guint len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      3);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 3);
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_vlan_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_8021Q);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021Q, ETH_PROTOCOL_IP, 1);
    guint8 len = (guint) (p - test_buffer);

    /* No VLAN length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(vlan_hdr_t), 0, NULL, NULL, 0,
                     NULL, TRUE));
    /* Partial VLAN length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 1, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv4_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip(p, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No IPv4 length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(ip_hdr_t), 0, NULL, NULL, 0,
                     NULL, FALSE));
    /* Partial IPv4 length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 8, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv6_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No IPv6 length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(ip6_hdr_t), 0, NULL, NULL, 0,
                     NULL, FALSE));
    /* Partial IPv6 length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 8, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_pppoe_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_PPPOE_SESS);
    p = build_hdr_pppoe(p, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No PPPoE length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(pppoe_sess_hdr_t), 0, NULL,
                     NULL, 0, NULL, FALSE));
    /* Partial PPPoE length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 2, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_tcp_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No TCP length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(tcp_hdr_t), 0, NULL, NULL, 0,
                     NULL, TRUE));
    /* Partial TCP length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 4, 0, NULL, NULL, 0, NULL, TRUE));
}

void test_flow_parse_malformed_udp_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_UDP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No UDP length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - sizeof(udp_hdr_t), 0, NULL, NULL, 0,
                     NULL, FALSE));
    /* Partial UDP length */
    NP_ASSERT_FALSE(flow_parse
                    (test_tuple, test_buffer, len - 4, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_icmp_hdr_length()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);

    /* No ICMP length */
    NP_ASSERT(flow_parse
              (test_tuple, test_buffer, len - sizeof(icmp_hdr_t), 0, NULL, NULL, 0, NULL,
               FALSE));
    /* Partial ICMP length */
    NP_ASSERT(flow_parse(test_tuple, test_buffer, len - 4, 0, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_hbh_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_HBH_OPT, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_HBH_OPT, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No HBH header length ( (4 + 1) * 8) */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 40, NULL, NULL, 0, NULL, FALSE));
    /* Partial part HBH header length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 39, NULL, NULL, 0, NULL, FALSE));
    /* Partial full HBH length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 8, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_frag_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_FRAGMENT, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_FRAGMENT, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No Fragment header length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - sizeof(frag_hdr_t), NULL, NULL, 0,
                     NULL, FALSE));
    /* Partial Fragment length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 4, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_auth_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_AUTH, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_AUTH, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No Auth length ( (4 + 2) * 4) */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 24, NULL, NULL, 0, NULL, FALSE));
    /* Partial part Auth header length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 23, NULL, NULL, 0, NULL, FALSE));
    /* Partial full Auth length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 8, NULL, NULL, 0, NULL, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_sctp_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_SCTP, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_SCTP, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No SCTP length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, sizeof(sctp_hdr_t), NULL, NULL, 0, NULL,
                     FALSE));
    /* Partial SCTP length */
    NP_ASSERT_FALSE(flow_parse_ipv6
                    (test_tuple, test_buffer, len - 8, NULL, NULL, 0, NULL, FALSE));
}

gchar *num_to_string(guint8 * number, GSocketFamily family)
{
    char str[INET6_ADDRSTRLEN];
    if (inet_ntop(family, number, str, INET6_ADDRSTRLEN) == NULL) {
        return NULL;
    }
    return g_strdup(str);
}

void test_flow_properties()
{
    /* Original values converted to network byte order */
    guint saddr = htonl(TEST_SADDR);
    guint daddr = htonl(TEST_DADDR);

    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 packets;
    guint hash;
    guint protocol;
    guint lport;
    guint uport;
    guint server_port;
    gchar *lip;
    gchar *uip;
    gchar *sip;
    gchar *saddr_c = NULL;
    gchar *daddr_c = NULL;


    setup_test();

    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_object_get(flow, "packets", &packets, "hash", &hash, "protocol", &protocol, NULL);
    NP_ASSERT_EQUAL(packets, 2);
    NP_ASSERT(hash);
    NP_ASSERT_EQUAL(protocol, IP_PROTOCOL_TCP);

    g_object_get(flow, "lport", &lport, "uport", &uport, "serverport", &server_port, NULL);
    NP_ASSERT_EQUAL(lport, TEST_SPORT);
    NP_ASSERT_EQUAL(server_port, TEST_SPORT);
    NP_ASSERT_EQUAL(uport, TEST_DPORT);

    g_object_get(flow, "lip", &lip, "uip", &uip, "serverip", &sip, NULL);
    NP_ASSERT_NOT_NULL(lip);
    NP_ASSERT_NOT_NULL(uip);
    NP_ASSERT_NOT_NULL(sip);
    saddr_c = num_to_string((gchar *) & saddr, G_SOCKET_FAMILY_IPV4);
    daddr_c = num_to_string((gchar *) & daddr, G_SOCKET_FAMILY_IPV4);
    NP_ASSERT_STR_EQUAL(saddr_c, lip);
    NP_ASSERT_STR_EQUAL(saddr_c, sip);
    NP_ASSERT_STR_EQUAL(daddr_c, uip);

    g_free(saddr_c);
    g_free(daddr_c);
    g_free(lip);
    g_free(sip);
    g_free(uip);
    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_properties_reversed()
{
    /* Addresses in network order */
    guint saddr = htonl(TEST_SADDR);
    guint daddr = htonl(TEST_DADDR);

    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 packets;
    guint hash;
    guint protocol;
    guint lport;
    guint uport;
    guint server_port;
    gchar *lip;
    gchar *uip;
    gchar *sip;
    gchar *saddr_c = NULL;
    gchar *daddr_c = NULL;


    setup_test();

    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    /* Update flow */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_object_get(flow, "packets", &packets, "hash", &hash, "protocol", &protocol, NULL);
    NP_ASSERT_EQUAL(packets, 2);
    NP_ASSERT(hash);
    NP_ASSERT_EQUAL(protocol, IP_PROTOCOL_TCP);

    g_object_get(flow, "lport", &lport, "uport", &uport, "serverport", &server_port, NULL);
    NP_ASSERT_EQUAL(lport, TEST_SPORT);
    NP_ASSERT_EQUAL(server_port, TEST_SPORT);
    NP_ASSERT_EQUAL(uport, TEST_DPORT);

    g_object_get(flow, "lip", &lip, "uip", &uip, "serverip", &sip, NULL);
    NP_ASSERT_NOT_NULL(lip);
    NP_ASSERT_NOT_NULL(uip);
    NP_ASSERT_NOT_NULL(sip);
    saddr_c = num_to_string((gchar *) & saddr, G_SOCKET_FAMILY_IPV4);
    daddr_c = num_to_string((gchar *) & daddr, G_SOCKET_FAMILY_IPV4);
    NP_ASSERT_STR_EQUAL(saddr_c, lip);
    NP_ASSERT_STR_EQUAL(saddr_c, sip);
    NP_ASSERT_STR_EQUAL(daddr_c, uip);

    g_free(saddr_c);
    g_free(daddr_c);
    g_free(lip);
    g_free(sip);
    g_free(uip);
    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_properties_ipv6()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 packets;
    guint hash;
    guint protocol;
    guint lport;
    guint uport;
    guint server_port;
    gchar *lip;
    gchar *uip;
    gchar *sip;
    gchar *saddr_c = NULL;
    gchar *daddr_c = NULL;


    setup_test();

    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_object_get(flow, "packets", &packets, "hash", &hash, "protocol", &protocol, NULL);
    NP_ASSERT_EQUAL(packets, 2);
    NP_ASSERT(hash);
    NP_ASSERT_EQUAL(protocol, IP_PROTOCOL_TCP);

    g_object_get(flow, "lport", &lport, "uport", &uport, "serverport", &server_port, NULL);
    NP_ASSERT_EQUAL(lport, TEST_SPORT);
    NP_ASSERT_EQUAL(server_port, TEST_SPORT);
    NP_ASSERT_EQUAL(uport, TEST_DPORT);

    g_object_get(flow, "lip", &lip, "uip", &uip, "serverip", &sip, NULL);
    NP_ASSERT_NOT_NULL(lip);
    NP_ASSERT_NOT_NULL(uip);
    NP_ASSERT_NOT_NULL(sip);
    saddr_c = num_to_string(test_ip6src, G_SOCKET_FAMILY_IPV6);
    daddr_c = num_to_string(test_ip6dst, G_SOCKET_FAMILY_IPV6);
    NP_ASSERT_STR_EQUAL(saddr_c, lip);
    NP_ASSERT_STR_EQUAL(daddr_c, uip);
    NP_ASSERT_STR_EQUAL(saddr_c, sip);

    g_free(saddr_c);
    g_free(daddr_c);
    g_free(lip);
    g_free(sip);
    g_free(uip);
    g_object_unref(flow);
    g_object_unref(table);
}


void test_flow_properties_ipv6_reversed()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 packets;
    guint hash;
    guint protocol;
    guint lport;
    guint uport;
    guint server_port;
    gchar *lip;
    gchar *uip;
    gchar *sip;
    gchar *saddr_c = NULL;
    gchar *daddr_c = NULL;


    setup_test();

    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    /* Update flow */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_object_get(flow, "packets", &packets, "hash", &hash, "protocol", &protocol, NULL);
    NP_ASSERT_EQUAL(packets, 2);
    NP_ASSERT(hash);
    NP_ASSERT_EQUAL(protocol, IP_PROTOCOL_TCP);

    g_object_get(flow, "lport", &lport, "uport", &uport, "serverport", &server_port, NULL);
    NP_ASSERT_EQUAL(lport, TEST_SPORT);
    NP_ASSERT_EQUAL(server_port, TEST_SPORT);
    NP_ASSERT_EQUAL(uport, TEST_DPORT);

    g_object_get(flow, "lip", &lip, "uip", &uip, "serverip", &sip, NULL);
    NP_ASSERT_NOT_NULL(lip);
    NP_ASSERT_NOT_NULL(uip);
    NP_ASSERT_NOT_NULL(sip);
    saddr_c = num_to_string(test_ip6src, G_SOCKET_FAMILY_IPV6);
    daddr_c = num_to_string(test_ip6dst, G_SOCKET_FAMILY_IPV6);
    NP_ASSERT_STR_EQUAL(saddr_c, lip);
    NP_ASSERT_STR_EQUAL(daddr_c, uip);
    NP_ASSERT_STR_EQUAL(saddr_c, sip);

    g_free(saddr_c);
    g_free(daddr_c);
    g_free(lip);
    g_free(sip);
    g_free(uip);
    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_table_properties()
{
    GInetFlowTable *table;
    GInetFlow *flow1, *flow2;
    guint64 size;
    guint64 hits;
    guint64 misses;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow1 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_object_get(table, "size", &size, "hits", &hits, "misses", &misses, NULL);
    NP_ASSERT_EQUAL(size, 2);
    NP_ASSERT_EQUAL(hits, 1);
    NP_ASSERT_EQUAL(misses, 2);

    g_object_unref(flow1);
    g_object_unref(flow2);
    g_object_unref(table);
}

void flow_print_protocol(GInetFlow * flow)
{
    guint protocol;
    gchar *lip;

    NP_ASSERT_NOT_NULL(flow);
    g_object_get(flow, "protocol", &protocol, "lip", &lip, NULL);
    NP_ASSERT((protocol == IP_PROTOCOL_TCP) || (protocol == IP_PROTOCOL_UDP));
    NP_ASSERT_NOT_NULL(lip);

    g_free(lip);
}

void test_flow_foreach()
{
    GInetFlowTable *table;
    GInetFlow *flow1, *flow2;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow1 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    g_inet_flow_foreach(table, (GIFFunc) flow_print_protocol, NULL);

    g_object_unref(flow1);
    g_object_unref(flow2);
    g_object_unref(table);
}

void test_flow_create()
{
    GInetFlowTable *table = g_inet_flow_table_new();
    guint64 now = get_time_us();
    setup_test();
    NP_ASSERT_NOT_NULL(table);
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    GInetFlow *flow =
        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE, FALSE, NULL);
    NP_ASSERT_NOT_NULL(flow);
    guint64 size;
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(flow);
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

    guint pk1 = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    GInetFlow *flow1 =
        g_inet_flow_get_full(table, test_buffer, pk1, 0, get_time_us(), TRUE, TRUE, FALSE,
                             NULL);
    NP_ASSERT_NOT_NULL(flow1);

    guint pk2 = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    GInetFlow *flow2 =
        g_inet_flow_get_full(table, test_buffer, pk2, 0, get_time_us(), TRUE, TRUE, FALSE,
                             NULL);
    NP_ASSERT_NULL(flow2);

    g_object_unref(flow1);
    g_object_unref(table);
}

void test_flow_not_expired()
{
    guint64 now = get_time_us();
    guint64 later = now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000) - 1;
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL(table = g_inet_flow_table_new());
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE, FALSE, NULL);
    NP_ASSERT_NULL(g_inet_flow_expire(table, later));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_expired()
{
    guint64 now = get_time_us();
    guint64 later = now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE, FALSE, NULL);
    NP_ASSERT_NOT_NULL(g_inet_flow_expire(table, later));
    g_object_unref(flow);
    NP_ASSERT_NULL(g_inet_flow_expire(table, later));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);
    g_object_unref(table);
}

void test_flow_expired_no_unref()
{
    guint64 now = get_time_us();
    guint64 later = now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    GInetFlowTable *table;
    GInetFlow *flow;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE, FALSE, NULL);
    NP_ASSERT_NOT_NULL(g_inet_flow_expire(table, later));
    NP_ASSERT_NOT_NULL(g_inet_flow_expire(table, later));
    NP_ASSERT_NOT_NULL(g_inet_flow_expire(table, later));
    g_object_unref(flow);
    NP_ASSERT_NULL(g_inet_flow_expire(table, later));
    g_object_unref(table);
}

void test_flow_expired_only_once()
{
    guint64 now = get_time_us();
    guint64 later = now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    GInetFlowTable *table;
    GInetFlow *flow;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE, FALSE, NULL);
    while ((flow = g_inet_flow_expire(table, later))) {
        g_object_unref(flow);
    }
    g_object_unref(table);
}

void test_flow_tcp_new()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_tcp_update()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));

    /* Flow not updated */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow = g_inet_flow_get(table, test_buffer, len)));

    g_object_unref(flow);
    g_object_unref(table);
}

guint8 *build_pkt_tcp(guint8 * buffer,
                      guint16 eth_protocol,
                      guint ip_protocol,
                      gboolean reverse, guint16 sport, guint16 dport, guint16 flags)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, reverse);
    p = build_hdr_tcp_detail(p, sport, dport, flags);
    return p;
}

void test_flow_tcp_state_basic()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 1, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 2, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* Outgoing TCP FIN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, FIN_ACK);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 3, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_CLOSED);
    g_inet_flow_expire(table,
                       flow->timestamp + (G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_syn_rst()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 1, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_CLOSED);
    g_inet_flow_expire(table,
                       flow->timestamp + (G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_syn_synack_rst()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 1, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 2, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_CLOSED);
    g_inet_flow_expire(table,
                       flow->timestamp + (G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_fin_rst()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 1, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 2, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 3, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_CLOSED);
    g_inet_flow_expire(table,
                       flow->timestamp + (G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_syn_timeout()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);

    /* Set packet timestamp */
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_inet_flow_expire(table, now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_syn_synack_timeout()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);

    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    /* Set packet timestamp */
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);
    g_inet_flow_expire(table, now + (G_INET_FLOW_DEFAULT_OPEN_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_tcp_state_fin_timeout()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;
    guint64 size;
    guint64 ts;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE,
                      TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 1, TRUE, TRUE,
                                             FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    /* Set packet timestamp */
    NP_ASSERT_NOT_NULL((flow = g_inet_flow_get_full(table, test_buffer, len, 0,
                                                    now, TRUE, TRUE, FALSE, NULL)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_OPEN);

    g_inet_flow_expire(table, now + (G_INET_FLOW_DEFAULT_OPEN_TIMEOUT * 1000000));
    g_object_unref(flow);

    /* Always expect flow to expire when it is closed */
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);

    g_object_unref(table);
}

void test_flow_ipv4_encap()
{
    GInetFlowTable *table;
    GInetFlow *flow;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, FALSE,
                                             FALSE, NULL)));
    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_ipv6_encap()
{
    GInetFlow *flow;
    GInetFlowTable *table;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, FALSE,
                                             FALSE, NULL)));

    g_object_unref(flow);
    g_object_unref(table);
}

void test_flow_bad_ip_version()
{
    setup_test();

    guint8 *p = build_hdr_bad_ipv4(test_buffer, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    NP_ASSERT_FALSE(flow_parse_ip
                    (test_tuple, test_buffer, len, 0, NULL, NULL, 0, NULL, TRUE));
}

void test_flow_parse_ipv4_fragment()
{
    guint8 *p;
    GInetFlow *flow1, *flow2, *flow3;
    GInetFlowTable *table;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 0);

    /* First IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    guint8 len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow1 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    /* Second IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0xb9,
                              0xbeef);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(flow1 == flow2);
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    /* Last IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, FALSE, 0xb9,
                              0xbeef);
    NP_ASSERT_NOT_NULL((flow3 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(flow1 == flow3);
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 0);

    g_object_unref(flow1);
    g_object_unref(table);
}

void test_flow_parse_ipv6_fragment()
{
    guint8 *p;
    GInetFlow *flow1, *flow2, *flow3;
    GInetFlowTable *table;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 0);

    /* First IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, TRUE, 0,
                              0xbeef);
    guint8 len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow1 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    /* Second IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, TRUE, 0xb9,
                              0xbeef);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(flow1 == flow2);
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    /* Last IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, FALSE, 0xb9,
                              0xbeef);
    NP_ASSERT_NOT_NULL((flow3 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE, TRUE,
                                             FALSE, NULL)));
    NP_ASSERT(flow1 == flow3);
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 0);

    g_object_unref(flow1);
    g_object_unref(table);
}

void test_clear_expired_frag_info()
{
    guint8 *p;
    GInetFlow *flow1, *flow2, *flow3;
    GInetFlowTable *table;
    guint64 now = get_time_us();

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 0);

    /* IP fragment 1 - expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x1111);
    guint8 len = (guint) (p - test_buffer);
    NP_ASSERT_NOT_NULL((flow1 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now - 50 * 1000000,
                                             TRUE, TRUE, FALSE, NULL)));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    /* IP fragment 2 - expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x2222);
    NP_ASSERT_NOT_NULL((flow2 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now - 40 * 1000000,
                                             TRUE, TRUE, FALSE, NULL)));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 2);

    /* IP fragment 3 - not expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x3333);
    NP_ASSERT_NOT_NULL((flow3 =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now - 30 * 1000000,
                                             TRUE, TRUE, FALSE, NULL)));
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 3);

    NP_ASSERT(clear_expired_frag_info(table->frag_info_list, now) == 2);
    NP_ASSERT(g_list_length(table->frag_info_list->head) == 1);

    GInetFragment *non_expired = (g_list_first(table->frag_info_list->head))->data;
    NP_ASSERT(non_expired->id == 0x3333);

    /* Do proper clean up */
    clear_expired_frag_info(table->frag_info_list, now + 1000000);
    g_object_unref(flow1);
    g_object_unref(table);
}

void test_flow_expiry_queue()
{
    guint64 now = get_time_us();
    guint64 later = (now * 10) + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    guint64 timeout = now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);

    GInetFlowTable *table;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));

    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len1 = (guint) (p - test_buffer);

    GInetFlow *flow1 =
        g_inet_flow_get_full(table, test_buffer, len1, 0, now, TRUE, TRUE, FALSE, NULL);
    NP_ASSERT_NOT_NULL(flow1);

    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                      0x1238, 0x5678, SYN);
    guint len2 = (guint) (p - test_buffer);
    GInetFlow *flow2 =
        g_inet_flow_get_full(table, test_buffer, len2, 0, later, TRUE, TRUE, FALSE, NULL);

    NP_ASSERT_NOT_NULL(g_inet_flow_expire(table, timeout));
    g_object_unref(flow1);
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(flow2);
    g_object_unref(table);
}
