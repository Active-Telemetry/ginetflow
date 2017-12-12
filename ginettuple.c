/* GInetTuple - IP Tuple
 *
 * Copyright (C) Allied Telesis Labs NZ
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

#include "ginettuple.h"
#include <string.h>

void clear_cached(GInetTuple * tuple)
{
    tuple->hash = 0;
}

struct sockaddr_storage *g_inet_tuple_get_src(GInetTuple * tuple)
{
    return &tuple->src;
}

struct sockaddr_storage *g_inet_tuple_get_dst(GInetTuple * tuple)
{
    return &tuple->dst;
}

void g_inet_tuple_set_protocol(GInetTuple * tuple, guint16 protocol)
{
    tuple->protocol = protocol;
}

struct sockaddr_storage *g_inet_tuple_get_lower(GInetTuple * tuple)
{
    if (((struct sockaddr_in*)&tuple->src)->sin_port < ((struct sockaddr_in*)&tuple->dst)->sin_port)
        return &tuple->src;
    else
        return &tuple->dst;
}

struct sockaddr_storage *g_inet_tuple_get_upper(GInetTuple * tuple)
{
    if (((struct sockaddr_in*)&tuple->src)->sin_port >= ((struct sockaddr_in*)&tuple->dst)->sin_port)
        return &tuple->src;
    else
        return &tuple->dst;
}

struct sockaddr_storage *g_inet_tuple_get_server(GInetTuple * tuple)
{
    return g_inet_tuple_get_lower(tuple);
}

struct sockaddr_storage *g_inet_tuple_get_client(GInetTuple * tuple)
{
    return g_inet_tuple_get_upper(tuple);
}

guint16 g_inet_tuple_get_protocol(GInetTuple * tuple)
{
    return tuple->protocol;
}

static int sock_address_comparison(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (((struct sockaddr_in*)a)->sin_family != ((struct sockaddr_in*)a)->sin_family)
    {
        return 1;
    }

    if (((struct sockaddr_in*)a)->sin_family == AF_INET)
    {
        struct sockaddr_in *a_v4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b_v4 = (struct sockaddr_in *)b;
        return memcmp(&a_v4->sin_addr, &b_v4->sin_addr, sizeof(a_v4->sin_addr));
    }
    else
    {
        struct sockaddr_in6 *a_v6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b_v6 = (struct sockaddr_in6 *)b;
        return memcmp(&a_v6->sin6_addr, &b_v6->sin6_addr, sizeof(a_v6->sin6_addr));
    }
}

gboolean g_inet_tuple_equal(GInetTuple * a, GInetTuple * b)
{
    if (a->protocol != b->protocol) {
        return FALSE;
    }

    struct sockaddr_storage *lower_a = g_inet_tuple_get_lower(a);
    struct sockaddr_storage *upper_a = g_inet_tuple_get_upper(a);
    struct sockaddr_storage *lower_b = g_inet_tuple_get_lower(b);
    struct sockaddr_storage *upper_b = g_inet_tuple_get_upper(b);

    if (sock_address_comparison(lower_a, lower_b)) {
        return FALSE;
    }
    if (sock_address_comparison(upper_a, upper_b)) {
        return FALSE;
    }

    return TRUE;
}

guint g_inet_tuple_hash(GInetTuple * tuple)
{
    guint hash = 0;

    guint16 src_crc = 0xffff;
    guint16 dst_crc = 0xffff;
    guint16 prot_crc = 0xffff;

    if (tuple->hash)
    {
        return tuple->hash;
    }

    struct sockaddr_storage *lower = g_inet_tuple_get_lower(tuple);
    struct sockaddr_storage *upper = g_inet_tuple_get_upper(tuple);

    tuple->hash = ((struct sockaddr_in*)lower)->sin_port << 16 | ((struct sockaddr_in*)upper)->sin_port;

    return tuple->hash;
}
