/* GInetTuple - IP Tuple object
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
#ifndef __G_INET_TUPLE_H__
#define __G_INET_TUPLE_H__

#include <glib-object.h>
#include <glib.h>
#include <gio/gio.h>

#include <netinet/in.h>

typedef struct _GInetTuple {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    guint16 protocol;

    /* Internal use only */
    guint hash;
} GInetTuple;

struct sockaddr_storage *g_inet_tuple_get_src(GInetTuple * tuple);
struct sockaddr_storage *g_inet_tuple_get_dst(GInetTuple * tuple);
struct sockaddr_storage *g_inet_tuple_get_lower(GInetTuple * tuple);
struct sockaddr_storage *g_inet_tuple_get_upper(GInetTuple * tuple);
struct sockaddr_storage *g_inet_tuple_get_server(GInetTuple * tuple);
struct sockaddr_storage *g_inet_tuple_get_client(GInetTuple * tuple);
void g_inet_tuple_set_protocol(GInetTuple * tuple, guint16 protocol);
guint16 g_inet_tuple_get_protocol(GInetTuple * tuple);
gboolean g_inet_tuple_equal(GInetTuple * a, GInetTuple * b);
guint g_inet_tuple_hash(GInetTuple * t);


G_END_DECLS
#endif                          /* __G_INET_TUPLE_H__ */
