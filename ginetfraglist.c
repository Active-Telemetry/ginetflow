/* GInetFlow - IP Fragmentation Manager
 *
 * Copyright (C) 2017 Allied Telesis Ltd
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
#include <gio/gio.h>

#include "ginettuple.h"
#include "ginetfraglist.h"

#include <netinet/in.h>

#define DEBUG(fmt, args...)
//#define DEBUG(fmt, args...) {g_printf("%s: ",__func__);g_printf (fmt, ## args);}

#define FRAG_EXPIRY_TIME    30
#define TIMESTAMP_RESOLUTION_US    1000000
#define MAX_FRAG_DEPTH      128

static inline guint64 get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * (guint64) TIMESTAMP_RESOLUTION_US + tv.tv_usec);
}

static int address_comparison(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (((struct sockaddr_in *) a)->sin_family != ((struct sockaddr_in *) a)->sin_family) {
        return 1;
    }

    if (((struct sockaddr_in *) a)->sin_family == AF_INET) {
        struct sockaddr_in *a_v4 = (struct sockaddr_in *) a;
        struct sockaddr_in *b_v4 = (struct sockaddr_in *) b;
        return memcmp(&a_v4->sin_addr, &b_v4->sin_addr, sizeof(a_v4->sin_addr));
    } else {
        struct sockaddr_in6 *a_v6 = (struct sockaddr_in6 *) a;
        struct sockaddr_in6 *b_v6 = (struct sockaddr_in6 *) b;
        return memcmp(&a_v6->sin6_addr, &b_v6->sin6_addr, sizeof(a_v6->sin6_addr));
    }
}

static int find_flow_by_frag_info(gconstpointer a, gconstpointer b)
{
    GInetFragment *entry = (GInetFragment *) a;
    GInetFragment *f = (GInetFragment *) b;

    if (entry->id != f->id) {
        return 1;
    }

    /* This is similar to g_inet_tuple_equal but ignores ports as they
     * are missing from the fragmented packet. */
    struct sockaddr_storage *lower_a = g_inet_tuple_get_lower(&entry->tuple);
    struct sockaddr_storage *upper_a = g_inet_tuple_get_upper(&entry->tuple);

    struct sockaddr_storage *src_b = g_inet_tuple_get_lower(&f->tuple);
    struct sockaddr_storage *dst_b = g_inet_tuple_get_upper(&f->tuple);

    if (address_comparison(lower_a, src_b) == 0 && address_comparison(upper_a, dst_b) == 0) {
        return 0;
    }
    if (address_comparison(lower_a, dst_b) == 0 && address_comparison(upper_a, src_b) == 0) {
        return 0;
    }
    return 1;
}

static gboolean frag_is_expired(GInetFragment * frag_info, guint64 timestamp)
{
    if (timestamp - frag_info->timestamp > FRAG_EXPIRY_TIME * TIMESTAMP_RESOLUTION_US)
        return TRUE;
    return FALSE;
}

static guint16 clear_expired_frag_info(GInetFragList * frag_info_list, guint64 timestamp)
{
    guint16 cleared = 0;
    GList *l = frag_info_list->head;
    while (l != NULL) {
        GList *next = l->next;
        if (frag_is_expired(l->data, timestamp)) {
            struct frag_info *frag_info = (struct frag_info *) (l->data);
            free(l->data);
            frag_info_list->head = g_list_delete_link(frag_info_list->head, l);
            cleared += 1;
        }
        l = next;
    }
    return cleared;
}

static gboolean store_frag_info(GInetFragList * fragments, GInetFragment * f, guint64 ts)
{
    uint64_t timestamp = ts ? : get_time();
    guint32 id = f->id;

    g_rw_lock_writer_lock(&fragments->lock);
    if (g_list_length(fragments->head) >= MAX_FRAG_DEPTH) {
        if (clear_expired_frag_info(fragments, timestamp) == 0) {
            DEBUG("Fragment tracking limit reached\n");
            g_rw_lock_writer_unlock(&fragments->lock);
            return FALSE;
        }
    }
    GInetFragment *entry = g_malloc0(sizeof(GInetFragment));
    entry->id = id;
    entry->tuple = f->tuple;
    entry->timestamp = timestamp;
    fragments->head = g_list_prepend(fragments->head, entry);
    g_rw_lock_writer_unlock(&fragments->lock);
    return TRUE;
}

gboolean g_inet_frag_list_update(GInetFragList * fragments, GInetFragment * entry,
                                 gboolean more_fragments)
{
    GList *match;

    /* If there are no more fragments, we need a write lock to remove the entry */
    (more_fragments ? g_rw_lock_reader_lock : g_rw_lock_writer_lock) (&fragments->lock);
    match = g_list_find_custom(fragments->head, entry, find_flow_by_frag_info);

    /* If we didn't find a match, store this fragment for later */
    if (!match) {
        (more_fragments ? g_rw_lock_reader_unlock : g_rw_lock_writer_unlock) (&fragments->
                                                                              lock);
        return store_frag_info(fragments, entry, entry->timestamp);
    }

    GInetFragment *found_flow = match->data;

    /* Match source port / address etc - could be either way around */
    if (found_flow->tuple.src.ss_family == AF_INET) {
        ((struct sockaddr_in *) &entry->tuple.src)->sin_port =
            ((struct sockaddr_in *) &found_flow->tuple.src)->sin_port;
        ((struct sockaddr_in *) &entry->tuple.dst)->sin_port =
            ((struct sockaddr_in *) &found_flow->tuple.dst)->sin_port;
    } else {
        ((struct sockaddr_in6 *) &entry->tuple.src)->sin6_port =
            ((struct sockaddr_in6 *) &found_flow->tuple.src)->sin6_port;
        ((struct sockaddr_in6 *) &entry->tuple.dst)->sin6_port =
            ((struct sockaddr_in6 *) &found_flow->tuple.dst)->sin6_port;
    }

    /* If this is the last IP fragment (MF is unset), clean up the list */
    if (!more_fragments) {
        fragments->head = g_list_remove_link(fragments->head, match);
        free(match->data);
        g_list_free(match);
    }
    (more_fragments ? g_rw_lock_reader_unlock : g_rw_lock_writer_unlock) (&fragments->lock);
    return TRUE;
}

void g_inet_frag_list_free(GInetFragList * finished)
{
    g_rw_lock_writer_lock(&finished->lock);
    g_rw_lock_clear(&finished->lock);
    free(finished);
}

GInetFragList *g_inet_frag_list_new()
{
    GInetFragList *new_list = calloc(1, sizeof(GInetFragList));
    g_rw_lock_init(&new_list->lock);
    return new_list;
}
