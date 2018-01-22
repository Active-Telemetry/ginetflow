/* GInetFragList - Lockable list for storing L3 fragments
 *
 * Copyright (C) 2018 Allied Telesis Ltd
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
#ifndef __G_INET_FRAG_LIST_H__
#define __G_INET_FRAG_LIST_H__

#include <glib.h>
#include <ginettuple.h>

typedef struct _GInetFragment {
    guint32 id;
    GInetTuple tuple;
    guint64 timestamp;
} GInetFragment;

typedef struct _GInetFragList {
    GRWLock lock;
    GList *head;
} GInetFragList;

GInetFragList *g_inet_frag_list_new();
void g_inet_frag_list_free(GInetFragList * finished);
gboolean g_inet_frag_list_update(GInetFragList * fragments, GInetFragment * entry,
                                 gboolean more_fragments);

#endif                          /* __G_INET_FRAG_LIST_H__ */
