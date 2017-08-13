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
#ifndef __G_INET_FLOW_H__
#define __G_INET_FLOW_H__

#include <glib-object.h>

G_BEGIN_DECLS
#define G_INET_TYPE_FLOW            (g_inet_flow_get_type ())
typedef struct _GInetFlow GInetFlow;
typedef struct _GInetFlowClass GInetFlowClass;
#define G_INET_FLOW(o)              (G_TYPE_CHECK_INSTANCE_CAST ((o), G_INET_TYPE_FLOW, GInetFlow))

#define G_INET_TYPE_FLOW_TABLE      (g_inet_flow_table_get_type ())
typedef struct _GInetFlowTable GInetFlowTable;
typedef struct _GInetFlowTableClass GInetFlowTableClass;
#define G_INET_FLOW_TABLE(o)        (G_TYPE_CHECK_INSTANCE_CAST ((o), G_INET_TYPE_FLOW_TABLE, GInetFlowTable))

/* Flow states */
typedef enum {
    FLOW_NEW,
    FLOW_OPEN,
    FLOW_CLOSED,
} GInetFlowState;

/* Default timeouts */
#define G_INET_FLOW_DEFAULT_NEW_TIMEOUT         30
#define G_INET_FLOW_DEFAULT_OPEN_TIMEOUT        300
#define G_INET_FLOW_DEFAULT_CLOSED_TIMEOUT      0

GInetFlowTable *g_inet_flow_table_new(void);
GInetFlow *g_inet_flow_get(GInetFlowTable * table, const guint8 * frame, guint length);
GInetFlow *g_inet_flow_get_full(GInetFlowTable * table, const guint8 * frame,
                                guint length, guint16 hash, guint64 timestamp,
                                gboolean update);
GInetFlow *g_inet_flow_expire(GInetFlowTable * table, guint64 ts);

typedef void (*GIFFunc) (GInetFlow * flow, gpointer user_data);
void g_inet_flow_foreach(GInetFlowTable * table, GIFFunc func, gpointer user_data);
void g_inet_flow_table_max_set(GInetFlowTable * table, guint64 value);

G_END_DECLS
#endif                          /* __G_INET_FLOW_H__ */
