/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-object.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "nm-utils.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"
#include "nm-client.h"
#include "nm-core-internal.h"

static gboolean debug = FALSE;
#define dbgmsg(f,...) if (G_UNLIKELY (debug)) { g_message (f, ## __VA_ARGS__ ); }

static void nm_object_initable_iface_init (GInitableIface *iface);
static void nm_object_async_initable_iface_init (GAsyncInitableIface *iface);

typedef struct {
	NMObjectDecideTypeFunc type_func;
	char *interface;
	char *property;
} NMObjectTypeFuncData;

static GHashTable *type_funcs;

typedef struct {
	GSList *interfaces;
} NMObjectClassPrivate;

#define NM_OBJECT_CLASS_GET_PRIVATE(k) (G_TYPE_CLASS_GET_PRIVATE ((k), NM_TYPE_OBJECT, NMObjectClassPrivate))

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMObject, nm_object, G_TYPE_OBJECT,
                                  type_funcs = g_hash_table_new (NULL, NULL);
                                  g_type_add_class_private (g_define_type_id, sizeof (NMObjectClassPrivate));
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_object_initable_iface_init);
                                  G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_object_async_initable_iface_init);
                                  )

#define NM_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OBJECT, NMObjectPrivate))

typedef struct {
	PropertyMarshalFunc func;
	GType object_type;
	gpointer field;
	const char *signal_prefix;
} PropertyInfo;

static void reload_complete (NMObject *object, gboolean emit_now);
static gboolean demarshal_generic (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field);

typedef struct {
	GDBusObject *object;
	GDBusObjectManager *object_manager;

	GSList *property_tables;
	NMObject *parent;
	gboolean suppress_property_updates;

	gboolean inited;        /* async init finished? */
	GSList *waiters;        /* if async init did not finish, users of this object need
	                         * to defer their notifications by adding themselves here. */

	GSList *notify_items;
	guint32 notify_id;

	GSList *reload_results;
	guint reload_remaining;
	GError *reload_error;


	//ObjectCreatedData 
	GList *pending;
} NMObjectPrivate;

enum {
	PROP_0,
	PROP_PATH,
	PROP_DBUS_CONNECTION,
	PROP_NM_RUNNING,
	PROP_DBUS_OBJECT,
	PROP_DBUS_OBJECT_MANAGER,

	LAST_PROP
};

/**
 * _nm_object_class_add_interface:
 * @object_class: an #NMObjectClass
 * @interface: a D-Bus interface name
 *
 * Registers that @object_class implements @interface. A proxy for that
 * interface will automatically be created at construction time, and can
 * be retrieved with _nm_object_get_proxy().
 */
void
_nm_object_class_add_interface (NMObjectClass *object_class,
                                const char    *interface)
{
	NMObjectClassPrivate *cpriv;

	g_return_if_fail (NM_IS_OBJECT_CLASS (object_class));
	g_return_if_fail (interface);

	cpriv = NM_OBJECT_CLASS_GET_PRIVATE (object_class);

	g_return_if_fail (g_slist_find_custom (cpriv->interfaces, interface, (GCompareFunc) g_strcmp0) == NULL);

	cpriv->interfaces = g_slist_prepend (cpriv->interfaces, g_strdup (interface));
}

/**
 * nm_object_get_path:
 * @object: a #NMObject
 *
 * Gets the DBus path of the #NMObject.
 *
 * Returns: the object's path. This is the internal string used by the
 * object, and must not be modified.
 **/
const char *
nm_object_get_path (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return g_dbus_object_get_object_path (NM_OBJECT_GET_PRIVATE (object)->object);
}

/**
 * _nm_object_get_proxy:
 * @object: an #NMObject
 * @interface: a D-Bus interface implemented by @object
 *
 * Gets the D-Bus proxy for @interface on @object.
 *
 * Returns: (transfer none): a D-Bus proxy
 */
GDBusProxy *
_nm_object_get_proxy (NMObject   *object,
                      const char *interface)
{
	GDBusInterface *proxy;

	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	proxy = g_dbus_object_get_interface (NM_OBJECT_GET_PRIVATE (object)->object, interface);
	g_return_val_if_fail (proxy != NULL, NULL);

	return G_DBUS_PROXY (proxy);
}

typedef enum {
	NOTIFY_SIGNAL_PENDING_NONE,
	NOTIFY_SIGNAL_PENDING_ADDED,
	NOTIFY_SIGNAL_PENDING_REMOVED,
	NOTIFY_SIGNAL_PENDING_ADDED_REMOVED,
} NotifySignalPending;

typedef struct {
	const char *property;
	const char *signal_prefix;
	NotifySignalPending pending;
	NMObject *changed;
} NotifyItem;

static void
notify_item_free (NotifyItem *item)
{
	g_clear_object (&item->changed);
	g_slice_free (NotifyItem, item);
}

static gboolean
deferred_notify_cb (gpointer data)
{
	NMObject *object = NM_OBJECT (data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	NMObjectClass *object_class = NM_OBJECT_GET_CLASS (object);
	GSList *props, *iter;

	priv->notify_id = 0;

	/* Wait until all reloads are done before notifying */
	if (priv->reload_remaining)
		return G_SOURCE_REMOVE;

	/* Clear priv->notify_items early so that an NMObject subclass that
	 * listens to property changes can queue up other property changes
	 * during the g_object_notify() call separately from the property
	 * list we're iterating.
	 */
	props = g_slist_reverse (priv->notify_items);
	priv->notify_items = NULL;

	g_object_ref (object);

	/* Emit added/removed signals first since some of our internal objects
	 * use the added/removed signals for new object processing.
	 */
	for (iter = props; iter; iter = g_slist_next (iter)) {
		NotifyItem *item = iter->data;
		char buf[50];
		gint ret = 0;

		switch (item->pending) {
		case NOTIFY_SIGNAL_PENDING_ADDED:
			ret = g_snprintf (buf, sizeof (buf), "%s-added", item->signal_prefix);
			break;
		case NOTIFY_SIGNAL_PENDING_REMOVED:
			ret = g_snprintf (buf, sizeof (buf), "%s-removed", item->signal_prefix);
			break;
		case NOTIFY_SIGNAL_PENDING_ADDED_REMOVED:
			if (object_class->object_creation_failed)
				object_class->object_creation_failed (object, nm_object_get_path (item->changed));
			break;
		case NOTIFY_SIGNAL_PENDING_NONE:
		default:
			break;
		}
		if (ret > 0) {
			g_assert (ret < sizeof (buf));
			g_signal_emit_by_name (object, buf, item->changed);
		}
	}

	/* Emit property change notifications second */
	for (iter = props; iter; iter = g_slist_next (iter)) {
		NotifyItem *item = iter->data;

		if (item->property)
			g_object_notify (G_OBJECT (object), item->property);
	}

	g_object_unref (object);

	g_slist_free_full (props, (GDestroyNotify) notify_item_free);
	return G_SOURCE_REMOVE;
}

static void
_nm_object_defer_notify (NMObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (!priv->notify_id)
		priv->notify_id = g_idle_add_full (G_PRIORITY_LOW, deferred_notify_cb, object, NULL);
}

static void
_nm_object_queue_notify_full (NMObject *object,
                              const char *property,
                              const char *signal_prefix,
                              gboolean added,
                              NMObject *changed)
{
	NMObjectPrivate *priv;
	NotifyItem *item;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (!signal_prefix != !property);
	g_return_if_fail (!signal_prefix == !changed);

	priv = NM_OBJECT_GET_PRIVATE (object);
	_nm_object_defer_notify (object);

	property = g_intern_string (property);
	signal_prefix = g_intern_string (signal_prefix);
	for (iter = priv->notify_items; iter; iter = g_slist_next (iter)) {
		item = iter->data;

		if (property && (property == item->property))
			return;

		/* Collapse signals for the same object (such as "added->removed") to
		 * ensure we don't emit signals when their sum should have no effect.
		 * The "added->removed->removed" sequence requires special handling,
		 * hence the addition of the ADDED_REMOVED state to ensure that no
		 * signal is emitted in this case:
		 *
		 * Without the ADDED_REMOVED state:
		 *     NONE          + added   -> ADDED
		 *     ADDED         + removed -> NONE
		 *     NONE          + removed -> REMOVED (would emit 'removed' signal)
		 *
		 * With the ADDED_REMOVED state:
		 *     NONE | ADDED_REMOVED  + added   -> ADDED
		 *     ADDED                 + removed -> ADDED_REMOVED
		 *     ADDED_REMOVED         + removed -> ADDED_REMOVED (emits no signal)
		 */
		if (signal_prefix && (changed == item->changed) && (item->signal_prefix == signal_prefix)) {
			switch (item->pending) {
			case NOTIFY_SIGNAL_PENDING_ADDED:
				if (!added)
					item->pending = NOTIFY_SIGNAL_PENDING_ADDED_REMOVED;
				break;
			case NOTIFY_SIGNAL_PENDING_REMOVED:
				if (added)
					item->pending = NOTIFY_SIGNAL_PENDING_NONE;
				break;
			case NOTIFY_SIGNAL_PENDING_ADDED_REMOVED:
				if (added)
					item->pending = NOTIFY_SIGNAL_PENDING_ADDED;
				break;
			case NOTIFY_SIGNAL_PENDING_NONE:
				item->pending = added ? NOTIFY_SIGNAL_PENDING_ADDED : NOTIFY_SIGNAL_PENDING_REMOVED;
				break;
			default:
				g_assert_not_reached ();
			}
			return;
		}
	}

	item = g_slice_new0 (NotifyItem);
	item->property = property;
	if (signal_prefix) {
		item->signal_prefix = signal_prefix;
		item->pending = added ? NOTIFY_SIGNAL_PENDING_ADDED : NOTIFY_SIGNAL_PENDING_REMOVED;
		item->changed = changed ? g_object_ref (changed) : NULL;
	}
	priv->notify_items = g_slist_prepend (priv->notify_items, item);
}

void
_nm_object_queue_notify (NMObject *object, const char *property)
{
	_nm_object_queue_notify_full (object, property, NULL, FALSE, NULL);
}

void
_nm_object_register_type_func (GType base_type,
                               NMObjectDecideTypeFunc type_func,
                               const char *interface,
                               const char *property)
{
	NMObjectTypeFuncData *type_data;

	g_return_if_fail (type_func != NULL);
	g_return_if_fail (interface != NULL);
	g_return_if_fail (property != NULL);

	type_data = g_slice_new (NMObjectTypeFuncData);
	type_data->type_func = type_func;
	type_data->interface = g_strdup (interface);
	type_data->property = g_strdup (property);

	g_hash_table_insert (type_funcs,
	                     GSIZE_TO_POINTER (base_type),
	                     type_data);
}

typedef struct {
	NMObject *self;
	PropertyInfo *pi;

	GObject **objects;
	int length, remaining;

	gboolean array;
	const char *property_name;
} ObjectCreatedData;

static void
odata_free (gpointer data)
{
	ObjectCreatedData *odata = data;

	g_object_unref (odata->self);
	g_free (odata->objects);
	g_slice_free (ObjectCreatedData, odata);
}

static void object_property_maybe_complete (NMObject *self, gboolean emit_now);


typedef void (*NMObjectCreateCallbackFunc) (GObject *, const char *, gpointer);
typedef struct {
	char *path;
	NMObjectCreateCallbackFunc callback;
	gpointer user_data;
	NMObjectTypeFuncData *type_data;
	GDBusConnection *connection;
} NMObjectTypeAsyncData;

/* Stolen from dbus-glib */
static char*
wincaps_to_dash (const char *caps)
{
	const char *p;
	GString *str;

	str = g_string_new (NULL);
	p = caps;
	while (*p) {
		if (g_ascii_isupper (*p)) {
			if (str->len > 0 && (str->len < 2 || str->str[str->len-2] != '-'))
				g_string_append_c (str, '-');
			g_string_append_c (str, g_ascii_tolower (*p));
		} else
			g_string_append_c (str, *p);
		++p;
	}

	return g_string_free (str, FALSE);
}

/* Adds object to array if it's not already there */
static void
add_to_object_array_unique (GPtrArray *array, GObject *obj)
{
	guint i;

	g_return_if_fail (array != NULL);

	if (obj != NULL) {
		for (i = 0; i < array->len; i++) {
			if (g_ptr_array_index (array, i) == obj) {
				g_object_unref (obj);
				return;
			}
		}
		g_ptr_array_add (array, obj);
	}
}

/* Places items from 'needles' that are not in 'haystack' into 'diff' */
static void
array_diff (GPtrArray *needles, GPtrArray *haystack, GPtrArray *diff)
{
	guint i, j;
	GObject *obj;

	g_assert (needles);
	g_assert (haystack);
	g_assert (diff);

	for (i = 0; i < needles->len; i++) {
		obj = g_ptr_array_index (needles, i);

		for (j = 0; j < haystack->len; j++) {
			if (g_ptr_array_index (haystack, j) == obj)
				break;
		}

		if (j == haystack->len)
			g_ptr_array_add (diff, obj);
	}
}

static void
queue_added_removed_signal (NMObject *self,
                            const char *signal_prefix,
                            NMObject *changed,
                            gboolean added)
{
	_nm_object_queue_notify_full (self, NULL, signal_prefix, added, changed);
}

static gboolean
already_awaits (ObjectCreatedData *odata, GObject *object)
{
	NMObject *self = odata->self;
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GSList *iter;

	if ((GObject *)odata->self == object)
		return TRUE;

	for (iter = priv->waiters; iter; iter = g_slist_next (iter)) {
		if (already_awaits (iter->data, object))
			return TRUE;
	}

	return FALSE;
}

static void
object_property_maybe_complete (NMObject *self, gboolean emit_now)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GList *this;
	int i;

	while ((this = g_list_first (priv->pending))) {
		ObjectCreatedData *odata = this->data;
		PropertyInfo *pi = odata->pi;
		gboolean different = TRUE;

		/* Only complete the array property load when all the objects are initialized. */
		for (i = 0; i < odata->length; i++) {
			GObject *obj = odata->objects[i];
			NMObjectPrivate *obj_priv;

			/* Could not load the object. Perhaps it was removed. */
			if (!obj)
				continue;

			obj_priv = NM_OBJECT_GET_PRIVATE (obj);
			if (!obj_priv->inited) {

				/* The object is not finished because we block its creation. */
				if (already_awaits (odata, obj))
					continue;

				if (!g_slist_find (obj_priv->waiters, odata))
					obj_priv->waiters = g_slist_prepend (obj_priv->waiters, odata);
				return;
			}
		}

		if (odata->array) {
			GPtrArray *old = *((GPtrArray **) pi->field);
			GPtrArray *new;

			/* Build up new array */
			new = g_ptr_array_new_full (odata->length, g_object_unref);
			for (i = 0; i < odata->length; i++) {
				add_to_object_array_unique (new, odata->objects[i]);
			}

			*((GPtrArray **) pi->field) = new;

			if (pi->signal_prefix) {
				GPtrArray *added = g_ptr_array_sized_new (3);
				GPtrArray *removed = g_ptr_array_sized_new (3);

				if (old) {
					/* Find objects in 'old' that do not exist in 'new' */
					array_diff (old, new, removed);

					/* Find objects in 'new' that do not exist in old */
					array_diff (new, old, added);
				} else {
					for (i = 0; i < new->len; i++)
						g_ptr_array_add (added, g_ptr_array_index (new, i));
				}

				/* Emit added & removed */
				for (i = 0; i < removed->len; i++) {
					queue_added_removed_signal (self,
								    pi->signal_prefix,
								    g_ptr_array_index (removed, i),
								    FALSE);
				}

				for (i = 0; i < added->len; i++) {
					queue_added_removed_signal (self,
								    pi->signal_prefix,
								    g_ptr_array_index (added, i),
								    TRUE);
				}

				different = removed->len || added->len;
				g_ptr_array_unref (added);
				g_ptr_array_unref (removed);
			} else {
				/* No added/removed signals to send, just replace the property with
				 * the new values.
				 */
				different = TRUE;
			}

			/* Free old array last since it will release references, thus freeing
			 * any objects in the 'removed' array.
			 */
			if (old)
				g_ptr_array_unref (old);
		} else {
			GObject **obj_p = pi->field;

			different = (*obj_p != odata->objects[0]);
			if (*obj_p)
				g_object_unref (*obj_p);
			*obj_p = odata->objects[0];
		}

		if (different && odata->property_name)
			_nm_object_queue_notify (self, odata->property_name);

		if (--priv->reload_remaining == 0)
			reload_complete (self, TRUE);

		priv->pending = g_list_delete_link (priv->pending, this);
		odata_free (odata);
	}
}

static void
object_created (GObject *obj, const char *path, gpointer user_data)
{
	ObjectCreatedData *odata = user_data;

	/* We assume that on error, the creator_func printed something */

	if (obj == NULL && g_strcmp0 (path, "/") != 0 ) {
		NMObjectClass *object_class = NM_OBJECT_GET_CLASS (odata->self);

		if (object_class->object_creation_failed)
			object_class->object_creation_failed (odata->self, path);
	}

	odata->objects[--odata->remaining] = obj ? g_object_ref (obj) : NULL;
	if (!odata->remaining)
		object_property_maybe_complete (odata->self, FALSE);
}

static gboolean
handle_object_property (NMObject *self, const char *property_name, GVariant *value,
                        PropertyInfo *pi)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GDBusObject *object;
	GObject *obj;
	const char *path;
	ObjectCreatedData *odata;

	odata = g_slice_new (ObjectCreatedData);
	odata->self = g_object_ref (self);
	odata->pi = pi;
	odata->objects = g_new (GObject *, 1);
	odata->length = odata->remaining = 1;
	odata->array = FALSE;
	odata->property_name = property_name;

	priv->pending = g_list_append (priv->pending, odata);
	priv->reload_remaining++;

	path = g_variant_get_string (value, NULL);

	if (!strcmp (path, "/")) {
		object_created (NULL, path, odata);
		return TRUE;
	}

	object = g_dbus_object_manager_get_object (priv->object_manager, path);
	if (!object) {
		g_warning ("no object known for %s\n", path);
		return FALSE;
	}

	obj = g_object_get_data (G_OBJECT (object), "nm-object");
	object_created (obj, path, odata);
	g_object_unref (object);

	return FALSE;
}

static gboolean
handle_object_array_property (NMObject *self, const char *property_name, GVariant *value,
                              PropertyInfo *pi)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GDBusObject *object;
	GObject *obj;
	GVariantIter iter;
	gsize npaths;
	GPtrArray **array = pi->field;
	const char *path;
	ObjectCreatedData *odata;

	npaths = g_variant_n_children (value);

	odata = g_slice_new (ObjectCreatedData);
	odata->self = g_object_ref (self);
	odata->pi = pi;
	odata->objects = g_new0 (GObject *, npaths);
	odata->length = odata->remaining = npaths;
	odata->array = TRUE;
	odata->property_name = property_name;

	priv->pending = g_list_append (priv->pending, odata);
	priv->reload_remaining++;

	if (npaths == 0) {
		object_property_maybe_complete (self, FALSE);
		return TRUE;
	}

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "&o", &path)) {
		if (!strcmp (path, "/")) {
			/* FIXME: can't happen? */
			continue;
		}

		object = g_dbus_object_manager_get_object (priv->object_manager, path);
		if (!object) {
			g_warning ("no object known for %s\n", path);
			return FALSE;
		}

		obj = g_object_get_data (G_OBJECT (object), "nm-object");
		object_created (obj, path, odata);
		g_object_unref (object);
	}

	return *array && ((*array)->len == npaths);
}

static void
handle_property_changed (NMObject *self, const char *dbus_name, GVariant *value)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	char *prop_name;
	PropertyInfo *pi;
	GParamSpec *pspec;
	gboolean success = FALSE, found = FALSE;
	GSList *iter;

	prop_name = wincaps_to_dash (dbus_name);

	/* Iterate through the object and its parents to find the property */
	for (iter = priv->property_tables; iter; iter = g_slist_next (iter)) {
		pi = g_hash_table_lookup ((GHashTable *) iter->data, prop_name);
		if (pi) {
			if (!pi->field) {
				/* We know about this property but aren't tracking changes on it. */
				goto out;
			}

			found = TRUE;
			break;
		}
	}

	if (!found) {
		dbgmsg ("Property '%s' unhandled.", prop_name);
		goto out;
	}

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (self)), prop_name);
	if (!pspec && pi->func == demarshal_generic) {
		dbgmsg ("%s: property '%s' changed but wasn't defined by object type %s.",
		        __func__,
		        prop_name,
		        G_OBJECT_TYPE_NAME (self));
		goto out;
	}

	if (G_UNLIKELY (debug)) {
		char *s;
		s = g_variant_print (value, FALSE);
		dbgmsg ("PC: (%p) %s:%s => '%s' (%s%s%s)",
		        self, G_OBJECT_TYPE_NAME (self),
		        prop_name,
		        s,
		        g_variant_get_type_string (value),
		        pi->object_type ? " / " : "",
		        pi->object_type ? g_type_name (pi->object_type) : "");
		g_free (s);
	}

	if (pspec && pi->object_type) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_OBJECT_PATH))
			success = handle_object_property (self, pspec->name, value, pi);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE ("ao")))
			success = handle_object_array_property (self, pspec->name, value, pi);
		else {
			g_warn_if_reached ();
			goto out;
		}
	} else
		success = (*(pi->func)) (self, pspec, value, pi->field);

	if (!success) {
		dbgmsg ("%s: failed to update property '%s' of object type %s.",
		        __func__,
		        prop_name,
		        G_OBJECT_TYPE_NAME (self));
	}

out:
	g_free (prop_name);
}

static void
properties_changed (GDBusProxy *proxy,
                    GVariant   *changed_properties,
                    GStrv       invalidated_properties,
                    gpointer    user_data)
{
	NMObject *self = NM_OBJECT (user_data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	GVariantIter iter;
	const char *name;
	GVariant *value;

	if (priv->suppress_property_updates)
		return;

	g_variant_iter_init (&iter, changed_properties);
	while (g_variant_iter_next (&iter, "{&sv}", &name, &value)) {
		handle_property_changed (self, name, value);
		g_variant_unref (value);
	}
}

#define HANDLE_TYPE(vtype, ctype, getter) \
	G_STMT_START { \
		if (g_variant_is_of_type (value, vtype)) { \
			ctype *param = (ctype *) field; \
			ctype newval = getter (value); \
			different = *param != newval; \
			*param = newval; \
		} else { \
			success = FALSE; \
			goto done; \
		} \
	} G_STMT_END

static gboolean
demarshal_generic (NMObject *object,
                   GParamSpec *pspec,
                   GVariant *value,
                   gpointer field)
{
	gboolean success = TRUE;
	gboolean different = FALSE;

	if (pspec->value_type == G_TYPE_STRING) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING)) {
			char **param = (char **) field;
			const char *newval = g_variant_get_string (value, NULL);

			different = !!g_strcmp0 (*param, newval);
			if (different) {
				g_free (*param);
				*param = g_strdup (newval);
			}
		} else if (g_variant_is_of_type (value, G_VARIANT_TYPE_OBJECT_PATH)) {
			char **param = (char **) field;
			const char *newval = g_variant_get_string (value, NULL);

			/* Handle "NULL" object paths */
			if (g_strcmp0 (newval, "/") == 0)
				newval = NULL;
			different = !!g_strcmp0 (*param, newval);
			if (different) {
				g_free (*param);
				*param = g_strdup (newval);
			}
		} else {
			success = FALSE;
			goto done;
		}
	} else if (pspec->value_type == G_TYPE_STRV) {
		char ***param = (char ***)field;
		const char **newval;
		gsize i;

		newval = g_variant_get_strv (value, NULL);
		if (!*param)
			different = TRUE;
		else {
			if (!_nm_utils_strv_equal ((char **) newval, *param)) {
				different = TRUE;
				g_strfreev (*param);
			}
		}
		if (different) {
			for (i = 0; newval[i]; i++)
				newval[i] = g_strdup (newval[i]);
			*param = (char **) newval;
		} else
			g_free (newval);
	} else if (pspec->value_type == G_TYPE_BYTES) {
		GBytes **param = (GBytes **)field;
		gconstpointer val, old_val = NULL;
		gsize length, old_length = 0;

		val = g_variant_get_fixed_array (value, &length, 1);

		if (*param)
			old_val = g_bytes_get_data (*param, &old_length);
		different =    old_length != length
		            || (   length > 0
		                && memcmp (old_val, val, length) != 0);
		if (different) {
			if (*param)
				g_bytes_unref (*param);
			*param = length > 0 ? g_bytes_new (val, length) : NULL;
		}
	} else if (G_IS_PARAM_SPEC_ENUM (pspec)) {
		int *param = (int *) field;
		int newval = 0;

		if (g_variant_is_of_type (value, G_VARIANT_TYPE_INT32))
			newval = g_variant_get_int32 (value);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE_UINT32))
			newval = g_variant_get_uint32 (value);
		else {
			success = FALSE;
			goto done;
		}
		different = *param != newval;
		*param = newval;
	} else if (G_IS_PARAM_SPEC_FLAGS (pspec)) {
		guint *param = (guint *) field;
		guint newval = 0;

		if (g_variant_is_of_type (value, G_VARIANT_TYPE_INT32))
			newval = g_variant_get_int32 (value);
		else if (g_variant_is_of_type (value, G_VARIANT_TYPE_UINT32))
			newval = g_variant_get_uint32 (value);
		else {
			success = FALSE;
			goto done;
		}
		different = *param != newval;
		*param = newval;
	} else if (pspec->value_type == G_TYPE_BOOLEAN)
		HANDLE_TYPE (G_VARIANT_TYPE_BOOLEAN, gboolean, g_variant_get_boolean);
	else if (pspec->value_type == G_TYPE_UCHAR)
		HANDLE_TYPE (G_VARIANT_TYPE_BYTE, guchar, g_variant_get_byte);
	else if (pspec->value_type == G_TYPE_DOUBLE) {
		NM_PRAGMA_WARNING_DISABLE("-Wfloat-equal")
		HANDLE_TYPE (G_VARIANT_TYPE_DOUBLE, gdouble, g_variant_get_double);
		NM_PRAGMA_WARNING_REENABLE
	} else if (pspec->value_type == G_TYPE_INT)
		HANDLE_TYPE (G_VARIANT_TYPE_INT32, gint, g_variant_get_int32);
	else if (pspec->value_type == G_TYPE_UINT)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT32, guint, g_variant_get_uint32);
	else if (pspec->value_type == G_TYPE_INT64)
		HANDLE_TYPE (G_VARIANT_TYPE_INT64, gint, g_variant_get_int64);
	else if (pspec->value_type == G_TYPE_UINT64)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT64, guint, g_variant_get_uint64);
	else if (pspec->value_type == G_TYPE_LONG)
		HANDLE_TYPE (G_VARIANT_TYPE_INT64, glong, g_variant_get_int64);
	else if (pspec->value_type == G_TYPE_ULONG)
		HANDLE_TYPE (G_VARIANT_TYPE_UINT64, gulong, g_variant_get_uint64);
	else {
		g_warning ("%s: %s:%s unhandled type %s.",
		           __func__,
		           G_OBJECT_TYPE_NAME (object),
		           pspec->name,
		           g_type_name (pspec->value_type));
		success = FALSE;
	}

done:
	if (success) {
		if (different)
			_nm_object_queue_notify (object, pspec->name);
	} else {
		dbgmsg ("%s: %s:%s (type %s) couldn't be set from D-Bus type %s.",
		        __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		        g_type_name (pspec->value_type), g_variant_get_type_string (value));
	}
	return success;
}

void
_nm_object_register_properties (NMObject *object,
                                const char *interface,
                                const NMPropertiesInfo *info)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GDBusProxy *proxy;
	static gsize dval = 0;
	const char *debugstr;
	NMPropertiesInfo *tmp;
	GHashTable *instance;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (info != NULL);

	if (g_once_init_enter (&dval)) {
		debugstr = getenv ("LIBNM_GLIB_DEBUG");
		if (debugstr && strstr (debugstr, "properties-changed"))
			debug = TRUE;
		g_once_init_leave (&dval, 1);
	}

	proxy = _nm_object_get_proxy (object, interface);
	g_signal_connect (proxy, "g-properties-changed",
		          G_CALLBACK (properties_changed), object);

	instance = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->property_tables = g_slist_prepend (priv->property_tables, instance);

	for (tmp = (NMPropertiesInfo *) info; tmp->name; tmp++) {
		PropertyInfo *pi;

		if (!tmp->name || (tmp->func && !tmp->field)) {
			g_warning ("%s: missing field in NMPropertiesInfo", __func__);
			continue;
		}

		pi = g_malloc0 (sizeof (PropertyInfo));
		pi->func = tmp->func ? tmp->func : demarshal_generic;
		pi->object_type = tmp->object_type;
		pi->field = tmp->field;
		pi->signal_prefix = tmp->signal_prefix;
		g_hash_table_insert (instance, g_strdup (tmp->name), pi);
	}
}

void
_nm_object_suppress_property_updates (NMObject *object, gboolean suppress)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	priv->suppress_property_updates = suppress;
}

void
_nm_object_set_property (NMObject *object,
                         const char *interface,
                         const char *prop_name,
                         const char *format_string,
                         ...)
{
	GVariant *val, *ret;
	va_list ap;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);
	g_return_if_fail (format_string != NULL);

	va_start (ap, format_string);
	val = g_variant_new_va (format_string, NULL, &ap);
	va_end (ap);
	g_return_if_fail (val != NULL);

	ret = g_dbus_proxy_call_sync (_nm_object_get_proxy (object, interface),
	                              DBUS_INTERFACE_PROPERTIES ".Set",
	                              g_variant_new ("(ssv)", interface, prop_name, val),
	                              G_DBUS_CALL_FLAGS_NONE, 2000,
	                              NULL, NULL);
	/* Ignore errors. */
	if (ret)
		g_variant_unref (ret);
}

static void
reload_complete (NMObject *object, gboolean emit_now)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSimpleAsyncResult *simple;
	GSList *results, *iter;
	GError *error;

	if (emit_now) {
		nm_clear_g_source (&priv->notify_id);
		deferred_notify_cb (object);
	} else
		_nm_object_defer_notify (object);

	results = priv->reload_results;
	priv->reload_results = NULL;
	error = priv->reload_error;
	priv->reload_error = NULL;

	for (iter = results; iter; iter = iter->next) {
		simple = iter->data;

		if (error)
			g_simple_async_result_set_from_error (simple, error);
		else
			g_simple_async_result_set_op_res_gboolean (simple, TRUE);

		g_simple_async_result_complete (simple);
		g_object_unref (simple);
	}
	g_slist_free (results);
	g_clear_error (&error);
}

/**************************************************************/

static void
init_dbus (NMObject *object)
{
}

static void
init_if (GDBusInterface *interface, gpointer user_data)
{
	NMObject *self = NM_OBJECT (user_data);
	GDBusProxy *proxy = G_DBUS_PROXY (interface);
	gchar **props;
	char **prop;
	GVariant *val;
	gchar *str;

	props = g_dbus_proxy_get_cached_property_names (proxy);

	for (prop = props; *prop; prop++) {
                val = g_dbus_proxy_get_cached_property (proxy, *prop);
                str = g_variant_print (val, TRUE);
		handle_property_changed (self, *prop, val);
                g_variant_unref (val);
                g_free (str);
	}

	g_strfreev (props);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMObject *self = NM_OBJECT (initable);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
        GList *interfaces;

	g_assert (priv->object && priv->object_manager);
	
	NM_OBJECT_GET_CLASS (self)->init_dbus (self);

	priv->reload_remaining++;

	interfaces = g_dbus_object_get_interfaces (priv->object);
	g_list_foreach (interfaces, (GFunc) init_if, self);
	g_list_free_full (interfaces, g_object_unref);

	priv->inited = TRUE;

	if (--priv->reload_remaining == 0)
		reload_complete (self, TRUE);

	/* There are some object properties whose creation couldn't proceed
	 * because it depended on this object. */
	while (priv->waiters) {
		ObjectCreatedData *odata = priv->waiters->data;

		priv->waiters = g_slist_remove (priv->waiters, odata);
		object_property_maybe_complete (self, TRUE);
	}

	return TRUE;
}

/**************************************************************/

typedef struct {
	NMObject *object;
	GSimpleAsyncResult *simple;
	GCancellable *cancellable;
	int proxies_pending;
	GError *error;
} NMObjectInitData;

static void
init_async_complete (NMObjectInitData *init_data)
{
	if (init_data->error)
		g_simple_async_result_take_error (init_data->simple, init_data->error);
	else
		g_simple_async_result_set_op_res_gboolean (init_data->simple, TRUE);
	g_simple_async_result_complete_in_idle (init_data->simple);
	g_object_unref (init_data->simple);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMObjectInitData, init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMObject *self = NM_OBJECT (initable);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	NMObjectInitData *init_data;
        GList *interfaces;

	g_assert (priv->object && priv->object_manager);

	NM_OBJECT_GET_CLASS (self)->init_dbus (self);

	init_data = g_slice_new0 (NMObjectInitData);
	init_data->object = self;
	init_data->simple = g_simple_async_result_new (G_OBJECT (initable), callback, user_data, init_async);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

        interfaces = g_dbus_object_get_interfaces (priv->object);
        g_list_foreach (interfaces, (GFunc) init_if, self);
        g_list_free_full (interfaces, g_object_unref);

	init_async_complete (init_data);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (initable);

	priv->inited = TRUE;

	/* There are some object properties whose creation couldn't proceed
	 * because it depended on this object. */
	while (priv->waiters) {
		ObjectCreatedData *odata = priv->waiters->data;

		priv->waiters = g_slist_remove (priv->waiters, odata);
		object_property_maybe_complete (odata->self, FALSE);
	}

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
}

/**************************************************************/

static void
nm_object_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_object_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}

static void
nm_object_init (NMObject *object)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* Construct only */
		//priv->path = g_value_dup_string (value);
		break;
	case PROP_DBUS_CONNECTION:
		/* Construct only */
		//priv->connection = g_value_dup_object (value);
		break;
	case PROP_DBUS_OBJECT:
		/* Construct only */
		priv->object = g_value_dup_object (value);
		break;
	case PROP_DBUS_OBJECT_MANAGER:
		/* Construct only */
		priv->object_manager = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, nm_object_get_path (NM_OBJECT (object)));
		break;
	case PROP_DBUS_CONNECTION:
		g_value_set_object (value, g_dbus_object_manager_client_get_connection (G_DBUS_OBJECT_MANAGER_CLIENT (priv->object_manager)));
		break;
	case PROP_DBUS_OBJECT:
		g_value_set_object (value, priv->object);
		break;
	case PROP_DBUS_OBJECT_MANAGER:
		g_value_set_object (value, priv->object_manager);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	nm_clear_g_source (&priv->notify_id);

	g_slist_free_full (priv->notify_items, (GDestroyNotify) notify_item_free);
	priv->notify_items = NULL;

	g_slist_free_full (priv->waiters, odata_free);

	g_clear_object (&priv->object);
	g_clear_object (&priv->object_manager);

	G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	g_slist_free_full (priv->property_tables, (GDestroyNotify) g_hash_table_destroy);

	G_OBJECT_CLASS (nm_object_parent_class)->finalize (object);
}

static void
nm_object_class_init (NMObjectClass *nm_object_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nm_object_class);

	g_type_class_add_private (nm_object_class, sizeof (NMObjectPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* Properties */

	/**
	 * NMObject:path:
	 *
	 * The D-Bus object path.
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_OBJECT_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:dbus-connection: (skip)
	 *
	 * The #GDBusConnection of the object.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DBUS_CONNECTION,
	     g_param_spec_object (NM_OBJECT_DBUS_CONNECTION, "", "",
	                          G_TYPE_DBUS_CONNECTION,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:dbus-object: (skip)
	 *
	 * The #GDBusObject of the object.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DBUS_OBJECT,
	     g_param_spec_object (NM_OBJECT_DBUS_OBJECT, "", "",
	                          G_TYPE_DBUS_OBJECT,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMObject:dbus-object: (skip)
	 *
	 * The #GDBusObject of the object.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DBUS_OBJECT_MANAGER,
	     g_param_spec_object (NM_OBJECT_DBUS_OBJECT_MANAGER, "", "",
	                          G_TYPE_DBUS_OBJECT_MANAGER,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));
}
