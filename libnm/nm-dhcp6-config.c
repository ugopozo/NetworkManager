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
 * Copyright 2008 - 2011 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include <string.h>

#include "nm-dhcp6-config.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMDhcp6Config, nm_dhcp6_config, NM_TYPE_OBJECT)

#define NM_DHCP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigPrivate))

typedef struct {
	GHashTable *options;
} NMDhcp6ConfigPrivate;

enum {
	PROP_0,
	PROP_OPTIONS,

	LAST_PROP
};

static void
nm_dhcp6_config_init (NMDhcp6Config *config)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (config);

	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static gboolean
demarshal_dhcp6_options (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);
	GVariantIter iter;
	const char *key;
	GVariant *opt;

	g_hash_table_remove_all (priv->options);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &opt)) {
		g_hash_table_insert (priv->options, g_strdup (key), g_variant_dup_string (opt, NULL));
		g_variant_unref (opt);
	}

	_nm_object_queue_notify (object, NM_DHCP6_CONFIG_OPTIONS);
	return TRUE;
}

static void
init_dbus (NMObject *object)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DHCP6_CONFIG_OPTIONS,   &priv->options, demarshal_dhcp6_options },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_dhcp6_config_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DHCP6_CONFIG,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	if (priv->options)
		g_hash_table_destroy (priv->options);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDhcp6Config *self = NM_DHCP6_CONFIG (object);

	switch (prop_id) {
	case PROP_OPTIONS:
		g_value_set_boxed (value, nm_dhcp6_config_get_options (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp6_config_class_init (NMDhcp6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMDhcp6ConfigPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DHCP6_CONFIG);

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMDhcp6Config:options:
	 *
	 * The #GHashTable containing options of the configuration.
	 *
	 * Type: GLib.HashTable(utf8,GObject.Value)
	 **/
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP6_CONFIG_OPTIONS, "", "",
		                     G_TYPE_HASH_TABLE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}

/**
 * nm_dhcp6_config_get_options:
 * @config: a #NMDhcp6Config
 *
 * Gets all the options contained in the configuration.
 *
 * Returns: (transfer none) (element-type utf8 GObject.Value): the #GHashTable containing strings for keys and values.
 * This is the internal copy used by the configuration, and must not be modified.
 **/
GHashTable *
nm_dhcp6_config_get_options (NMDhcp6Config *config)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (config), NULL);

	return NM_DHCP6_CONFIG_GET_PRIVATE (config)->options;
}

/**
 * nm_dhcp6_config_get_one_option:
 * @config: a #NMDhcp6Config
 * @option: the option to retrieve
 *
 * Gets one option by option name.
 *
 * Returns: the configuration option's value. This is the internal string used by the
 * configuration, and must not be modified.
 **/
const char *
nm_dhcp6_config_get_one_option (NMDhcp6Config *config, const char *option)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (config), NULL);

	return g_hash_table_lookup (nm_dhcp6_config_get_options (config), option);
}