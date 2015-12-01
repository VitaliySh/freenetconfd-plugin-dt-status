/*
 * Copyright (C) 2015 Deutsche Telekom AG.
 *
 * Author: Mislav Novakovic <mislav.novakovic@sartura.hr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freenetconfd/plugin.h>
#include <freenetconfd/datastore.h>
#include <freenetconfd/freenetconfd.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <json-c/json.h>
#include <uci.h>

#include "config.h"

struct ubus_context *ubus_ctx;

__unused struct module *init();
__unused void destroy();

datastore_t root = DATASTORE_ROOT_DEFAULT;
datastore_t *status = NULL;

struct module m;
char *_ns = "urn:ietf:params:xml:ns:yang:status";
static char *config_file = "wireless";

static char *get_uci_id(char *device)
{
	struct uci_context *ctx = NULL;
	struct uci_package *package = NULL;
	struct uci_element *e, *el, *el_list;
	struct uci_section *s;
	struct uci_option *o, *o_list;
	char *result = NULL;
	int rc = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	rc = uci_load(ctx, config_file, &package);
	if (rc != UCI_OK)
		goto out;

	uci_foreach_element(&package->sections, e) {
		s = uci_to_section(e);
		result = s->e.name;

		if (strcmp(s->type, "wifi-iface"))
			continue;
		result = strdup(s->e.name);
		uci_foreach_element(&s->options, el) {
			o = uci_to_option(el);
			if (UCI_TYPE_STRING == o->type && !strcmp(o->e.name, "device")) {
				if (device && !strcmp(o->v.string, device))
					goto out;
				free(result);
				result = NULL;
			}
		}
	}

out:
	if (!result)
		result = strdup("");

	if (package)
		uci_unload(ctx, package);
	if (ctx)
		uci_free_context(ctx);
	return result;
}

static datastore_t *find_sibling(datastore_t *self, char *name, char *value)
{
	datastore_t *left = self;
	while (left->prev)
		left = left->prev;
	return ds_find_sibling(left, name, value);
}

static int list_set_node(datastore_t *self, char *value)
{
	datastore_t *node = find_sibling(self, "device", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	datastore_t *tmp = self;
	int i = -1;

	while(tmp->prev) {
		if (!strcmp(tmp->name, self->name))
			i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + strlen(value) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_list_set_value(&uci[0], value, i);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + strlen(value) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		if (uci_id)
			free(option);
		return uci_list_set_value(&uci[0], value, i);
	}
}

static char *list_get_node(datastore_t *self)
{
	datastore_t *node = find_sibling(self, "device", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	char *result = NULL;
	datastore_t *tmp = self;
	int i = -1;

	while(tmp->prev) {
		if (!strcmp(tmp->name, self->name))
			i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		result = uci_list_get(&uci[0], i);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		if (uci_id)
			free(option);
		result = uci_list_get(&uci[0], i);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int list_del_node(struct datastore *self, void *data)
{
	datastore_t *node = find_sibling(self, "device", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	datastore_t *tmp = self;
	int i = -1;

	while(tmp->prev) {
		if (!strcmp(tmp->name, self->name))
			i++;
		tmp = tmp->prev;
	}

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_list_del(&uci[0], i);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		if (uci_id)
			free(option);
		return uci_list_del(&uci[0], i);
	}
}

static int set_node(datastore_t *self, char *value)
{
	char *option = NULL;
	datastore_t *node = find_sibling(self, "name", NULL);
	if (node)
		option = node->value;
	char *element = self->name;

	if (!strcmp(self->parent->name, "wifi-iface")) {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "name", NULL);
		char *device_name = NULL;
		if (device)
			device_name = device->value;
		option = get_uci_id(device_name);
		if (!option)
			return 0;
		int len = strlen(config_file) + strlen(option) + strlen(element) + strlen(value) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s=%s", config_file, option, element, value);
		free(option);
		return uci_set_value(&uci[0]);
	} else if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + strlen(value) + 8;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s=%s", config_file, self->parent->name, element, value);
		return uci_set_value(&uci[0]);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + strlen(value) + 4;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s=%s", config_file, option, element, value);
		if (uci_id)
			free(option);
		return uci_set_value(&uci[0]);
	}
}

static char *get_node(datastore_t *self)
{
	datastore_t *node = find_sibling(self, "name", NULL);
	if (!node)
		node = find_sibling(self, "device", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;
	char *result = NULL;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		result = uci_get(&uci[0]);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		if (uci_id)
			free(option);
		result = uci_get(&uci[0]);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int del_node(struct datastore *self, void *data)
{
	datastore_t *node = find_sibling(self, "name", NULL);
	if (!node)
		node = find_sibling(self, "device", NULL);
	if (!node)
		return 0;
	char *option = node->value;
	char *element = self->name;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + strlen(element) + 7;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0].%s", config_file, self->parent->name, element);
		return uci_del(&uci[0]);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + strlen(element) + 3;
		char uci[len];
		snprintf(uci, len, "%s.%s.%s", config_file, option, element);
		if (uci_id)
			free(option);
		return uci_del(&uci[0]);
	}
}

static int config_set_node(datastore_t *self, char *value)
{
	struct uci_package *pack = NULL;
	struct uci_ptr ptr = { 0 };

	datastore_t *node = self->parent;

	if (!value || !strcmp(value, "") || !strcmp(node->name, "wifi-iface")) {
		struct uci_context *ctx;
		int ret;

		ctx = uci_alloc_context();
		if (!ctx)
			return 1;

		ret = uci_load(ctx, config_file, &pack);
		if (UCI_OK != ret) {
			uci_free_context(ctx);
			return 1;
		}

		ptr.p = pack;
		uci_add_section(ctx, pack, self->parent->name, &ptr.s);
		ptr.o = NULL;

		if (uci_save(ctx, ptr.p) != UCI_OK) {
			printf("UCI save error.\n");
			uci_free_context(ctx);
			return 1;
		}
		if (uci_commit(ctx, &ptr.p, 1) != UCI_OK) {
			printf("UCI commit error.\n");
			uci_free_context(ctx);
			return 1;
		}

		uci_free_context(ctx);
		return 0;
	}

	int len = strlen(config_file) + strlen(self->parent->name) + strlen(value) + 3;
	char uci[len];
	snprintf(uci, len, "%s.%s=%s", config_file, value, self->parent->name);

	return uci_set_value(&uci[0]);
}

static char *config_get_node(datastore_t *self)
{
	char *option = self->value;
	char *result = NULL;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + 6;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0]", config_file, self->parent->name);
		result = uci_get(&uci[0]);
	} else {
		result = strdup(option);
	}

	if (result) {
		char *buffer = strdup(result);
		free(result);
		return buffer;
	} else {
		char *buffer = strdup("");
		return buffer;
	}
}

static int config_del_node(struct datastore *self, void *data)
{
	if (!self)
		return 0;
	if (!self->value)
		self = ds_find_child(self, "name", NULL);
	char *option = self->value;

	if (!option || !strcmp(option, "")) {
		int len = strlen(config_file) + strlen(self->parent->name) + 6;
		char uci[len];
		snprintf(uci, len, "%s.@%s[0]", config_file, self->parent->name);
		return uci_del(&uci[0]);
	} else {
		bool uci_id = false;
		datastore_t *device = find_sibling(self, "device", NULL);
		if (device && self->parent && !strcmp(self->parent->name, "wifi-iface")) {
			option = get_uci_id(device->value);
			uci_id = true;
		}
		int len = strlen(config_file) + strlen(option) + 2;
		char uci[len];
		snprintf(uci, len, "%s.%s", config_file, option);
		if (uci_id)
			free(option);
		return uci_del(&uci[0]);
	}
}

datastore_t *create_dhcp_leases_child(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, ns, target_name, target_position);

	if (!strcmp(name, "leases-expirey")) {
	} else if (!strcmp(name, "mac")) {
	} else if (!strcmp(name, "ip")) {
	} else if (!strcmp(name, "name")) {
	} else if (!strcmp(name, "id")) {
		child->is_key = 1;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

datastore_t *create_wifi_device_child(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "name")) {
		child->set = config_set_node;
		child->get = config_get_node;
		child->del = config_del_node;
		child->is_key = 1;
	} else if (!strcmp(name, "type")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "channel")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "macaddr")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "hwmode")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "disabled")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "test")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

datastore_t *create_wifi_iface_child(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = ds_add_child_create(self, name, value, NULL, NULL, 0);

	if (!strcmp(name, "name")) {
		child->set = config_set_node;
		child->get = config_get_node;
		child->del = config_del_node;
		child->is_key = 1;
	} else if (!strcmp(name, "type")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "device")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "network")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "mode")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "ssid")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "encryption")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "maclist")) {
		child->set = list_set_node;
		child->get = list_get_node;
		child->del = list_del_node;
		child->is_list = 1;
	} else if (!strcmp(name, "macfilter")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "key")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else if (!strcmp(name, "test")) {
		child->set = set_node;
		child->get = get_node;
		child->del = del_node;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

datastore_t *create_dhcp_child(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(name, "dhcp-leases")) {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child->create_child = create_dhcp_leases_child;
		child->is_list = 1;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

datastore_t *create_wifi_child(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(name, "wifi-device")) {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child->create_child = create_wifi_device_child;
		child->del = config_del_node;
		child->is_list = 1;
	} else if (!strcmp(name, "wifi-iface")) {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child->create_child = create_wifi_iface_child;
		child->del = config_del_node;
		child->is_list = 1;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

datastore_t *create_status(datastore_t *self, char *name, char *value, char *ns, char *target_name, int target_position)
{
	datastore_t *child = NULL;

	if (!strcmp(name, "board")) {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
	} else if (!strcmp(name, "dhcp")) {
		child = ds_add_child_create(self, name, NULL, _ns, NULL, 0);
		child->create_child = create_dhcp_child;
	} else if (!strcmp(name, "wifi")) {
		child = ds_add_child_create(self, name, NULL, NULL, NULL, 0);
		child->create_child = create_wifi_child;
	} else {
		//ds_free(child, 0);
		//child = NULL;
	}

	return child;
}

char *format_ubus_response(const char *str) {
	size_t len = strlen(str);
	if (len <= 2) {
		return strdup("");
	}

	char *res = (char *) malloc((len + 1) * sizeof(char));
	memcpy(res, str, len + 1);
	memmove(res, res + 1, len - 2);
	res[len-2] = '\0';
	return res;
}

static void system_board_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct json_object *t, *o, *r;
	char *json_result = NULL;
	datastore_t *board = NULL;
	char *tmp = NULL;
	int rc;

	if (msg) {
		json_result = blobmsg_format_json(msg, true);
		r = json_tokener_parse(json_result);
	} else {
		return;
	}

	if (!status)
		goto out;

	board = ds_find_child(status, "board", NULL);
	if (!board)
		return NULL;

	json_object_object_get_ex(r, "kernel", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(board, "kernel", tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(r, "hostname", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(board, "hostname", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(r, "system", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(board, "system", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(r, "release", &t);
	tmp = format_ubus_response(json_object_to_json_string(o));
	datastore_t *release = ds_add_child_create(board, "release", NULL, _ns, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "distribution", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "distribution", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "version", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "version", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "revision", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "revision", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "codename", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "codename", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "target", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "target", (char *) tmp, NULL, NULL, 0);
	free(tmp);

	json_object_object_get_ex(t, "description", &o);
	tmp = format_ubus_response(json_object_to_json_string(o));
	ds_add_child_create(release, "description", (char *) tmp, NULL, NULL, 0);
	free(tmp);

out:
	json_object_put(r);
	free(json_result);
}

static void system_board()
{
	struct ubus_context *ubus_ctx = NULL;
	struct json_object *j = NULL;
	struct blob_buf *buf = NULL;
	uint32_t id = 0;
	int rc;

	buf = calloc(1, sizeof(struct blob_buf));
	if (!buf)
		goto out;

	rc = blob_buf_init(buf, 0);
	if (rc)
		goto out;

	ubus_ctx = ubus_connect(NULL);
	if (!ubus_ctx)
		goto out;

	rc = ubus_lookup_id(ubus_ctx, "system", &id);
	if (rc)
		goto out;

	rc = ubus_invoke(ubus_ctx, id, "board", buf->head, system_board_cb, NULL, 5000);

out:
	if (buf) {
		blob_buf_free(buf);
		free(buf);
	}
	if (ubus_ctx) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
	}
	return;
}

static void update_dhcp_leases()
{
	datastore_t *dhcp = NULL;
	char *line = NULL;
	char *pch = NULL;
	size_t len = 0;
	ssize_t read;
	FILE * fp;

	dhcp = ds_find_child(status, "dhcp", NULL);
	if (dhcp)
		ds_free(dhcp->child, 1);

	dhcp = status->create_child(status, "dhcp", NULL, _ns, NULL, 0);
	if (!dhcp)
		goto out;

	fp = fopen("/tmp/dhcp.leases", "r");
	if (fp == NULL)
		goto out;

	while ((read = getline(&line, &len, fp)) != -1) {
		char *tmp = line;

		//lease-expirey
		pch = strchr(tmp, ' ');
		if (!pch)
			continue;
		int len = strlen(tmp) - strlen(pch) + 1;
		char leases_expirey[len];
		snprintf(leases_expirey, len, "%s", tmp);
		tmp = (pch + 1);

		//mac
		pch = strchr(tmp, ' ');
		if (!pch)
			continue;
		len = strlen(tmp) - strlen(pch) + 1;
		char mac[len];
		snprintf(mac, len, "%s", tmp);
		tmp = (pch + 1);

		//ip
		pch = strchr(tmp, ' ');
		if (!pch)
			continue;
		len = strlen(tmp) - strlen(pch) + 1;
		char ip[len];
		snprintf(ip, len, "%s", tmp);
		tmp = (pch + 1);

		//name
		pch = strchr(tmp, ' ');
		if (!pch)
			continue;
		len = strlen(tmp) - strlen(pch) + 1;
		char name[len];
		snprintf(name, len, "%s", tmp);
		tmp = (pch + 1);

		//id
		len = strlen(tmp);
		char id[len];
		snprintf(id, len, "%s", tmp);

		datastore_t *dhcp_leases = dhcp->create_child(dhcp, "dhcp-leases", NULL, _ns, NULL, 0);
		if (!dhcp_leases)
			continue;
		dhcp_leases->create_child(dhcp_leases, "leases-expirey", leases_expirey, NULL, NULL, 0);
		dhcp_leases->create_child(dhcp_leases, "mac", mac, NULL, NULL, 0);
		dhcp_leases->create_child(dhcp_leases, "ip", ip, NULL, NULL, 0);
		dhcp_leases->create_child(dhcp_leases, "name", name, NULL, NULL, 0);
		dhcp_leases->create_child(dhcp_leases, "id", id, NULL, NULL, 0);
	}

out:
	if (fp)
		fclose(fp);
	if (line)
		free(line);
	return;
}

static void update_wifi()
{
	datastore_t *wifi = NULL;
	datastore_t *node = NULL;
	struct uci_context *ctx = NULL;
	struct uci_package *package = NULL;
	struct uci_element *e, *el, *el_list;
	struct uci_section *s;
	struct uci_option *o, *o_list;
	int rc = 0;

	wifi = ds_find_child(status, "wifi", NULL);
	if (wifi)
		ds_free(wifi->child, 0);

	wifi = status->create_child(status, "wifi", NULL, _ns, NULL, 0);
	if (!wifi)
		goto out;

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;

	rc = uci_load(ctx, config_file, &package);
	if (rc != UCI_OK)
		goto out;

	uci_foreach_element(&package->sections, e) {
		s = uci_to_section(e);

		if (!strcmp(s->type, "wifi-device")) {
			node = wifi->create_child(wifi, "wifi-device", NULL, _ns, NULL, 0);
			node->create_child(node, "name", s->e.name, NULL, NULL, 0);
		} else if (!strcmp(s->type, "wifi-iface")) {
			node = wifi->create_child(wifi, "wifi-iface", NULL, _ns, NULL, 0);
		} else {
			continue;
		}

		uci_foreach_element(&s->options, el) {
			o = uci_to_option(el);
			if (UCI_TYPE_STRING == o->type) {
				if (!strcmp(o->e.name, "maclist")) {
					int len = strlen(config_file) + strlen(s->e.name) + strlen("maclist") + 5;
					char uci[len];
					snprintf(uci, len, "%s.%s.%s", config_file, s->e.name, "maclist");
					uci_del(&uci[0]);

					int set_len = strlen(config_file) + strlen(s->e.name) + strlen("maclist") + strlen(o->v.string) + 1;
					char set_uci[set_len];
					snprintf(set_uci, set_len, "%s.%s.%s", config_file, s->e.name, "maclist");
					uci_list_set_value(&set_uci[0], o->v.string, 0);
				} else if (!strcmp(o->e.name, "device")) {
					node->create_child(node, "name", o->v.string, NULL, NULL, 0);
				}
				node->create_child(node, o->e.name, o->v.string, NULL, NULL, 0);
			} else if (UCI_TYPE_LIST == o->type && !strcmp(o->e.name, "maclist")) {
				uci_foreach_element(&o->v.list, el_list) {
					o_list = uci_to_option(el_list);
					node->create_child(node, o->e.name, o_list->e.name, NULL, NULL, 0);
				}
			}
		}
	}

out:
	if (package)
		uci_unload(ctx, package);
	if (ctx)
		uci_free_context(ctx);
	return;
}

static void create_store()
{
	status = ds_add_child_create(&root, "status", NULL, NULL, NULL, 0);
	status->create_child = create_status;
	status->create_child(status, "board", NULL, _ns, NULL, 0);
	system_board();
	update_dhcp_leases();
	update_wifi();
}

struct rpc_method rpc[] = {
};

__unused struct module *init()
{
	m.rpcs = rpc;
	m.rpc_count = (sizeof(rpc) / sizeof(*(rpc)));
	m.ns = _ns;
	m.datastore = &root;

	create_store();

	return &m;
}

__unused void destroy()
{
	ds_free(root.child, 1);
	root.child = NULL;
}
