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
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include "config.h"

char *uci_get(const char *str)
{
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		goto error;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		goto error;
	}

	if (UCI_TYPE_SECTION == result.target && result.s) {
		char *ret = strdup(result.s->type);
		if (!ret)
			printf("Error memory.\n");
		uci_free_context(context);
		return ret;
	}

	if (!result.o)
		goto error;

	char *ret = strdup(result.o->v.string);
	if (!ret)
		printf("Error uci get.\n");

	if (!ret)
		ret = strdup("");
	uci_free_context(context);
	return ret;
error:
	if (context)
		uci_free_context(context);
	return NULL;
}

int uci_set_value(const char *str)
{
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		goto error;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		goto error;
	}

	if (uci_set(context, &result) != UCI_OK) {
		printf("UCI set error.\n");
		goto error;
	}
	if (uci_save(context, result.p) != UCI_OK) {
		printf("UCI save error.\n");
		goto error;
	}
	if (uci_commit(context, &result.p, 1) != UCI_OK) {
		printf("UCI commit error.\n");
		goto error;
	}

	uci_free_context(context);
	return 0;
error:
	if (context)
		uci_free_context(context);
	return -1;
}

int uci_del(const char *str)
{
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		goto error;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		goto error;
	}

	if (uci_delete(context, &result) != UCI_OK) {
		printf("UCI delete error.\n");
		goto error;
	}

	if (uci_save(context, result.p) != UCI_OK) {
		printf("UCI save error.\n");
		goto error;
	}

	if (uci_commit(context, &result.p, false) != UCI_OK) {
		printf("UCI commit error.\n");
		goto error;
	}

	uci_free_context(context);
	return 0;
error:
	if (context)
		uci_free_context(context);
	return 0;
}

char *uci_list_get(const char *str, int element)
{
	struct uci_option *o;
	struct uci_element *el;
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	int i = 0;

	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		goto error;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		goto error;
	}

	if (!result.o)
		goto error;

	uci_foreach_element(&result.o->v.list, el) {
		o = uci_to_option(el);
		if (i == element)
			break;
		else
			i++;
	}

	if (element < i)
		goto error;

	if (!o->e.name)
		goto error;

	char *ret = strdup(o->e.name);
	if (!ret)
		printf("Error memory.\n");

	uci_free_context(context);
	return ret;

error:
	if (context)
		uci_free_context(context);
	return NULL;
}

int uci_list_set_value(const char *str, const char *value, int element)
{
	struct uci_option *o;
	struct uci_element *el;
	struct uci_ptr result = {};
	struct uci_ptr result_copy = {};
	char str_copy[strlen(str) + 1];
	int i = 0, n, m;
	int ret = 0;

	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		return -1;

	ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
	if (UCI_OK != ret) {
		uci_free_context(context);
		return -1;
	}

	if (result.o && result.o->type) {
		uci_foreach_element(&result.o->v.list, el) {i++;}
	}
	char *list[i];
	n = i;
	m = n;
	i = 0;

	if (result.o && result.o->type) {
		uci_foreach_element(&result.o->v.list, el) {
			o = uci_to_option(el);
			list[i] = strdup(o->e.name);
			i++;
		}
	}

	for (i = 0; i < n; i++) {
		int len = strlen(str) + strlen(list[i]) + 2;
		char uci[len];

		snprintf(uci, len, "%s=%s", str, list[i]);

		char str_copy[strlen(uci) + 1];
		snprintf(str_copy, (strlen(uci) + 1), "%s", uci);
		ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
		if (UCI_OK != ret) {
			goto out;
		}

		ret = uci_del_list(context, &result);
		if (UCI_OK != ret) {
			printf("UCI delet list error.\n");
			goto out;
		}
	}

	if (element >= i) {
		n++;
	}
	if (0 == i) {
		n = 1;
		element =0;
	}

	for (i = 0; i < n; i++) {
		const char *new_value;
		if (i == element)
			new_value = value;
		else
			new_value = list[i];

		int len = strlen(str) + strlen(new_value) + 2;
		char uci[len];
		snprintf(uci, len, "%s=%s", str, new_value);
		char str_copy[strlen(uci) + 2];
		snprintf(str_copy, (strlen(uci) + 1), "%s", uci);

		if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
			goto out;
		}

		if (0 == i) {
			ret = uci_set(context, &result);
			snprintf(str_copy, (strlen(uci) + 2), "%s%s", uci, "_");
			if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
				goto out;
			}
			ret = uci_add_list(context, &result);
			ret = uci_del_list(context, &result);
		} else {
			ret = uci_add_list(context, &result);
		}

		if (UCI_OK != ret) {
			printf("UCI set error.\n");
			goto out;
		}
	}

	ret = uci_save(context, result.p);
	if (UCI_OK != ret) {
		printf("UCI save error.\n");
		goto out;
	}

	ret = uci_commit(context, &result.p, 1);
	if (UCI_OK != ret) {
		printf("UCI commit error.\n");
		goto out;
	}

out:
	for (i = 0; i < m; i++) {
		free(list[i]);
	}

	uci_free_context(context);
	return ret;
}

int uci_list_del(const char *str, int element)
{
	struct uci_option *o;
	struct uci_element *el;
	struct uci_ptr result = {};
	char str_copy[strlen(str) + 1];
	int i = 0, n = 0;
	int ret = 0;

	snprintf(str_copy, (strlen(str) + 1), "%s", str);

	struct uci_context *context = uci_alloc_context();
	if (!context)
		return -1;

	if (uci_lookup_ptr(context, &result, (char *) str_copy, true) != UCI_OK) {
		uci_free_context(context);
		return -1;
	}

	if (result.o && result.o->type) {
		uci_foreach_element(&result.o->v.list, el) {i++;}
	}
	char *list[i];
	n = i;
	i = 0;

	if (result.o && result.o->type) {
		uci_foreach_element(&result.o->v.list, el) {
			o = uci_to_option(el);
			list[i] = strdup(o->e.name);
			i++;
		}
	}

	for (i = 0; i < n; i++) {
		int len = strlen(str) + strlen(list[i]) + 2;
		char uci[len];

		snprintf(uci, len, "%s=%s", str, list[i]);

		char str_copy[strlen(uci) + 1];
		snprintf(str_copy, (strlen(uci) + 1), "%s", uci);
		ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
		if (UCI_OK != ret) {
			goto out;
		}

		ret = uci_del_list(context, &result);
		if (UCI_OK != ret) {
			printf("UCI delet list error.\n");
			goto out;
		}
	}

	for (i = 0; i < n; i++) {
		const char *new_value;
		if (i == element)
			continue;

		int len = strlen(str) + strlen(list[i]) + 2;
		char uci[len];

		snprintf(uci, len, "%s=%s", str, list[i]);

		char str_copy[strlen(uci) + 1];
		snprintf(str_copy, (strlen(uci) + 1), "%s", uci);
		ret = uci_lookup_ptr(context, &result, (char *) str_copy, true);
		if (UCI_OK != ret) {
			goto out;
		}

		if (0 == i)
			ret = uci_set(context, &result);
		else
			ret = uci_add_list(context, &result);
		if (UCI_OK != ret) {
			printf("UCI set error.\n");
			goto out;
		}
	}

	ret = uci_save(context, result.p);
	if (UCI_OK != ret) {
		printf("UCI save error.\n");
		goto out;
	}
	ret = uci_commit(context, &result.p, 1);
	if (UCI_OK != ret) {
		printf("UCI commit error.\n");
		goto out;
	}

out:
	for (i = 0; i < n; i++) {
		free(list[i]);
	}
	uci_free_context(context);
	return ret;
}
