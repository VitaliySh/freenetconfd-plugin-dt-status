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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <uci.h>

char *uci_get(const char *str);
int uci_set_value(const char *str);
int uci_del(const char *str);
int uci_del_section(const char *str);

char *uci_list_get(const char *str, int element);
int uci_list_set_value(const char *str, const char *value, int element);
int uci_list_del(const char *str, int element);

#endif /* __CONFIG_H__ */
