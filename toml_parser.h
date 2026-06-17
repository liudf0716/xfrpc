// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * TOML parser wrapper using tomlc17 library.
 * 
 * IMPORTANT: toml_parser.c must include vendor/tomlc17/tomlc17.h BEFORE
 * this header to avoid macro conflicts. Other files should only include
 * this header (NOT tomlc17.h directly).
 */

#ifndef XFRPC_TOML_PARSER_H
#define XFRPC_TOML_PARSER_H

#include <stddef.h>

/* Opaque document handle */
struct toml_doc;

int xfrpc_toml_parse_file(const char *path, struct toml_doc **doc);
void xfrpc_toml_doc_free(struct toml_doc *doc);
void *xfrpc_toml_find_array_section(struct toml_doc *doc, const char *prefix, int index);
int xfrpc_toml_count_array_sections(struct toml_doc *doc, const char *prefix);
const char *xfrpc_toml_get(void *sec, const char *key);

/* Compatibility macros for config.c (not active in toml_parser.c which
 * includes tomlc17.h first, conflicting with these names) */
#ifndef TOML_PARSER_INTERNAL
#define toml_parse_file(path, doc)             xfrpc_toml_parse_file(path, doc)
#define toml_doc_free(doc)                     xfrpc_toml_doc_free(doc)
#define toml_find_array_section(doc, pre, idx) xfrpc_toml_find_array_section(doc, pre, idx)
#define toml_count_array_sections(doc, pre)    xfrpc_toml_count_array_sections(doc, pre)
#define toml_get(sec, key)                     xfrpc_toml_get(sec, key)
#endif

#endif /* XFRPC_TOML_PARSER_H */
