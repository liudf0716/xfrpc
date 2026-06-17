// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * TOML parser wrapper using tomlc17 library.
 * Maps the xfrpc-style flat API (toml_find_array_section/toml_get) onto
 * the tomlc17 tree-based API (toml_seek/toml_get).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "vendor/tomlc17/tomlc17.h"
#define TOML_PARSER_INTERNAL
#include "toml_parser.h"
#include "debug.h"

/* ---- Internal document structure ---- */

struct toml_doc {
	toml_result_t result;
};

/* ---- Parse a TOML file ---- */

int xfrpc_toml_parse_file(const char *path, struct toml_doc **out_doc)
{
	struct toml_doc *doc = calloc(1, sizeof(struct toml_doc));
	if (!doc) {
		debug(LOG_ERR, "TOML: out of memory");
		return -1;
	}

	doc->result = toml_parse_file_ex(path);
	if (!doc->result.ok) {
		debug(LOG_ERR, "TOML: parse error: %s", doc->result.errmsg);
		free(doc);
		return -1;
	}

	*out_doc = doc;
	return 0;
}

/* ---- Free document ---- */

void xfrpc_toml_doc_free(struct toml_doc *doc)
{
	if (!doc)
		return;
	toml_free(doc->result);
	free(doc);
}

/* ---- Get root table from doc ---- */

static toml_datum_t get_root(struct toml_doc *doc)
{
	return doc->result.toptab;
}

/* ---- Find array-of-tables section ---- */

void *xfrpc_toml_find_array_section(struct toml_doc *doc, const char *prefix, int index)
{
	if (!doc)
		return NULL;

	toml_datum_t root = get_root(doc);

	/* index == -1 means return the root table itself */
	if (index < 0) {
		/* Return a pointer to the root datum (persistent in doc) */
		static __thread toml_datum_t tls_slot;
		tls_slot = root;
		return &tls_slot;
	}

	/* Look up the array by prefix */
	toml_datum_t arr;
	if (prefix && *prefix) {
		arr = toml_get(root, prefix);
	} else {
		arr = root;
	}

	if (arr.type != TOML_ARRAY)
		return NULL;
	if (index >= arr.u.arr.size)
		return NULL;

	/* Return pointer to the element (persistent in doc) */
	return &arr.u.arr.elem[index];
}

/* ---- Count array-of-tables sections ---- */

int xfrpc_toml_count_array_sections(struct toml_doc *doc, const char *prefix)
{
	if (!doc || !prefix)
		return 0;

	toml_datum_t root = get_root(doc);
	toml_datum_t arr = toml_get(root, prefix);

	if (arr.type != TOML_ARRAY)
		return 0;

	return arr.u.arr.size;
}

/* ---- Helper: convert datum to string in doc's buffer ---- */


/* ---- Get value from section by key ---- */

const char *xfrpc_toml_get(void *sec, const char *key)
{
	if (!sec || !key)
		return NULL;

	toml_datum_t *table = (toml_datum_t *)sec;

	/* Use toml_seek for dotted key paths (e.g. "transport.tls.enable") */
	toml_datum_t val = toml_seek(*table, key);
	if (val.type == TOML_UNKNOWN)
		return NULL;

	/* Find the document that owns this datum to use its scratch buffer.
	 * We store a doc pointer at a known offset. Since toml_datum_t is
	 * embedded in the doc's result tree, we can't easily get back to doc.
	 * Instead, use a thread-local static buffer. */
	static __thread char tls_buf[1024];

	switch (val.type) {
	case TOML_STRING:
		return val.u.s;
	case TOML_INT64:
		snprintf(tls_buf, sizeof(tls_buf), "%" PRId64, val.u.int64);
		return tls_buf;
	case TOML_BOOLEAN:
		return val.u.boolean ? "1" : "0";
	case TOML_FP64:
		snprintf(tls_buf, sizeof(tls_buf), "%g", val.u.fp64);
		return tls_buf;
	case TOML_ARRAY: {
		int pos = 0;
		for (int i = 0; i < val.u.arr.size && pos < (int)sizeof(tls_buf) - 4; i++) {
			toml_datum_t elem = val.u.arr.elem[i];
			if (i > 0)
				pos += snprintf(tls_buf + pos, sizeof(tls_buf) - pos, ", ");
			if (elem.type == TOML_STRING)
				pos += snprintf(tls_buf + pos, sizeof(tls_buf) - pos, "%s", elem.u.s);
			else if (elem.type == TOML_INT64)
				pos += snprintf(tls_buf + pos, sizeof(tls_buf) - pos, "%" PRId64, elem.u.int64);
		}
		return tls_buf;
	}
	default:
		return NULL;
	}
}
