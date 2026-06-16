// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Lightweight TOML parser for frp-compatible configuration.
 * Supports the subset of TOML used by frp's configuration format.
 */

#ifndef XFRPC_TOML_PARSER_H
#define XFRPC_TOML_PARSER_H

#include <stddef.h>

/* TOML value types */
#define TOML_VAL_STRING  0
#define TOML_VAL_INT     1
#define TOML_VAL_BOOL    2
#define TOML_VAL_ARRAY   3

/* Maximum limits */
#define TOML_MAX_KEY     128
#define TOML_MAX_VAL     1024
#define TOML_MAX_ENTRIES 128
#define TOML_MAX_SECTIONS 64
#define TOML_MAX_ARRAY   32

/* TOML key-value entry */
struct toml_entry {
	char key[TOML_MAX_KEY];      /* Full dotted key, e.g. "localIP" */
	char val[TOML_MAX_VAL];      /* String value (arrays as CSV) */
	int  val_type;               /* TOML_VAL_* */
};

/* TOML section (regular section or array-of-tables element) */
struct toml_section {
	char name[TOML_MAX_KEY];     /* Section key, e.g. "proxies[0]" */
	struct toml_entry entries[TOML_MAX_ENTRIES];
	int  entry_count;
};

/* Top-level TOML document */
struct toml_doc {
	struct toml_section sections[TOML_MAX_SECTIONS];
	int  section_count;
};

/**
 * @brief Parse a TOML file into a document structure
 * @param path Path to the TOML file
 * @param doc  Output document structure
 * @return 0 on success, -1 on error
 */
int toml_parse_file(const char *path, struct toml_doc *doc);

/**
 * @brief Free resources associated with a TOML document
 * @param doc Document to free
 */
void toml_doc_free(struct toml_doc *doc);

/**
 * @brief Find a section by name prefix (for array-of-tables matching)
 * @param doc    Document to search
 * @param prefix Section name prefix (e.g. "proxies")
 * @param index  Index within the array (0-based)
 * @return Pointer to section, or NULL if not found
 */
struct toml_section *toml_find_array_section(struct toml_doc *doc,
	const char *prefix, int index);

/**
 * @brief Count array-of-tables entries with given prefix
 * @param doc    Document to search
 * @param prefix Section name prefix (e.g. "proxies")
 * @return Number of entries found
 */
int toml_count_array_sections(struct toml_doc *doc, const char *prefix);

/**
 * @brief Get a value from a section by key name
 * @param sec Section to search
 * @param key Key name to find
 * @return Value string, or NULL if not found
 */
const char *toml_get(struct toml_section *sec, const char *key);

#endif /* XFRPC_TOML_PARSER_H */
