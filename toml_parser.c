// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Lightweight TOML parser for frp-compatible configuration.
 * Supports: strings, integers, booleans, dotted keys, sections,
 *           array-of-tables ([[...]]), inline arrays, and comments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "toml_parser.h"
#include "debug.h"

/* ---- helper: trim whitespace in-place ---- */
static char *trim(char *s)
{
	while (isspace((unsigned char)*s)) s++;
	char *end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
	return s;
}

/* ---- find or create a section by name ---- */
static struct toml_section *find_section(struct toml_doc *doc, const char *name)
{
	for (int i = 0; i < doc->section_count; i++) {
		if (strcmp(doc->sections[i].name, name) == 0)
			return &doc->sections[i];
	}
	if (doc->section_count >= TOML_MAX_SECTIONS) {
		debug(LOG_ERR, "TOML: too many sections");
		return NULL;
	}
	struct toml_section *sec = &doc->sections[doc->section_count++];
	memset(sec, 0, sizeof(*sec));
	snprintf(sec->name, sizeof(sec->name), "%s", name);
	return sec;
}

/* ---- add entry to section ---- */
static int add_entry(struct toml_section *sec, const char *key, const char *val,
	int val_type)
{
	if (sec->entry_count >= TOML_MAX_ENTRIES) {
		debug(LOG_ERR, "TOML: too many entries in section [%s]", sec->name);
		return -1;
	}
	struct toml_entry *e = &sec->entries[sec->entry_count++];
	snprintf(e->key, sizeof(e->key), "%s", key);
	snprintf(e->val, sizeof(e->val), "%s", val);
	e->val_type = val_type;
	return 0;
}

/* ---- parse a TOML string value (handle quotes and escapes) ---- */
static int parse_string_value(const char *raw, char *out, size_t out_size)
{
	if (raw[0] != '"') {
		/* Unquoted value */
		snprintf(out, out_size, "%s", raw);
		return 0;
	}

	/* Quoted string - skip opening quote */
	const char *p = raw + 1;
	size_t pos = 0;

	while (*p && pos < out_size - 1) {
		if (*p == '"' && (p == raw + 1 || *(p - 1) != '\\')) {
			/* Closing quote */
			out[pos] = '\0';
			return 0;
		}
		if (*p == '\\' && *(p + 1)) {
			p++;
			switch (*p) {
			case 'n':  out[pos++] = '\n'; break;
			case 't':  out[pos++] = '\t'; break;
			case '\\': out[pos++] = '\\'; break;
			case '"':  out[pos++] = '"';  break;
			default:   out[pos++] = *p;   break;
			}
		} else {
			out[pos++] = *p;
		}
		p++;
	}
	out[pos] = '\0';
	return 0;
}

/* ---- parse inline array value: ["a", "b"] -> "a,b" ---- */
static int parse_inline_array(const char *raw, char *out, size_t out_size)
{
	if (raw[0] != '[') {
		snprintf(out, out_size, "%s", raw);
		return 0;
	}

	/* Skip brackets */
	const char *p = raw + 1;
	size_t pos = 0;
	int in_string = 0;

	while (*p && *p != ']' && pos < out_size - 1) {
		if (*p == '"') {
			in_string = !in_string;
			p++;
			continue;
		}
		if (!in_string && (*p == ',' || *p == ' ')) {
			if (*p == ',' && pos > 0 && out[pos - 1] != ',') {
				out[pos++] = ',';
			}
			p++;
			continue;
		}
		if (in_string || (!isspace((unsigned char)*p) && *p != ',')) {
			out[pos++] = *p;
		}
		p++;
	}
	out[pos] = '\0';

	/* Trim trailing comma */
	if (pos > 0 && out[pos - 1] == ',')
		out[pos - 1] = '\0';

	return 0;
}

/* ---- parse a single TOML line ---- */
static int parse_line(char *line, struct toml_doc *doc,
	struct toml_section **current_sec, int *current_array_idx,
	char *current_array_prefix, size_t prefix_size)
{
	char *trimmed = trim(line);

	/* Skip empty lines and comments */
	if (*trimmed == '\0' || *trimmed == '#')
		return 0;

	/* Array of tables: [[name]] */
	if (trimmed[0] == '[' && trimmed[1] == '[') {
		char *end = strstr(trimmed + 2, "]]");
		if (!end) {
			debug(LOG_ERR, "TOML: invalid array-of-tables: %s", line);
			return -1;
		}
		*end = '\0';
		char *name = trim(trimmed + 2);

		/* Track array prefix and index */
		if (strcmp(name, current_array_prefix) != 0) {
			snprintf(current_array_prefix, prefix_size, "%s", name);
			*current_array_idx = 0;
		} else {
			(*current_array_idx)++;
		}

		/* Create indexed section name: "proxies[0]", "proxies[1]", etc. */
		char sec_name[TOML_MAX_KEY];
		snprintf(sec_name, sizeof(sec_name), "%s[%d]", name,
			*current_array_idx);

		*current_sec = find_section(doc, sec_name);
		return 0;
	}

	/* Regular section: [name] */
	if (trimmed[0] == '[') {
		char *end = strchr(trimmed + 1, ']');
		if (!end) {
			debug(LOG_ERR, "TOML: invalid section: %s", line);
			return -1;
		}
		*end = '\0';
		char *name = trim(trimmed + 1);
		*current_sec = find_section(doc, name);
		/* Reset array tracking */
		current_array_prefix[0] = '\0';
		return 0;
	}

	/* Key-value pair */
	char *eq = strchr(trimmed, '=');
	if (!eq) {
		debug(LOG_ERR, "TOML: invalid line: %s", line);
		return -1;
	}

	*eq = '\0';
	char *key = trim(trimmed);
	char *val = trim(eq + 1);

	if (*key == '\0') {
		debug(LOG_ERR, "TOML: empty key");
		return -1;
	}

	/* Determine value type and normalize */
	char normalized[TOML_MAX_VAL];
	int val_type;

	if (val[0] == '[') {
		/* Inline array */
		parse_inline_array(val, normalized, sizeof(normalized));
		val_type = TOML_VAL_ARRAY;
	} else if (val[0] == '"') {
		/* String */
		parse_string_value(val, normalized, sizeof(normalized));
		val_type = TOML_VAL_STRING;
	} else if (strcmp(val, "true") == 0 || strcmp(val, "false") == 0) {
		/* Boolean -> integer */
		snprintf(normalized, sizeof(normalized), "%s",
			strcmp(val, "true") == 0 ? "1" : "0");
		val_type = TOML_VAL_BOOL;
	} else {
		/* Try integer or keep as string */
		char *endptr;
		long intval = strtol(val, &endptr, 10);
		if (*endptr == '\0' && endptr != val) {
			snprintf(normalized, sizeof(normalized), "%ld", intval);
			val_type = TOML_VAL_INT;
		} else {
			snprintf(normalized, sizeof(normalized), "%s", val);
			val_type = TOML_VAL_STRING;
		}
	}

	/* If no section defined yet, use "default" */
	if (!*current_sec) {
		*current_sec = find_section(doc, "default");
	}

	return add_entry(*current_sec, key, normalized, val_type);
}

/* ---- public API ---- */

int toml_parse_file(const char *path, struct toml_doc *doc)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		debug(LOG_ERR, "TOML: cannot open %s", path);
		return -1;
	}

	memset(doc, 0, sizeof(*doc));

	struct toml_section *current_sec = NULL;
	int current_array_idx = 0;
	char current_array_prefix[TOML_MAX_KEY] = {0};
	char line[8192];
	int line_num = 0;

	while (fgets(line, sizeof(line), f)) {
		line_num++;

		/* Strip trailing newline/carriage return */
		size_t len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';

		/* Skip BOM */
		if (line_num == 1 && (unsigned char)line[0] == 0xEF &&
			(unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF) {
			memmove(line, line + 3, len - 2);
		}

		if (parse_line(line, doc, &current_sec, &current_array_idx,
				current_array_prefix, sizeof(current_array_prefix)) < 0) {
			debug(LOG_ERR, "TOML: parse error at line %d: %s", line_num, line);
			fclose(f);
			return -1;
		}
	}

	fclose(f);
	debug(LOG_DEBUG, "TOML: parsed %d sections from %s", doc->section_count, path);
	return 0;
}

void toml_doc_free(struct toml_doc *doc)
{
	/* No dynamic memory in current implementation */
	memset(doc, 0, sizeof(*doc));
}

struct toml_section *toml_find_array_section(struct toml_doc *doc,
	const char *prefix, int index)
{
	char name[TOML_MAX_KEY];
	snprintf(name, sizeof(name), "%s[%d]", prefix, index);

	for (int i = 0; i < doc->section_count; i++) {
		if (strcmp(doc->sections[i].name, name) == 0)
			return &doc->sections[i];
	}
	return NULL;
}

int toml_count_array_sections(struct toml_doc *doc, const char *prefix)
{
	int count = 0;
	size_t prefix_len = strlen(prefix);

	for (int i = 0; i < doc->section_count; i++) {
		if (strncmp(doc->sections[i].name, prefix, prefix_len) == 0 &&
			doc->sections[i].name[prefix_len] == '[') {
			count++;
		}
	}
	return count;
}

const char *toml_get(struct toml_section *sec, const char *key)
{
	if (!sec || !key)
		return NULL;

	for (int i = 0; i < sec->entry_count; i++) {
		if (strcmp(sec->entries[i].key, key) == 0)
			return sec->entries[i].val;
	}
	return NULL;
}
