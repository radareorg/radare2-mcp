/* r2mcp - MIT - Copyright 2025 - pancake */

#if R2_VERSION_NUMBER < 50909
static st64 r_json_get_num(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, 0);
	const RJson *field = r_json_get (json, key);
	if (field) {
		switch (field->type) {
		case R_JSON_STRING:
			return r_num_get (NULL, field->str_value);
		case R_JSON_INTEGER:
			return field->num.s_value;
		case R_JSON_BOOLEAN:
			return field->num.u_value;
		case R_JSON_DOUBLE:
			return (int)field->num.dbl_value;
		}
	}
	return 0;
}

static const char *r_json_get_str(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, NULL);
	const RJson *field = r_json_get (json, key);
	if (!field || field->type != R_JSON_STRING) {
		return NULL;
	}
	return field->str_value;
}

#endif

// Helper to paginate text by lines
static inline char *paginate_text_by_lines(char *text, const char *cursor, int page_size, bool *has_more, char **next_cursor) {
	if (!text) {
		if (has_more) {
			*has_more = false;
		}
		if (next_cursor) {
			*next_cursor = NULL;
		}
		return strdup ("");
	}
	RList *lines = r_str_split_list (text, "\n", 0);
	if (!lines) {
		return NULL;
	}
	int total_lines = r_list_length (lines);
	int start_line = 0;
	if (cursor) {
		start_line = atoi (cursor);
		if (start_line < 0) {
			start_line = 0;
		}
	}
	int end_line = start_line + page_size;
	if (end_line > total_lines) {
		end_line = total_lines;
	}
	RStrBuf *sb = r_strbuf_new ("");
	int idx = 0;
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		if (idx >= start_line && idx < end_line) {
			if (r_strbuf_length (sb) > 0) {
				r_strbuf_append (sb, "\n");
			}
			r_strbuf_append (sb, line);
		}
		idx++;
	}
	r_list_free (lines);
	char *result = r_strbuf_drain (sb);
	if (has_more) {
		*has_more = end_line < total_lines;
	}
	if (next_cursor) {
		if (end_line < total_lines) {
			*next_cursor = r_str_newf ("%d", end_line);
		} else {
			*next_cursor = NULL;
		}
	}
	return result;
}

static inline int pagination_start_from_cursor(const char *cursor) {
	int start = 0;
	if (cursor) {
		start = atoi (cursor);
		if (start < 0) {
			start = 0;
		}
	}
	return start;
}

static inline int rjson_child_count(const RJson *json) {
	int count = 0;
	const RJson *child;
	if (!json) {
		return 0;
	}
	for (child = json->children.first; child; child = child->next) {
		count++;
	}
	return count;
}

static inline void pj_append_rjson_value(PJ *pj, const RJson *json) {
	const RJson *child;
	if (!json) {
		pj_null (pj);
		return;
	}
	switch (json->type) {
	case R_JSON_NULL:
		pj_null (pj);
		break;
	case R_JSON_BOOLEAN:
		pj_b (pj, json->num.u_value);
		break;
	case R_JSON_INTEGER:
		pj_n (pj, json->num.s_value);
		break;
	case R_JSON_DOUBLE:
		pj_d (pj, json->num.dbl_value);
		break;
	case R_JSON_STRING:
		pj_s (pj, json->str_value);
		break;
	case R_JSON_ARRAY:
		pj_a (pj);
		for (child = json->children.first; child; child = child->next) {
			pj_append_rjson_value (pj, child);
		}
		pj_end (pj);
		break;
	case R_JSON_OBJECT:
		pj_o (pj);
		for (child = json->children.first; child; child = child->next) {
			pj_k (pj, child->key);
			pj_append_rjson_value (pj, child);
		}
		pj_end (pj);
		break;
	}
}

static inline void pagination_set_result(int end, int total, bool *has_more, char **next_cursor) {
	bool more = end < total;
	if (has_more) {
		*has_more = more;
	}
	if (next_cursor) {
		*next_cursor = more? r_str_newf ("%d", end): NULL;
	}
}

static inline void pj_append_rjson_array_page(PJ *pj, const RJson *json, int start, int end) {
	int idx = 0;
	const RJson *child;
	pj_a (pj);
	for (child = json->children.first; child; child = child->next) {
		if (idx >= start && idx < end) {
			pj_append_rjson_value (pj, child);
		}
		idx++;
	}
	pj_end (pj);
}

static inline const RJson *rjson_largest_array_child(const RJson *json, int *count_out) {
	const RJson *child;
	const RJson *best = NULL;
	int best_count = 0;
	if (count_out) {
		*count_out = 0;
	}
	if (!json || json->type != R_JSON_OBJECT) {
		return NULL;
	}
	for (child = json->children.first; child; child = child->next) {
		if (child->type == R_JSON_ARRAY) {
			int count = rjson_child_count (child);
			if (!best || count > best_count) {
				best = child;
				best_count = count;
			}
		}
	}
	if (count_out) {
		*count_out = best_count;
	}
	return best;
}

static inline void pj_append_rjson_object_with_array_page(PJ *pj, const RJson *json, const RJson *paged_array, int start, int end) {
	const RJson *child;
	pj_o (pj);
	for (child = json->children.first; child; child = child->next) {
		pj_k (pj, child->key);
		if (child == paged_array) {
			pj_append_rjson_array_page (pj, child, start, end);
		} else {
			pj_append_rjson_value (pj, child);
		}
	}
	pj_end (pj);
}

static inline char *paginate_json_value(const RJson *json, const char *cursor, int page_size, bool *has_more, char **next_cursor) {
	PJ *pj;
	int total;
	int start;
	int end;
	const RJson *paged_array = NULL;
	if (!json) {
		return NULL;
	}
	start = pagination_start_from_cursor (cursor);
	if (page_size <= 0) {
		page_size = R2MCP_DEFAULT_PAGE_SIZE;
	}
	if (page_size > R2MCP_MAX_PAGE_SIZE) {
		page_size = R2MCP_MAX_PAGE_SIZE;
	}
	if (json->type == R_JSON_ARRAY) {
		total = rjson_child_count (json);
		end = R_MIN (start + page_size, total);
		pj = pj_new ();
		pj_append_rjson_array_page (pj, json, start, end);
		pagination_set_result (end, total, has_more, next_cursor);
		return pj_drain (pj);
	}
	if (json->type == R_JSON_OBJECT) {
		paged_array = rjson_largest_array_child (json, &total);
		if (paged_array && (total > page_size || start > 0)) {
			end = R_MIN (start + page_size, total);
			pj = pj_new ();
			pj_append_rjson_object_with_array_page (pj, json, paged_array, start, end);
			pagination_set_result (end, total, has_more, next_cursor);
			return pj_drain (pj);
		}
	}
	pj = pj_new ();
	pj_append_rjson_value (pj, json);
	pagination_set_result (0, 0, has_more, next_cursor);
	return pj_drain (pj);
}

// Intentionally no generic require_str_param helper; callers validate params inline
