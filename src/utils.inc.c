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

// Intentionally no generic require_str_param helper; callers validate params inline
