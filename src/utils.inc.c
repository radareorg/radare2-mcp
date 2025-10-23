// Helper function to create a simple text tool result
static inline char *jsonrpc_tooltext_response(const char *text) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", text);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

// Helper function to create a paginated text tool result
static inline char *jsonrpc_tooltext_response_paginated(const char *text, bool has_more, const char *next_cursor) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", text);
	pj_end (pj);
	pj_end (pj);
	if (has_more || next_cursor) {
		pj_k (pj, "pagination");
		pj_o (pj);
		if (has_more) {
			pj_kb (pj, "hasMore", true);
		}
		if (next_cursor) {
			pj_ks (pj, "nextCursor", next_cursor);
		}
		pj_end (pj);
	}
	pj_end (pj);
	return pj_drain (pj);
}

// Render tool output as a JSON array of lines for frontend filtering compatibility
static inline char *jsonrpc_tooltext_response_lines(const char *text) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "content");
	pj_a (pj);
	if (text) {
		RList *lines = r_str_split_list ((char *)text, "\n", 0);
		if (lines) {
			RListIter *it;
			char *line;
			r_list_foreach (lines, it, line) {
				pj_s (pj, line);
			}
			r_list_free (lines);
		}
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

#if R2_VERSION_NUMBER < 50909
static st64 r_json_get_num(const RJson *json, const char *key) {
	if (!json || !key) {
		return 0;
	}

	const RJson *field = r_json_get (json, key);
	if (!field) {
		return 0;
	}
	switch (field->type) {
	case R_JSON_STRING:
		return r_num_get (NULL, field->str_value);
	case R_JSON_INTEGER:
		return field->num.s_value;
	case R_JSON_BOOLEAN:
		return field->num.u_value;
	case R_JSON_DOUBLE:
		return (int)field->num.dbl_value;
	default:
		return 0;
	}
}

static const char *r_json_get_str(const RJson *json, const char *key) {
	if (!json || !key) {
		return NULL;
	}

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
		return NULL;
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

// JSON-RPC error response builder. Returns heap-allocated JSON string (caller frees).
static char *jsonrpc_error_response(int code, const char *message, const char *id, const char *uri) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");
	if (id) {
		pj_ks (pj, "id", id);
	}
	pj_k (pj, "error");
	pj_o (pj);
	pj_ki (pj, "code", code);
	pj_ks (pj, "message", message);
	if (uri) {
		pj_k (pj, "data");
		pj_o (pj);
		pj_ks (pj, "uri", uri);
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

// Intentionally no generic require_str_param helper; callers validate params inline
