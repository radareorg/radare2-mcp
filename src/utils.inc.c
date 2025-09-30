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
