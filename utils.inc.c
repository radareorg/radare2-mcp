// Set buffering modes for stdin/stdout
static void set_nonblocking_io(bool nonblocking) {
	// Set stdin/stdout to blocking or non-blocking mode
	int flags = fcntl (STDIN_FILENO, F_GETFL, 0);
	if (nonblocking) {
		fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	} else {
		fcntl (STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
	}

	// Set stdout to line buffered mode
	setvbuf (stdout, NULL, _IOLBF, 0);
}
// Helper function to create a simple text tool result
static char *jsonrpc_tooltext_response(const char *text) {
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

#if R2_VERSION_NUMBER  < 50909
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

