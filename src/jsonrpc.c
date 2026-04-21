/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include "jsonrpc.h"

char *jsonrpc_tooltext_response(const char *text) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
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

static void emit_content(PJ *pj, const char *s) {
	R_RETURN_IF_FAIL (s);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", s);
	pj_end (pj);
	pj_end (pj);
}

static void emit_structured(PJ *pj, const char *structured_json, const char *text_fallback) {
	pj_k (pj, "structuredContent");
	if (structured_json) {
		pj_raw (pj, structured_json);
	} else {
		pj_o (pj);
		pj_ks (pj, "content", text_fallback? text_fallback: "");
		pj_end (pj);
	}
}

char *jsonrpc_tool_response(const char *text, const char *structured_json, R2McpContentMode mode) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	switch (mode) {
	case R2MCP_CONTENT_TEXT:
		emit_content (pj, text);
		break;
	case R2MCP_CONTENT_JSON:
		emit_content (pj, structured_json? structured_json: text);
		break;
	case R2MCP_CONTENT_STRUCTURED:
		emit_content (pj, structured_json? structured_json: text);
		emit_structured (pj, structured_json, text);
		break;
	case R2MCP_CONTENT_BOTH:
		emit_content (pj, text);
		emit_structured (pj, structured_json, text);
		break;
	default:
		emit_content (pj, text);
		break;
	}
	pj_end (pj);
	return pj_drain (pj);
}
char *jsonrpc_tool_response_paginated(const char *text, const char *structured_json, R2McpContentMode mode, bool has_more, const char *next_cursor) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	switch (mode) {
	case R2MCP_CONTENT_TEXT:
		emit_content (pj, text);
		break;
	case R2MCP_CONTENT_JSON:
		emit_content (pj, structured_json? structured_json: text);
		break;
	case R2MCP_CONTENT_STRUCTURED:
		emit_content (pj, structured_json? structured_json: text);
		emit_structured (pj, structured_json, text);
		break;
	case R2MCP_CONTENT_BOTH:
		emit_content (pj, text);
		emit_structured (pj, structured_json, text);
		break;
	default:
		emit_content (pj, text);
		break;
	}
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

char *jsonrpc_tooltext_response_paginated(const char *text, bool has_more, const char *next_cursor) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
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

char *jsonrpc_error_response(int code, const char *message, const char *id, const char *uri) {
	R_RETURN_VAL_IF_FAIL (message, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");
	if (id) {
		char *endptr;
		long num_id = strtol (id, &endptr, 10);
		if (*id != '\0' && *endptr == '\0') {
			pj_kn (pj, "id", num_id);
		} else {
			pj_ks (pj, "id", id);
		}
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

char *jsonrpc_success_response(ServerState *ss, const char *result, const char *id) {
	R_RETURN_VAL_IF_FAIL (result, NULL);
	(void)ss;
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");

	if (id) {
		char *endptr;
		long num_id = strtol (id, &endptr, 10);
		if (*id != '\0' && *endptr == '\0') {
			pj_kn (pj, "id", num_id);
		} else {
			pj_ks (pj, "id", id);
		}
	}

	pj_k (pj, "result");
	if (result) {
		pj_raw (pj, result);
	} else {
		pj_null (pj);
	}

	pj_end (pj);
	return pj_drain (pj);
}

char *jsonrpc_error_missing_param(const char *param_name) {
	R_RETURN_VAL_IF_FAIL (param_name, NULL);
	char *msg = r_str_newf ("Missing required parameter: %s", param_name);
	char *err = jsonrpc_error_response (-32602, msg, NULL, NULL);
	free (msg);
	return err;
}

char *jsonrpc_error_tool_not_allowed(const char *tool_name) {
	R_RETURN_VAL_IF_FAIL (tool_name, NULL);
	char *msg = r_str_newf ("Tool '%s' not available in current mode (use -p for permissive)", tool_name);
	char *err = jsonrpc_error_response (-32611, msg, NULL, NULL);
	free (msg);
	return err;
}

char *jsonrpc_error_file_required(void) {
	return jsonrpc_error_response (-32611, "Use the open_file method before calling any other method", NULL, NULL);
}
