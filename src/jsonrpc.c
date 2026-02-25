/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include "jsonrpc.h"

// Helper function to create a simple text tool result
char *jsonrpc_tooltext_response(const char *text) {
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
char *jsonrpc_tooltext_response_paginated(const char *text, bool has_more, const char *next_cursor) {
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
char *jsonrpc_tooltext_response_lines(const char *text) {
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

// JSON-RPC error response builder. Returns heap-allocated JSON string (caller frees).
char *jsonrpc_error_response(int code, const char *message, const char *id, const char *uri) {
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

// Create a proper success response
char *jsonrpc_success_response(ServerState *ss, const char *result, const char *id) {
	(void)ss; // unused now, kept for API consistency
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");

	if (id) {
		// If id is a number string, treat it as a number
		char *endptr;
		long num_id = strtol (id, &endptr, 10);
		if (*id != '\0' && *endptr == '\0') {
			// It's a valid number
			pj_kn (pj, "id", num_id);
		} else {
			// It's a string
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

// Standardized error response helpers for consistent error handling
char *jsonrpc_error_missing_param(const char *param_name) {
	char *msg = r_str_newf ("Missing required parameter: %s", param_name);
	char *err = jsonrpc_error_response (-32602, msg, NULL, NULL);
	free (msg);
	return err;
}

char *jsonrpc_error_tool_not_allowed(const char *tool_name) {
	char *msg = r_str_newf ("Tool '%s' not available in current mode (use -p for permissive)", tool_name);
	char *err = jsonrpc_error_response (-32611, msg, NULL, NULL);
	free (msg);
	return err;
}

char *jsonrpc_error_file_required(void) {
	return jsonrpc_error_response (-32611, "Use the open_file method before calling any other method", NULL, NULL);
}
