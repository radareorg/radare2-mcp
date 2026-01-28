/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include "r2mcp.h"
// Simple DSL runner for invoking tools from the CLI for testing.
// DSL grammar (very small):
//   program := stmt (';' stmt)*
//   stmt := TOOLNAME (WS key=val)*
// Values may be quoted with double-quotes. Keys/values do not support
// nested structures. Example:
//   open_file file_path="/bin/ls"; list_functions only_named=true; close_file
char *tools_call(ServerState *ss, const char *tool_name, RJson *tool_args);
// Parse a single statement of the form: toolName [key=val ...]
// Returns 0 on success.
static int run_statement(ServerState *ss, char *stmt, RCore *core) {
	r_str_trim (stmt);
	if (R_STR_ISEMPTY (stmt)) {
		return 0;
	}
	// extract tool name (first token up to whitespace)
	char *p = stmt;
	while (*p && !isspace ((unsigned char)*p)) {
		p++;
	}
	char saved = *p;
	if (saved) {
		*p++ = '\0';
	}
	const char *tool = stmt;
	RStrBuf *sb = r_strbuf_new ("{");
	bool first = true;
	// parse key=val tokens
	while (*p) {
		p = (char *)r_str_trim_head_ro (p);
		if (!*p) {
			break;
		}
		// key
		char *key = p;
		// advance to '=' or whitespace
		while (*p && *p != '=' && !isspace ((ut8)*p)) {
			p++;
		}
		if (!*p || *p != '=') {
			// no key=value, treat rest as error or ignore
			break;
		}
		*p++ = '\0';
		// value
		char *val = p;
		if (*p == '"') {
			p++;
			val = p;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1]) {
					p += 2;
				} else {
					p++;
				}
			}
			if (*p == '"') {
				*p++ = '\0';
			}
		} else {
			p = (char *)r_str_trim_head_ro (p);
			if (*p) {
				*p++ = '\0';
			}
		}
		// append to JSON
		if (!first) {
			r_strbuf_append (sb, ",");
		}
		first = false;
		// determine if val is a bare true/false or number
		bool bare = false;
		if (!strcmp (val, "true") || !strcmp (val, "false")) {
			bare = true;
		} else {
			// check if integer
			char *q = (char *)val;
			bool digits = true;
			if (*q == '-' || *q == '+') {
				q++;
			}
			while (*q) {
				if (!isdigit ((ut8)*q)) {
					digits = false;
					break;
				}
				q++;
			}
			if (digits && *val) {
				bare = true;
			}
		}
		if (bare) {
			r_strbuf_appendf (sb, "\"%s\":%s", key, val);
		} else {
			char *esc = strdup (val); // r_str_escape_json (val, -1);
			r_strbuf_appendf (sb, "\"%s\":\"%s\"", key, esc);
			free (esc);
		}
	}
	// no need to restore the separator char
	r_strbuf_append (sb, "}");
	char *jsonbuf = r_strbuf_drain (sb);
	// debug: built args JSON (left commented intentionally)
	// printf ("[DSL] args json: %s\n", jsonbuf);
	RJson *args = NULL;
	if (strlen (jsonbuf) > 2) {
		// parse it (parser does not take ownership; keep jsonbuf alive until free)
		args = r_json_parse (jsonbuf);
		if (!args) {
			printf ("[DSL] Failed to parse arguments for tool %s\n", tool);
			free (jsonbuf);
			return -1;
		}
	}
	// call the tool
	char *res = tools_call (ss, tool, args);
	if (args) {
		r_json_free (args);
	}
	if (res) {
		if (core) {
			// Extract text from JSON response
			const char *text_start = strstr (res, "\"text\":\"");
			if (text_start) {
				text_start += 8; // skip "text":"
				const char *text_end = strstr (text_start, "\"");
				if (text_end) {
					char *text = r_str_ndup (text_start, text_end - text_start);
					r_str_replace_in (text, -1, "\\n", "\n", true);
					r_cons_printf ("%s\n", text);
					free (text);
				} else {
					r_cons_printf ("(malformed text in response)\n");
				}
			} else {
				r_cons_printf ("(no text in response)\n");
			}
		} else {
			printf ("[DSL] %s -> %s\n", tool, res);
		}
		free (res);
	} else {
		if (core) {
			r_cons_printf ("(no result)\n");
		} else {
			printf ("[DSL] %s -> (no result)\n", tool);
		}
	}
	free (jsonbuf);
	return 0;
}

int r2mcp_run_dsl_tests(ServerState *ss, const char *dsl, RCore *core) {
	R_RETURN_VAL_IF_FAIL (dsl, 1);
	char *copy = strdup (dsl);
	char *cur = copy;
	char *semi;
	int rc = 0;
	while ((semi = strchr (cur, ';')) != NULL) {
		*semi = '\0';
		if (run_statement (ss, cur, core) != 0) {
			rc = 1;
		}
		cur = semi + 1;
	}
	if (*cur) {
		if (run_statement (ss, cur, core) != 0) {
			rc = 1;
		}
	}
	free (copy);
	return rc;
}
