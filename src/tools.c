#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"
#include <r_util/pj.h>
#include "utils.inc.c" // bring in shared helpers like jsonrpc_tooltext_response

// Standardized error response helpers for consistent error handling
static inline char *jsonrpc_error_missing_param(const char *param_name) {
	char *msg = r_str_newf ("Missing required parameter: %s", param_name);
	char *err = jsonrpc_error_response (-32602, msg, NULL, NULL);
	free (msg);
	return err;
}

#if 0
static inline char *jsonrpc_error_invalid_param(const char *param_name, const char *reason) {
	char *msg = r_str_newf ("Invalid parameter '%s': %s", param_name, reason);
	char *err = jsonrpc_error_response (-32602, msg, NULL, NULL);
	free (msg);
	return err;
}
#endif

static inline char *jsonrpc_error_tool_not_allowed(const char *tool_name) {
	char *msg = r_str_newf ("Tool '%s' not available in current mode (use -p for permissive)", tool_name);
	char *err = jsonrpc_error_response (-32611, msg, NULL, NULL);
	free (msg);
	return err;
}

static inline char *jsonrpc_error_file_required(void) {
	return jsonrpc_error_response (-32611, "Use the open_file method before calling any other method", NULL, NULL);
}

// Parameter validation helpers
static inline bool validate_required_string_param(RJson *args, const char *param_name, const char **out_value) {
	const char *value = r_json_get_str (args, param_name);
	if (!value) {
		return false;
	}
	*out_value = value;
	return true;
}

static inline bool validate_address_param(RJson *args, const char *param_name, const char **out_address) {
	return validate_required_string_param (args, param_name, out_address);
}

static void pj_append_rjson(PJ *pj, RJson *j) {
	if (!j) {
		pj_null (pj);
		return;
	}
	switch (j->type) {
	case R_JSON_NULL:
		pj_null (pj);
		break;
	case R_JSON_BOOLEAN:
		pj_b (pj, j->num.u_value);
		break;
	case R_JSON_INTEGER:
		pj_n (pj, j->num.s_value);
		break;
	case R_JSON_DOUBLE:
		pj_d (pj, j->num.dbl_value);
		break;
	case R_JSON_STRING:
		pj_s (pj, j->str_value);
		break;
	case R_JSON_ARRAY:
		pj_a (pj);
		RJson *child = j->children.first;
		while (child) {
			pj_append_rjson (pj, child);
			child = child->next;
		}
		pj_end (pj);
		break;
	case R_JSON_OBJECT:
		pj_o (pj);
		child = j->children.first;
		while (child) {
			pj_k (pj, child->key);
			pj_append_rjson (pj, child);
			child = child->next;
		}
		pj_end (pj);
		break;
	}
}

// Check an optional whitelist of enabled tool names. If ss->enabled_tools is
// NULL, all tools are considered allowed. Otherwise only names present in the
// list are allowed.
static bool tool_allowed_by_whitelist(const ServerState *ss, const char *name) {
	if (!ss || !ss->enabled_tools) {
		return true;
	}
	RListIter *it;
	const char *s;
	r_list_foreach (ss->enabled_tools, it, s) {
		if (!strcmp (s, name)) {
			return true;
		}
	}
	return false;
}

static inline ToolMode current_mode(const ServerState *ss) {
	if (ss->http_mode) {
		return TOOL_MODE_HTTP;
	}
	if (ss->readonly_mode) {
		return TOOL_MODE_RO;
	}
	if (ss->minimode) {
		return TOOL_MODE_MINI;
	}
	return TOOL_MODE_NORMAL;
}

static ToolSpec *tool(const char *name, const char *desc, const char *schema, int modes) {
	ToolSpec *t = R_NEW0 (ToolSpec);
	t->name = name;
	t->description = desc;
	t->schema_json = schema;
	t->modes = modes;
	return t;
}

void tools_registry_init(ServerState *ss) {
	if (ss->tools) {
		return; // already initialized
	}
	ss->tools = r_list_newf (free);
	if (!ss->tools) {
		return;
	}

	// Modes convenience
	const int M_MINI = TOOL_MODE_MINI;
	const int M_HTTP = TOOL_MODE_HTTP;
	const int M_RO = TOOL_MODE_RO;

	// Normal mode: full set
	r_list_append (ss->tools, tool ("open_file", "Opens a binary file with radare2 for analysis <think>Call this tool before any other one from r2mcp. Use an absolute file_path</think>", "{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"file_path\"]}", TOOL_MODE_NORMAL | M_MINI));

	if (ss->enable_run_command_tool) {
		r_list_append (ss->tools, tool ("run_javascript", "Executes JavaScript code using radare2's qjs runtime", "{\"type\":\"object\",\"properties\":{\"script\":{\"type\":\"string\",\"description\":\"The JavaScript code to execute\"}},\"required\":[\"script\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));
		r_list_append (ss->tools, tool ("run_command", "Executes a raw radare2 command directly", "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"The radare2 command to execute\"}},\"required\":[\"command\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));
	}

	r_list_append (ss->tools, tool ("close_file", "Close the currently open file", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append (ss->tools, tool ("list_functions", "Lists all functions discovered during analysis", "{\"type\":\"object\",\"properties\":{\"only_named\":{\"type\":\"boolean\",\"description\":\"If true, only list functions with named symbols (excludes functions with numeric suffixes like sym.func.1000016c8)\"}}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));
	r_list_append (ss->tools, tool ("list_functions_tree", "Lists functions and successors (aflmu)", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_libraries", "Lists all shared libraries linked to the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_imports", "Lists imported symbols (note: use list_symbols for addresses with sym.imp. prefix)", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_sections", "Displays memory sections and segments from the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("show_function_details", "Displays detailed information about the current function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("get_current_address", "Shows the current position and function name", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("show_headers", "Displays binary headers and file information", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_symbols", "Shows all symbols (functions, variables, imports) with addresses", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_entrypoints", "Displays program entrypoints, constructors and main function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_methods", "Lists all methods belonging to the specified class", "{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list methods for\"}},\"required\":[\"classname\"]}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("list_classes", "Lists class names from various languages (C++, ObjC, Swift, Java, Dalvik)", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("list_decompilers", "Shows all available decompiler backends", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("rename_function", "Renames the function at the specified address", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"New function name\"},\"address\":{\"type\":\"string\",\"description\":\"Address of the function to rename\"}},\"required\":[\"name\",\"address\"]}", TOOL_MODE_NORMAL));
	r_list_append (ss->tools, tool ("rename_flag", "Renames a local variable or data reference within the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the flag containing the variable or data reference\"},\"name\":{\"type\":\"string\",\"description\":\"Current variable name or data reference\"},\"new_name\":{\"type\":\"string\",\"description\":\"New variable name or data reference\"}},\"required\":[\"address\",\"name\",\"new_name\"]}", TOOL_MODE_NORMAL | M_HTTP));

	r_list_append (ss->tools, tool ("use_decompiler", "Selects which decompiler backend to use (default: pdc)", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}", TOOL_MODE_NORMAL));

	r_list_append (ss->tools, tool ("get_function_prototype", "Retrieves the function signature at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("set_function_prototype", "Sets the function signature (return type, name, arguments)", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"},\"prototype\":{\"type\":\"string\",\"description\":\"Function signature in C-like syntax\"}},\"required\":[\"address\",\"prototype\"]}", TOOL_MODE_NORMAL));

	r_list_append (ss->tools, tool ("set_comment", "Adds a comment at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"message\":{\"type\":\"string\",\"description\":\"Comment text to use\"}},\"required\":[\"address\",\"message\"]}", TOOL_MODE_NORMAL | M_HTTP));

	r_list_append (ss->tools, tool ("list_strings", "Lists strings from data sections with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_all_strings", "Scans the entire binary for strings with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}}}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("analyze", "Runs binary analysis with optional depth level", "{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0-4, higher is more thorough)\"}},\"required\":[]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append (ss->tools, tool ("xrefs_to", "Finds all code references to the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to check for cross-references\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("decompile_function", "Show C-like pseudocode of the function in the given address. <think>Use this to inspect the code in a function, do not run multiple times in the same offset</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("list_files", "Lists files in the specified path using radare2's ls -q command. Files ending with / are directories, otherwise they are files.", "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Path to list files from\"}},\"required\":[\"path\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP | M_RO));

	r_list_append (ss->tools, tool ("disassemble_function", "Shows assembly listing of the function at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("disassemble", "Disassembles a specific number of instructions from an address <think>Use this tool to inspect a portion of memory as code without depending on function analysis boundaries. Use this tool when functions are large and you are only interested on few instructions</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"num_instructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble (default: 10)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_RO));

	r_list_append (ss->tools, tool ("calculate", "Evaluate a math expression using core->num (r_num_math). Usecases: do proper 64-bit math, resolve addresses for flag names/symbols, and avoid hallucinated results.", "{\"type\":\"object\",\"properties\":{\"expression\":{\"type\":\"string\",\"description\":\"Math expression to evaluate (eg. 0x100 + sym.flag - 4)\"}},\"required\":[\"expression\"]}", TOOL_MODE_NORMAL | M_MINI | M_RO));
}

void tools_registry_fini(ServerState *ss) {
	if (ss && ss->tools) {
		r_list_free (ss->tools);
		ss->tools = NULL;
	}
}

static bool tool_matches_mode(const ToolSpec *t, ToolMode mode) {
	return (t->modes & mode) != 0;
}

static RList *tools_filtered_for_mode(const ServerState *ss) {
	ToolMode mode = current_mode (ss);
	RList *out = r_list_new ();
	if (!out) {
		return NULL;
	}
	RListIter *it;
	ToolSpec *t;
	r_list_foreach (ss->tools, it, t) {
		if (tool_matches_mode (t, mode) && tool_allowed_by_whitelist (ss, t->name)) {
			r_list_append (out, t); // reference only
		}
	}
	return out;
}

bool tools_is_tool_allowed(const ServerState *ss, const char *name) {
	if (ss->permissive_tools) {
		return true;
	}
	if (!ss->tools || !name) {
		return false;
	}
	ToolMode mode = current_mode (ss);
	RListIter *it;
	ToolSpec *t;
	r_list_foreach (ss->tools, it, t) {
		if (!strcmp (t->name, name)) {
			if (!tool_allowed_by_whitelist (ss, name)) {
				return false;
			}
			return tool_matches_mode (t, mode);
		}
	}
	return false;
}

char *tools_build_catalog_json(const ServerState *ss, const char *cursor, int page_size) {
	if (!ss->tools) {
		return strdup ("{\"tools\":[]}");
	}

	int start_index = 0;
	if (cursor) {
		start_index = atoi (cursor);
		if (start_index < 0) {
			start_index = 0;
		}
	}

	RList *list = tools_filtered_for_mode (ss);
	if (!list) {
		return strdup ("{\"tools\":[]}");
	}
	int total_tools = r_list_length (list);
	int end_index = start_index + page_size;
	if (end_index > total_tools) {
		end_index = total_tools;
	}

	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "{\"tools\":[");

	int idx = 0;
	int out_count = 0;
	RListIter *it;
	ToolSpec *t;
	r_list_foreach (list, it, t) {
		if (idx >= start_index && idx < end_index) {
			if (out_count > 0) {
				r_strbuf_append (sb, ",");
			}
			r_strbuf_appendf (sb,
				"{\"name\":\"%s\",\"description\":\"%s\",\"inputSchema\":%s}",
				t->name, t->description, t->schema_json);
			out_count++;
		}
		idx++;
		if (idx >= end_index) {
			// keep looping for correctness of idx but we could break
		}
	}

	r_strbuf_append (sb, "]");
	if (end_index < total_tools) {
		r_strbuf_appendf (sb, ",\"nextCursor\":\"%d\"", end_index);
	}
	r_strbuf_append (sb, "}");

	r_list_free (list);
	return r_strbuf_drain (sb);
}

void tools_print_table(const ServerState *ss) {
	if (!ss || !ss->tools) {
		R_LOG_ERROR ("No tools registered");
		return;
	}

	RTable *table = r_table_new ("tools");
	if (!table) {
		R_LOG_ERROR ("Failed to allocate table");
		return;
	}

	RTableColumnType *s = r_table_type ("string");
	if (!s) {
		R_LOG_WARN ("Table string type unavailable");
		r_table_free (table);
		return;
	}

	r_table_add_column (table, s, "name", 0);
	r_table_add_column (table, s, "modes", 0);
	r_table_add_column (table, s, "description", 0);

	RListIter *it;
	ToolSpec *t;
	r_list_foreach (ss->tools, it, t) {
		char modes_buf[8];
		int p = 0;
		if (t->modes & TOOL_MODE_MINI) {
			modes_buf[p++] = 'M';
		}
		if (t->modes & TOOL_MODE_HTTP) {
			modes_buf[p++] = 'H';
		}
		if (t->modes & TOOL_MODE_RO) {
			modes_buf[p++] = 'R';
		}
		if (t->modes & TOOL_MODE_NORMAL) {
			modes_buf[p++] = 'N';
		}
		modes_buf[p] = '\0';
		const char *desc = t->description? t->description: "";
		r_table_add_rowf (table, "sss", t->name, modes_buf, desc);
	}

	char *table_str = r_table_tostring (table);
	if (table_str) {
		printf ("%s\n", table_str);
		free (table_str);
	}
	r_table_free (table);
}

// Filter lines in `input` by `pattern` regex. Returns a newly allocated string.
static char *filter_lines_by_regex(const char *input, const char *pattern) {
	const char *src = input? input: "";
	if (!pattern || !*pattern) {
		return strdup (src);
	}
	RStrBuf *sb = r_strbuf_new ("");
	RRegex rx;
	int re_flags = r_regex_flags ("e");
	if (r_regex_init (&rx, pattern, re_flags) != 0) {
		r_strbuf_appendf (sb, "Invalid regex used in filter parameter, try a simpler expression");
		return r_strbuf_drain (sb);
	}
	const char *line_begin = src;
	const char *p = src;
	for (;;) {
		if (*p == '\n' || *p == '\0') {
			size_t len = (size_t) (p - line_begin);
			char *line = (char *)malloc (len + 1);
			if (!line) {
				break;
			}
			memcpy (line, line_begin, len);
			line[len] = '\0';
			if (r_regex_exec (&rx, line, 0, 0, 0) == 0) {
				r_strbuf_appendf (sb, "%s\n", line);
			}
			free (line);
			if (*p == '\0') {
				break;
			}
			p++;
			line_begin = p;
			continue;
		}
		p++;
	}
	r_regex_fini (&rx);
	return r_strbuf_drain (sb);
}

static char *filter_named_functions_only(const char *input) {
	const char *src = input? input: "";
	RStrBuf *sb = r_strbuf_new ("");
	const char *line_begin = src;
	const char *p = src;
	for (;;) {
		if (*p == '\n' || *p == '\0') {
			size_t len = (size_t) (p - line_begin);
			char *line = (char *)malloc (len + 1);
			if (!line) {
				break;
			}
			memcpy (line, line_begin, len);
			line[len] = '\0';
			bool is_named = true;
			const char *last_dot = r_str_lchr (line, '.');
			if (last_dot && last_dot[1]) {
				if (isdigit (last_dot[1])) {
					is_named = false;
				}
			}
			if (is_named) {
				r_strbuf_appendf (sb, "%s\n", line);
			}
			free (line);
			if (*p == '\0') {
				break;
			}
			p++;
			line_begin = p;
			continue;
		}
		p++;
	}
	return r_strbuf_drain (sb);
}

// Main dispatcher that handles tool calls. Returns heap-allocated JSON
// string representing the tool "result" (caller must free it).
char *tools_call(ServerState *ss, const char *tool_name, RJson *tool_args) {
	RJson nil = { 0 };
	if (!tool_args) {
		tool_args = &nil;
	}
	if (!tool_name) {
		return jsonrpc_error_missing_param ("name");
	}
	// Enforce tool availability per mode unless permissive is enabled
	if (!tools_is_tool_allowed (ss, tool_name)) {
		return jsonrpc_error_tool_not_allowed (tool_name);
	}

	// Supervisor control check
	if (ss->svc_baseurl) {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "tool", tool_name);
		pj_k (pj, "arguments");
		pj_append_rjson (pj, tool_args);
		pj_k (pj, "available_tools");
		pj_a (pj);
		RListIter *iter;
		ToolSpec *ts;
		r_list_foreach (ss->tools, iter, ts) {
			pj_s (pj, ts->name);
		}
		pj_end (pj);
		pj_end (pj);
		char *req = pj_drain (pj);
		int rc;
		char *resp = curl_post_capture (ss->svc_baseurl, req, &rc);
		free (req);
		if (resp && rc == 0) {
			RJson *rj = r_json_parse (resp);
			free (resp);
			if (rj) {
				const char *err = r_json_get_str (rj, "error");
				if (err) {
					r_json_free (rj);
					return jsonrpc_error_response (-32000, err, NULL, NULL);
				}
				const char *r2cmd = r_json_get_str (rj, "r2cmd");
				if (r2cmd) {
					char *cmd_out = r2mcp_cmd (ss, r2cmd);
					char *res = jsonrpc_tooltext_response (cmd_out? cmd_out: "");
					free (cmd_out);
					// If the original tool was open_file, assume the r2cmd opened the file
					if (!strcmp (tool_name, "open_file")) {
						const char *filepath = r_json_get_str (tool_args, "file_path");
						if (filepath) {
							free (ss->rstate.current_file);
							ss->rstate.current_file = strdup (filepath);
							ss->rstate.file_opened = true;
						}
					}
					r_json_free (rj);
					return res;
				}
				const char *new_tool = r_json_get_str (rj, "tool");
				const RJson *new_args = r_json_get (rj, "arguments");
				if (new_tool && strcmp (new_tool, tool_name)) {
					tool_name = strdup (new_tool);
				}
				if (new_args) {
					tool_args = (RJson *)new_args;
				}
				// r_json_free (rj); // Keep alive for tool_args
			}
		}
	}

	// Special-case: open_file
	if (!strcmp (tool_name, "open_file")) {
		if (ss->http_mode) {
			char *res = r2mcp_cmd (ss, "i");
			char *foo = r_str_newf ("File was already opened, this are the details:\n%s", res);
			char *out = jsonrpc_tooltext_response (foo);
			free (res);
			free (foo);
			return out;
		}
		const char *filepath;
		if (!validate_required_string_param (tool_args, "file_path", &filepath)) {
			return jsonrpc_error_missing_param ("file_path");
		}

		char *filteredpath = strdup (filepath);
		r_str_replace_ch (filteredpath, '`', 0, true);
		bool success = r2mcp_open_file (ss, filteredpath);
		free (filteredpath);
		return jsonrpc_tooltext_response (success? "File opened successfully.": "Failed to open file.");
	}

	if (!ss->http_mode && !ss->rstate.file_opened) {
		return jsonrpc_error_file_required ();
	}

	// Map simple tools to commands or handlers
	if (!strcmp (tool_name, "list_methods")) {
		const char *classname;
		if (!validate_required_string_param (tool_args, "classname", &classname)) {
			return jsonrpc_error_missing_param ("classname");
		}
		char *res = r2mcp_cmdf (ss, "'ic %s", classname);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_files")) {
		const char *path;
		if (!validate_required_string_param (tool_args, "path", &path)) {
			return jsonrpc_error_missing_param ("path");
		}

		// Security checks
		if (!path || path[0] != '/') {
			return jsonrpc_error_response (-32603, "Relative paths are not allowed. Use an absolute path", NULL, NULL);
		}
		if (strstr (path, "/../") != NULL) {
			return jsonrpc_error_response (-32603, "Path traversal is not allowed (contains '/../')", NULL, NULL);
		}
		if (ss->sandbox && *ss->sandbox) {
			size_t plen = strlen (path);
			size_t slen = strlen (ss->sandbox);
			if (slen == 0 || slen > plen || strncmp (path, ss->sandbox, slen) != 0 ||
				(plen > slen && path[slen] != '/')) {
				return jsonrpc_error_response (-32603, "Access denied: path is outside of the sandbox", NULL, NULL);
			}
		}

		char *cmd = r_str_newf ("ls -q %s", path);
		char *res = r2mcp_cmd (ss, cmd);
		free (cmd);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_classes")) {
		const char *filter = r_json_get_str (tool_args, "filter");
		char *res = r2mcp_cmd (ss, "icqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			char *r = filter_lines_by_regex (res, filter);
			free (res);
			res = r;
		}
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_decompilers")) {
		char *res = r2mcp_cmd (ss, "e cmd.pdc=?");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_functions")) {
		const RJson *only_named_parameter = r_json_get (tool_args, "only_named");
		bool only_named = false;
		if (only_named_parameter) {
			if (only_named_parameter->type == R_JSON_BOOLEAN) {
				only_named = only_named_parameter->num.u_value;
			}
		}
		char *res = r2mcp_cmd (ss, "afl,addr/cols/name");
		r_str_trim (res);
		if (R_STR_ISEMPTY (res)) {
			free (res);
			free (r2mcp_cmd (ss, "aaa"));
			res = r2mcp_cmd (ss, "afl,addr/cols/name");
			r_str_trim (res);
			if (R_STR_ISEMPTY (res)) {
				free (res);
				res = strdup ("No functions found. Run the analysis first.");
			}
		}
		// Apply filtering if only_named is true
		if (only_named && res && !R_STR_ISEMPTY (res)) {
			char *filtered = filter_named_functions_only (res);
			if (filtered) {
				free (res);
				res = filtered;
			}
		}
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_functions_tree")) {
		char *res = r2mcp_cmd (ss, "aflmu");
		r_str_trim (res);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_imports")) {
		char *res = r2mcp_cmd (ss, "iiq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_sections")) {
		char *res = r2mcp_cmd (ss, "iS;iSS");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "show_headers")) {
		char *res = r2mcp_cmd (ss, "i;iH");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "show_function_details")) {
		char *res = r2mcp_cmd (ss, "afi");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "get_current_address")) {
		char *res = r2mcp_cmd (ss, "s;fd");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_symbols")) {
		char *res = r2mcp_cmd (ss, "isq~!func.,!imp.");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_entrypoints")) {
		char *res = r2mcp_cmd (ss, "ies");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "list_libraries")) {
		char *res = r2mcp_cmd (ss, "ilq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	if (!strcmp (tool_name, "calculate")) {
		const char *expression;
		if (!validate_required_string_param (tool_args, "expression", &expression)) {
			return jsonrpc_error_missing_param ("expression");
		}
		if (!ss->rstate.core || !ss->rstate.core->num) {
			return jsonrpc_error_response (-32611, "Core or number parser unavailable (open a file first)", NULL, NULL);
		}
		RCore *core = ss->rstate.core;
		ut64 result = r_num_math (core->num, expression);
		char *numstr = r_str_newf ("0x%" PFMT64x, (ut64)result);
		char *resp = jsonrpc_tooltext_response (numstr);
		free (numstr);
		return resp;
	}
	if (!strcmp (tool_name, "close_file")) {
		if (ss->http_mode) {
			return jsonrpc_tooltext_response ("In r2pipe mode we won't close the file.");
		}
		if (ss->rstate.core) {
			free (r2mcp_cmd (ss, "o-*"));
			ss->rstate.file_opened = false;
			free (ss->rstate.current_file);
			ss->rstate.current_file = NULL;
		}
		return jsonrpc_tooltext_response ("File closed successfully.");
	}

	if (!strcmp (tool_name, "set_comment")) {
		const char *address, *message;
		if (!validate_address_param (tool_args, "address", &address) ||
			!validate_required_string_param (tool_args, "message", &message)) {
			return jsonrpc_error_missing_param ("address and message");
		}

		char *cmd_cc = r_str_newf ("'@%s'CC %s", address, message);
		char *tmpres_cc = r2mcp_cmd (ss, cmd_cc);
		free (tmpres_cc);
		free (cmd_cc);
		return strdup ("ok");
	}

	if (!strcmp (tool_name, "set_function_prototype")) {
		const char *address, *prototype;
		if (!validate_address_param (tool_args, "address", &address) ||
			!validate_required_string_param (tool_args, "prototype", &prototype)) {
			return jsonrpc_error_missing_param ("address and prototype");
		}
		char *cmd_afs = r_str_newf ("'@%s'afs %s", address, prototype);
		char *tmpres_afs = r2mcp_cmd (ss, cmd_afs);
		free (tmpres_afs);
		free (cmd_afs);
		return strdup ("ok");
	}

	if (!strcmp (tool_name, "get_function_prototype")) {
		const char *address;
		if (!validate_address_param (tool_args, "address", &address)) {
			return jsonrpc_error_missing_param ("address");
		}
		char *s = r_str_newf ("'@%s'afs", address);
		char *res = r2mcp_cmd (ss, s);
		free (s);
		return res;
	}

	if (!strcmp (tool_name, "list_strings") || !strcmp (tool_name, "list_all_strings")) {
		const char *filter = r_json_get_str (tool_args, "filter");
		const char *cursor = r_json_get_str (tool_args, "cursor");
		int page_size = (int)r_json_get_num (tool_args, "page_size");
		if (page_size <= 0) {
			page_size = R2MCP_DEFAULT_PAGE_SIZE;
		}
		if (page_size > R2MCP_MAX_PAGE_SIZE) {
			page_size = R2MCP_MAX_PAGE_SIZE;
		}

		char *result = r2mcp_cmd (ss, (!strcmp (tool_name, "list_strings")? "izqq": "izzzqq"));
		if (R_STR_ISNOTEMPTY (filter)) {
			char *r = filter_lines_by_regex (result, filter);
			free (result);
			result = r;
		}
		if (!strcmp (tool_name, "list_all_strings") && R_STR_ISEMPTY (result)) {
			free (result);
			result = r_str_newf ("Error: No strings with regex %s", filter);
		}
		bool has_more = false;
		char *next_cursor = NULL;
		char *paginated = paginate_text_by_lines (result, cursor, page_size, &has_more, &next_cursor);
		free (result);
		char *response = jsonrpc_tooltext_response_paginated (paginated, has_more, next_cursor);
		free (paginated);
		free (next_cursor);
		return response;
	}

	if (!strcmp (tool_name, "analyze")) {
		const int level = (int)r_json_get_num (tool_args, "level");
		char *err = r2mcp_analyze (ss, level);
		char *result = r2mcp_cmd (ss, "aflc");
		char *errstr;
		if (R_STR_ISNOTEMPTY (err)) {
			errstr = r_str_newf ("\n\n<log>\n%s\n</log>\n", err);
		} else {
			errstr = strdup ("");
		}
		char *text = r_str_newf ("Analysis completed with level %d.\nFound %d functions.%s", level, atoi (result), errstr);
		char *response = jsonrpc_tooltext_response (text);
		free (err);
		free (errstr);
		free (result);
		free (text);
		return response;
	}

	if (!strcmp (tool_name, "disassemble")) {
		const char *address;
		if (!validate_address_param (tool_args, "address", &address)) {
			return jsonrpc_error_missing_param ("address");
		}

		RJson *num_instr_json = (RJson *)r_json_get (tool_args, "num_instructions");
		int num_instructions = 10;
		if (num_instr_json && num_instr_json->type == R_JSON_INTEGER) {
			num_instructions = (int)num_instr_json->num.u_value;
		}

		char *disasm = r2mcp_cmdf (ss, "'@%s'pd %d", address, num_instructions);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp (tool_name, "use_decompiler")) {
		const char *deco;
		if (!validate_required_string_param (tool_args, "name", &deco)) {
			return jsonrpc_error_missing_param ("name");
		}
		char *decompilersAvailable = r2mcp_cmd (ss, "e cmd.pdc=?");
		const char *response = "ok";
		if (strstr (deco, "ghidra")) {
			if (strstr (decompilersAvailable, "pdg")) {
				free (r2mcp_cmd (ss, "-e cmd.pdc=pdg"));
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "decai")) {
			if (strstr (decompilersAvailable, "decai")) {
				free (r2mcp_cmd (ss, "-e cmd.pdc=decai -d"));
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "r2dec")) {
			if (strstr (decompilersAvailable, "pdd")) {
				free (r2mcp_cmd (ss, "-e cmd.pdc=pdd"));
			} else {
				response = "This decompiler is not available";
			}
		} else {
			response = "Unknown decompiler";
		}
		free (decompilersAvailable);
		return jsonrpc_tooltext_response (response);
	}

	if (!strcmp (tool_name, "xrefs_to")) {
		const char *address;
		if (!validate_address_param (tool_args, "address", &address)) {
			return jsonrpc_error_missing_param ("address");
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'axt", address);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp (tool_name, "disassemble_function")) {
		const char *address;
		if (!validate_address_param (tool_args, "address", &address)) {
			return jsonrpc_error_missing_param ("address");
		}
		const char *cursor = r_json_get_str (tool_args, "cursor");
		int page_size = (int)r_json_get_num (tool_args, "page_size");
		if (page_size <= 0) {
			page_size = R2MCP_DEFAULT_PAGE_SIZE;
		}
		if (page_size > R2MCP_MAX_PAGE_SIZE) {
			page_size = R2MCP_MAX_PAGE_SIZE;
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'pdf", address);
		bool has_more = false;
		char *next_cursor = NULL;
		char *paginated = paginate_text_by_lines (disasm, cursor, page_size, &has_more, &next_cursor);
		free (disasm);
		char *response = jsonrpc_tooltext_response_paginated (paginated, has_more, next_cursor);
		free (paginated);
		free (next_cursor);
		return response;
	}

	if (!strcmp (tool_name, "rename_flag")) {
		const char *address, *name, *new_name;
		if (!validate_address_param (tool_args, "address", &address) ||
			!validate_required_string_param (tool_args, "name", &name) ||
			!validate_required_string_param (tool_args, "new_name", &new_name)) {
			return jsonrpc_error_missing_param ("address, name, and new_name");
		}
		char *remove_res = r2mcp_cmdf (ss, "'@%s'fr %s %s", address, name, new_name);
		if (R_STR_ISNOTEMPTY (remove_res)) {
			char *response = jsonrpc_tooltext_response (remove_res);
			free (remove_res);
			return response;
		}
		free (remove_res);
		return jsonrpc_tooltext_response ("ok");
	}

	if (!strcmp (tool_name, "rename_function")) {
		const char *address, *name;
		if (!validate_address_param (tool_args, "address", &address) ||
			!validate_required_string_param (tool_args, "name", &name)) {
			return jsonrpc_error_missing_param ("address and name");
		}
		free (r2mcp_cmdf (ss, "'@%s'afn %s", address, name));
		return jsonrpc_tooltext_response ("ok");
	}

	if (!strcmp (tool_name, "decompile_function")) {
		const char *address;
		if (!validate_address_param (tool_args, "address", &address)) {
			return jsonrpc_error_missing_param ("address");
		}
		const char *cursor = r_json_get_str (tool_args, "cursor");
		int page_size = (int)r_json_get_num (tool_args, "page_size");
		if (page_size <= 0) {
			page_size = R2MCP_DEFAULT_PAGE_SIZE;
		}
		if (page_size > R2MCP_MAX_PAGE_SIZE) {
			page_size = R2MCP_MAX_PAGE_SIZE;
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'pdc", address);
		bool has_more = false;
		char *next_cursor = NULL;
		char *paginated = paginate_text_by_lines (disasm, cursor, page_size, &has_more, &next_cursor);
		free (disasm);
		char *response = jsonrpc_tooltext_response_paginated (paginated, has_more, next_cursor);
		free (paginated);
		free (next_cursor);
		return response;
	}

	if (ss->enable_run_command_tool) {
		if (!strcmp (tool_name, "run_command")) {
			const char *command;
			if (!validate_required_string_param (tool_args, "command", &command)) {
				return jsonrpc_error_missing_param ("command");
			}
			char *res = r2mcp_cmd (ss, command);
			char *o = jsonrpc_tooltext_response (res);
			free (res);
			return o;
		}
		if (!strcmp (tool_name, "run_javascript")) {
			const char *script;
			if (!validate_required_string_param (tool_args, "script", &script)) {
				return jsonrpc_error_missing_param ("script");
			}
			char *encoded = r_base64_encode_dyn ((const ut8 *)script, strlen (script));
			if (!encoded) {
				return jsonrpc_error_response (-32603, "Failed to encode script", NULL, NULL);
			}
			char *cmd = r_str_newf ("js base64:%s", encoded);
			char *res = r2mcp_cmd (ss, cmd);
			char *o = jsonrpc_tooltext_response (res);
			free (res);
			free (cmd);
			free (encoded);
			return o;
		}
	}

	char *tmp = r_str_newf ("Unknown tool: %s", tool_name);
	char *err = jsonrpc_error_response (-32602, tmp, NULL, NULL);
	free (tmp);
	return err;
}
