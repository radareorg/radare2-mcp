/* r2mcp - MIT - Copyright 2025-2026 - pancake */

#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"
#include "validation.h"
#include "path.inc.c"
#include "utils.inc.c"
#include "jsonrpc.h"

typedef char *(*ToolFunc)(ServerState *ss, RJson *tool_args);

typedef struct {
	const char *name;
	ToolFunc func;
} ToolEntry;

extern ToolSpec tool_specs[];

// Parameter validation helpers
static inline bool validate_required_string_param(RJson *args, const char *param_name, const char **out_value) {
	const char *value = r_json_get_str (args, param_name);
	if (value) {
		*out_value = value;
		return true;
	}
	return false;
}

static bool validate_address_param(RJson *args, const char *param_name, const char **out_address) {
	return validate_required_string_param (args, param_name, out_address);
}

static bool rjson_get_int_param(RJson *args, const char *param_name, int *out_value) {
	const RJson *field = r_json_get (args, param_name);
	if (!field) {
		return false;
	}
	if (field->type == R_JSON_INTEGER) {
		*out_value = (int)field->num.s_value;
		return true;
	}
	if (field->type == R_JSON_DOUBLE) {
		*out_value = (int)field->num.dbl_value;
		return true;
	}
	if (field->type == R_JSON_STRING && R_STR_ISNOTEMPTY (field->str_value)) {
		char *end = NULL;
		double n = strtod (field->str_value, &end);
		if (end != field->str_value) {
			while (IS_WHITESPACE (*end)) {
				end++;
			}
			if (!*end) {
				*out_value = (int)n;
				return true;
			}
		}
	}
	return false;
}

static char *tool_cmd_response(char *res) {
	char *response = jsonrpc_tooltext_response (res);
	free (res);
	return response;
}

// Mode-aware variant of tool_cmd_response, frees both inputs
R_UNUSED static char *tool_mode_response(ServerState *ss, char *text, char *structured_json) {
	char *response = jsonrpc_tool_response (text, structured_json, ss->content_mode);
	free (text);
	free (structured_json);
	return response;
}

static inline const char *fx(ServerState *ss) {
	return ss->frida_mode? ":": "";
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

// Check if a tool is disabled via blacklist. If ss->disabled_tools is NULL,
// no tools are disabled. If the tool name is in the blacklist, return false.
static bool tool_not_disabled(const ServerState *ss, const char *name) {
	if (!ss || !ss->disabled_tools) {
		return true;
	}
	RListIter *it;
	const char *s;
	r_list_foreach (ss->disabled_tools, it, s) {
		if (!strcmp (s, name)) {
			return false;
		}
	}
	return true;
}

static bool tool_allowed_by_runtime_flags(const ServerState *ss, const char *name) {
	if (!name) {
		return false;
	}
	if ((!strcmp (name, "run_command") || !strcmp (name, "run_javascript")) && (!ss || !ss->enable_run_command_tool)) {
		return false;
	}
	return true;
}

static inline ToolMode current_mode(const ServerState *ss) {
	if (ss->readonly_mode) {
		return TOOL_MODE_RO;
	}
	ToolMode mode = 0;
	if (ss->http_mode) {
		mode |= TOOL_MODE_HTTP;
	}
	if (ss->frida_mode) {
		mode |= TOOL_MODE_FRIDA;
	}
	if (ss->use_sessions) {
		mode |= TOOL_MODE_SESSIONS;
	}
	if (ss->minimode) {
		mode |= TOOL_MODE_MINI;
	}
	if (mode == 0) {
		mode = TOOL_MODE_NORMAL;
	}
	return mode;
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
	for (size_t i = 0; tool_specs[i].name; i++) {
		ToolSpec *t = &tool_specs[i];
		if (tool_matches_mode (t, mode) && tool_allowed_by_runtime_flags (ss, t->name) && tool_allowed_by_whitelist (ss, t->name) && tool_not_disabled (ss, t->name)) {
			r_list_append (out, t); // reference only
		}
	}
	return out;
}

bool tools_is_tool_allowed(const ServerState *ss, const char *name) {
	if (!name) {
		return false;
	}
	if (!tool_allowed_by_runtime_flags (ss, name)) {
		return false;
	}
	if (ss->permissive_tools) {
		return true;
	}
	if (!tool_not_disabled (ss, name)) {
		return false;
	}
	ToolMode mode = current_mode (ss);
	for (size_t i = 0; tool_specs[i].name; i++) {
		ToolSpec *t = &tool_specs[i];
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
				t->name,
				t->description,
				t->schema_json);
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

	for (size_t i = 0; tool_specs[i].name; i++) {
		ToolSpec *t = &tool_specs[i];
		if (!tool_allowed_by_runtime_flags (ss, t->name) || !tool_allowed_by_whitelist (ss, t->name) || !tool_not_disabled (ss, t->name)) {
			continue;
		}
		char modes_buf[8];
		int p = 0;
		if (t->modes & TOOL_MODE_MINI) {
			modes_buf[p++] = 'M';
		}
		if (t->modes & TOOL_MODE_HTTP) {
			modes_buf[p++] = 'H';
		}
		if (t->modes & TOOL_MODE_FRIDA) {
			modes_buf[p++] = 'F';
		}
		if (t->modes & TOOL_MODE_RO) {
			modes_buf[p++] = 'R';
		}
		if (t->modes & TOOL_MODE_SESSIONS) {
			modes_buf[p++] = 'S';
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
	RRegex rx;
	int re_flags = r_regex_flags ("e");
	if (r_regex_init (&rx, pattern, re_flags) != 0) {
		return strdup ("Invalid regex used in filter parameter, try a simpler expression");
	}
	RStrBuf *sb = r_strbuf_new ("");
	RList *lines = r_str_split_list (strdup (src), "\n", 0);
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		if (r_regex_exec (&rx, line, 0, 0, 0) == 0) {
			r_strbuf_appendf (sb, "%s\n", line);
		}
	}
	r_list_free (lines);
	r_regex_fini (&rx);
	return r_strbuf_drain (sb);
}

static char *filter_named_functions_only(const char *input) {
	const char *src = input? input: "";
	RStrBuf *sb = r_strbuf_new ("");
	RList *lines = r_str_split_list (strdup (src), "\n", 0);
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
		const char *last_dot = r_str_lchr (line, '.');
		if (!last_dot || !last_dot[1] || !isdigit (last_dot[1])) {
			r_strbuf_appendf (sb, "%s\n", line);
		}
	}
	r_list_free (lines);
	return r_strbuf_drain (sb);
}

static char *tool_close_file(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	if (ss->http_mode) {
		return jsonrpc_tooltext_response ("In r2pipe mode we won't close the file.");
	}
	if (ss->rstate.core) {
		bool was_sandboxed = r_sandbox_enable (false);
		if (was_sandboxed) {
			r_sandbox_disable (true);
		}
		free (r2mcp_cmd (ss, "o-*"));
		if (was_sandboxed) {
			r_sandbox_disable (false);
		}
		ss->rstate.file_opened = false;
		ss->frida_mode = false;
		free (ss->rstate.current_file);
		ss->rstate.current_file = NULL;
	}
	return jsonrpc_tooltext_response ("File closed successfully.");
}

static char *tool_list_functions(ServerState *ss, RJson *tool_args) {
	const RJson *only_named_parameter = r_json_get (tool_args, "only_named");
	bool only_named = false;
	if (only_named_parameter) {
		if (only_named_parameter->type == R_JSON_BOOLEAN) {
			only_named = only_named_parameter->num.u_value;
		}
	}

	// Acquire additional parameters `start` and `max_length`.
	int start = 0;
	int max_length = 50;
	rjson_get_int_param (tool_args, "start", &start);
	rjson_get_int_param (tool_args, "max_length", &max_length);

	const char *filter = r_json_get_str (tool_args, "filter");
	if (filter && strchr (filter, '/')) {
		filter = NULL;
	}
	char *res;
	if (ss->frida_mode) {
		return jsonrpc_tooltext_response ("In Frida mode we won't list functions. List exports or classes instead.");
	}
	res = r2mcp_cmd (ss, "afl,addr/cols/name");
	r_str_trim (res);
	if (R_STR_ISEMPTY (res)) {
		free (res);
		free (r2mcp_cmd (ss, "aaa"));
		res = r2mcp_cmd (ss, "afl,addr/cols/name");
		r_str_trim (res);
		if (R_STR_ISEMPTY (res)) {
			free (res);
			char *err = strdup ("No functions found. Run the analysis first.");
			return tool_cmd_response (err);
		}
	}
	// Apply filtering if only_named is true
	if (only_named && R_STR_ISNOTEMPTY (res)) {
		char *filtered = filter_named_functions_only (res);
		if (filtered) {
			free (res);
			res = filtered;
		}
	}
	// Apply regex filter if provided
	if (R_STR_ISNOTEMPTY (filter) && R_STR_ISNOTEMPTY (res)) {
		char *r = filter_lines_by_regex (res, filter);
		free (res);
		res = r;
	}
	r_str_trim (res);
	if (R_STR_ISEMPTY (res)) {
		free (res);
		char *err = strdup ("No functions found. Run the analysis first.");
		return tool_cmd_response (err);
	}
	// Apply pagination, offset by 2 to skip the header lines
	int total_lines = r_str_char_count (res, '\n') - 2;
	int page_size = (max_length < 1)? total_lines: max_length;
	char cursor_buf[32];
	snprintf (cursor_buf, sizeof (cursor_buf), "%d", start + 2);
	char *next_cursor = NULL;
	bool has_more = false;
	char *paginated = paginate_text_by_lines (res, cursor_buf, page_size, &has_more, &next_cursor);
	free (res);
	free (next_cursor);
	return tool_cmd_response (paginated);
}

static char *tool_list_files(ServerState *ss, RJson *tool_args) {
	const char *path;
	if (!validate_required_string_param (tool_args, "path", &path)) {
		return jsonrpc_error_missing_param ("path");
	}

	const char *err = r2mcp_sandbox_check (ss, path);
	if (err) {
		return jsonrpc_error_response (-32603, err, NULL, NULL);
	}

	char *cmd = r_str_newf ("'ls -q %s", path);
	char *res = r2mcp_cmd (ss, cmd);
	free (cmd);
	return tool_cmd_response (res);
}

static char *tool_list_classes(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	char *res = r2mcp_cmd (ss, ss->frida_mode? ":ic": "icqq");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (res, filter);
		free (res);
		res = r;
	}
	return tool_cmd_response (res);
}

static char *tool_list_methods(ServerState *ss, RJson *tool_args) {
	const char *classname;
	if (!validate_required_string_param (tool_args, "classname", &classname)) {
		return jsonrpc_error_missing_param ("classname");
	}
	const char *prefix = ss->frida_mode? ":": "'";
	return tool_cmd_response (r2mcp_cmdf (ss, "'%sic %s", prefix, classname));
}

static char *tool_list_decompilers(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, "e cmd.pdc=?"));
}

static char *tool_list_functions_tree(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	char *res = r2mcp_cmd (ss, "aflmu");

	r_str_trim (res);

	return tool_cmd_response (res);
}

static char *tool_list_imports(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	char *res = r2mcp_cmd (ss, ss->frida_mode? ":ii": "iiq");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (res, filter);
		free (res);
		res = r;
	}
	return tool_cmd_response (res);
}

static char *tool_list_exports(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	char *res = r2mcp_cmd (ss, ss->frida_mode? ":iE": "iEq");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (res, filter);
		free (res);
		res = r;
	}
	return tool_cmd_response (res);
}

static char *tool_list_sections(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, ss->frida_mode? ":iS": "iS;iSS"));
}

static char *tool_list_memory_maps(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdm", fx (ss)));
}

static char *tool_show_info(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, ss->frida_mode? ":i": "i;iH"));
}

static char *tool_show_function_details(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, "afi"));
}

static char *tool_get_current_address(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, "s;fd"));
}

static char *tool_list_symbols(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	char *res = r2mcp_cmd (ss, ss->frida_mode? ":is": "isq~!func.,!imp.");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (res, filter);
		free (res);
		res = r;
	}
	return tool_cmd_response (res);
}

static char *tool_list_entrypoints(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, ss->frida_mode? ":ie": "ies"));
}

static char *tool_list_libraries(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmd (ss, ss->frida_mode? ":il": "ilq"));
}

static char *tool_calculate(ServerState *ss, RJson *tool_args) {
	const char *expression;
	if (!validate_required_string_param (tool_args, "expression", &expression)) {
		return jsonrpc_error_missing_param ("expression");
	}
	if (!ss->rstate.core || !ss->rstate.core->num) {
		return jsonrpc_error_response (-32611, "Core or number parser unavailable (open a file first)", NULL, NULL);
	}
	RCore *core = ss->rstate.core;
	ut64 calc_result = r_num_math (core->num, expression);
	char *numstr = r_str_newf ("0x%" PFMT64x, (ut64)calc_result);
	char *resp = jsonrpc_tooltext_response (numstr);
	free (numstr);
	return resp;
}

static char *tool_set_comment(ServerState *ss, RJson *tool_args) {
	const char *address, *message;
	if (!validate_address_param (tool_args, "address", &address) ||
		!validate_required_string_param (tool_args, "message", &message)) {
		return jsonrpc_error_missing_param ("address and message");
	}

	char *cmd_cc = r_str_newf ("'@%s'CC %s", address, message);
	char *tmpres_cc = r2mcp_cmd (ss, cmd_cc);
	free (tmpres_cc);
	free (cmd_cc);
	return jsonrpc_tooltext_response ("ok");
}

static char *tool_set_function_prototype(ServerState *ss, RJson *tool_args) {
	const char *address, *prototype;
	if (!validate_address_param (tool_args, "address", &address) ||
		!validate_required_string_param (tool_args, "prototype", &prototype)) {
		return jsonrpc_error_missing_param ("address and prototype");
	}
	char *cmd_afs = r_str_newf ("'@%s'afs %s", address, prototype);
	char *tmpres_afs = r2mcp_cmd (ss, cmd_afs);
	free (tmpres_afs);
	free (cmd_afs);
	return jsonrpc_tooltext_response ("ok");
}

static char *tool_get_function_prototype(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	char *s = r_str_newf ("'@%s'afs", address);
	char *res = r2mcp_cmd (ss, s);
	free (s);
	return tool_cmd_response (res);
}

static char *tool_list_strings(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	const char *cursor = r_json_get_str (tool_args, "cursor");
	int page_size = 0;
	rjson_get_int_param (tool_args, "page_size", &page_size);
	if (page_size <= 0) {
		page_size = R2MCP_DEFAULT_PAGE_SIZE;
	}
	if (page_size > R2MCP_MAX_PAGE_SIZE) {
		page_size = R2MCP_MAX_PAGE_SIZE;
	}

	char *cmd_result = r2mcp_cmd (ss, ss->frida_mode? ":iz": "izqq");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (cmd_result, filter);
		free (cmd_result);
		cmd_result = r;
	}
	bool has_more = false;
	char *next_cursor = NULL;
	char *paginated = paginate_text_by_lines (cmd_result, cursor, page_size, &has_more, &next_cursor);
	free (cmd_result);
	char *response = jsonrpc_tooltext_response_paginated (paginated, has_more, next_cursor);
	free (paginated);
	free (next_cursor);
	return response;
}

static char *tool_list_all_strings(ServerState *ss, RJson *tool_args) {
	const char *filter = r_json_get_str (tool_args, "filter");
	const char *cursor = r_json_get_str (tool_args, "cursor");
	int page_size = 0;
	rjson_get_int_param (tool_args, "page_size", &page_size);
	if (page_size <= 0) {
		page_size = R2MCP_DEFAULT_PAGE_SIZE;
	}
	if (page_size > R2MCP_MAX_PAGE_SIZE) {
		page_size = R2MCP_MAX_PAGE_SIZE;
	}

	char *cmd_result = r2mcp_cmd (ss, "izzzqq");
	if (R_STR_ISNOTEMPTY (filter)) {
		char *r = filter_lines_by_regex (cmd_result, filter);
		free (cmd_result);
		cmd_result = r;
	}
	if (R_STR_ISEMPTY (cmd_result)) {
		free (cmd_result);
		cmd_result = r_str_newf ("Error: No strings with regex %s", filter);
	}
	bool has_more = false;
	char *next_cursor = NULL;
	char *paginated = paginate_text_by_lines (cmd_result, cursor, page_size, &has_more, &next_cursor);
	free (cmd_result);
	char *response = jsonrpc_tooltext_response_paginated (paginated, has_more, next_cursor);
	free (paginated);
	free (next_cursor);
	return response;
}

static char *tool_analyze(ServerState *ss, RJson *tool_args) {
	if (ss->frida_mode) {
		return jsonrpc_tooltext_response ("Analysis is not available in frida mode. Use list_functions to see exports or run_command with r2frida commands.");
	}
	int level = 0;
	rjson_get_int_param (tool_args, "level", &level);
	const RJson *timeout_json = r_json_get (tool_args, "timeout_seconds");
	int timeout_seconds = R2MCP_ANALYZE_TIMEOUT_UNSET;
	if (timeout_json) {
		rjson_get_int_param (tool_args, "timeout_seconds", &timeout_seconds);
		if (timeout_seconds < 0) {
			timeout_seconds = 0;
		}
	}
	char *err = r2_analyze (ss, level, timeout_seconds);
	char *cmd_result = r2mcp_cmd (ss, "aflc");
	char *errstr;
	if (R_STR_ISNOTEMPTY (err)) {
		errstr = r_str_newf ("\n\n<log>\n%s\n</log>\n", err);
	} else {
		errstr = strdup ("");
	}
	bool timed_out = timeout_json && R_STR_ISNOTEMPTY (err) && r_str_casestr (err, "timeout");
	char *text;
	if (timed_out) {
		text = r_str_newf ("Analysis stopped after %d second%s at level %d.\nFound %d functions so far.%s",
			timeout_seconds,
			timeout_seconds == 1? "": "s",
			level,
			atoi (cmd_result),
			errstr);
	} else {
		text = r_str_newf ("Analysis completed with level %d.\nFound %d functions.%s", level, atoi (cmd_result), errstr);
	}
	char *response = jsonrpc_tooltext_response (text);
	free (err);
	free (errstr);
	free (cmd_result);
	free (text);
	return response;
}

static char *tool_disassemble(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}

	int num_instructions = 10;
	rjson_get_int_param (tool_args, "num_instructions", &num_instructions);

	return tool_cmd_response (r2mcp_cmdf (ss, "'@%s'pd %d", address, num_instructions));
}

static char *tool_use_decompiler(ServerState *ss, RJson *tool_args) {
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

static char *tool_xrefs_to(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "'@%s'axt", address));
}

static char *tool_disassemble_function(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	const char *cursor = r_json_get_str (tool_args, "cursor");
	int page_size = 0;
	rjson_get_int_param (tool_args, "page_size", &page_size);
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

static char *tool_rename_flag(ServerState *ss, RJson *tool_args) {
	const char *address, *name, *new_name;
	if (!validate_address_param (tool_args, "address", &address) ||
		!validate_required_string_param (tool_args, "name", &name) ||
		!validate_required_string_param (tool_args, "new_name", &new_name)) {
		return jsonrpc_error_missing_param ("address, name, and new_name");
	}
	char *remove_res = r2mcp_cmdf (ss, "'@%s'fr %s %s", address, name, new_name);
	if (R_STR_ISNOTEMPTY (remove_res)) {
		return tool_cmd_response (remove_res);
	}
	free (remove_res);
	return jsonrpc_tooltext_response ("ok");
}

static char *tool_rename_function(ServerState *ss, RJson *tool_args) {
	const char *address, *name;
	if (!validate_address_param (tool_args, "address", &address) ||
		!validate_required_string_param (tool_args, "name", &name)) {
		return jsonrpc_error_missing_param ("address and name");
	}
	free (r2mcp_cmdf (ss, "'@%s'afn %s", address, name));
	return jsonrpc_tooltext_response ("ok");
}

static char *tool_decompile_function(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	const char *cursor = r_json_get_str (tool_args, "cursor");
	int page_size = 0;
	rjson_get_int_param (tool_args, "page_size", &page_size);
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

static char *tool_get_pid(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdp", fx (ss)));
}

static char *tool_list_threads(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdpt", fx (ss)));
}

static char *tool_dump_registers(ServerState *ss, RJson *tool_args) {
	const RJson *thread_id_json = r_json_get (tool_args, "thread_id");
	if (thread_id_json) {
		int thread_id;
		if (!rjson_get_int_param (tool_args, "thread_id", &thread_id)) {
			return jsonrpc_error_response (-32602, "'thread_id' must be a number", NULL, NULL);
		}
		return tool_cmd_response (r2mcp_cmdf (ss, "%sdr %d", fx (ss), thread_id));
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdr", fx (ss)));
}

static char *tool_hexdump(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	const char *size = r_json_get_str (tool_args, "size");
	if (R_STR_ISNOTEMPTY (size)) {
		return tool_cmd_response (r2mcp_cmdf (ss, "'@%s'px %s", address, size));
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "'@%s'px", address));
}

static char *tool_memory_map_here(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdm.", fx (ss)));
}

static char *tool_list_heap_allocations(ServerState *ss, RJson *tool_args) {
	(void)tool_args;
	return tool_cmd_response (r2mcp_cmdf (ss, "%sdmh", fx (ss)));
}

static char *tool_alloc_memory(ServerState *ss, RJson *tool_args) {
	const char *string_value = r_json_get_str (tool_args, "string");
	if (R_STR_ISNOTEMPTY (string_value)) {
		return tool_cmd_response (r2mcp_cmdf (ss, ":dmas %s", string_value));
	}
	int size = 0;
	rjson_get_int_param (tool_args, "size", &size);
	if (size <= 0) {
		return jsonrpc_error_response (-32602, "Provide either 'size' (number of bytes) or 'string' to allocate", NULL, NULL);
	}
	return tool_cmd_response (r2mcp_cmdf (ss, ":dma %d", size));
}

static char *tool_change_memory_protection(ServerState *ss, RJson *tool_args) {
	const char *address, *protection;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	int size = 0;
	rjson_get_int_param (tool_args, "size", &size);
	if (size <= 0) {
		return jsonrpc_error_missing_param ("size");
	}
	if (!validate_required_string_param (tool_args, "protection", &protection)) {
		return jsonrpc_error_missing_param ("protection");
	}
	return tool_cmd_response (r2mcp_cmdf (ss, ":dmp %s %d %s", address, size, protection));
}

static char *tool_search(ServerState *ss, RJson *tool_args) {
	const char *query;
	if (!validate_required_string_param (tool_args, "query", &query)) {
		return jsonrpc_error_missing_param ("query");
	}
	const char *type = r_json_get_str (tool_args, "type");
	if (R_STR_ISEMPTY (type)) {
		type = "string";
	}
	if (!strcmp (type, "hex")) {
		return tool_cmd_response (r2mcp_cmdf (ss, "'%s/x %s", fx (ss), query));
	}
	if (!strcmp (type, "wide")) {
		return tool_cmd_response (r2mcp_cmdf (ss, "'%s/w %s", fx (ss), query));
	}
	if (!strcmp (type, "value")) {
		int value_size = 0;
		rjson_get_int_param (tool_args, "value_size", &value_size);
		if (value_size != 1 && value_size != 2 && value_size != 4 && value_size != 8) {
			value_size = 4;
		}
		return tool_cmd_response (r2mcp_cmdf (ss, "'%s/v%d %s", fx (ss), value_size, query));
	}
	// default: string search
	return tool_cmd_response (r2mcp_cmdf (ss, "'%s/ %s", fx (ss), query));
}

static char *tool_lookup_address(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "%sfd @ %s", fx (ss), address));
}

static char *tool_lookup_export(ServerState *ss, RJson *tool_args) {
	const char *name;
	if (!validate_required_string_param (tool_args, "name", &name)) {
		return jsonrpc_error_missing_param ("name");
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "%siaE %s", fx (ss), name));
}

static char *tool_lookup_symbol(ServerState *ss, RJson *tool_args) {
	const char *address;
	if (!validate_address_param (tool_args, "address", &address)) {
		return jsonrpc_error_missing_param ("address");
	}
	return tool_cmd_response (r2mcp_cmdf (ss, "%sis. @ %s", fx (ss), address));
}

static char *tool_run_command(ServerState *ss, RJson *tool_args) {
	const char *command;
	if (!validate_required_string_param (tool_args, "command", &command)) {
		return jsonrpc_error_missing_param ("command");
	}
	return tool_cmd_response (r2mcp_cmd (ss, command));
}

static char *tool_run_javascript(ServerState *ss, RJson *tool_args) {
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
	free (cmd);
	free (encoded);
	return tool_cmd_response (res);
}

static char *tool_run_frida_script(ServerState *ss, RJson *tool_args) {
	const char *script;
	if (!ss->frida_mode) {
		return jsonrpc_error_response (-32603, "Frida mode is not enabled", NULL, NULL);
	}
	if (!validate_required_string_param (tool_args, "script", &script)) {
		return jsonrpc_error_missing_param ("script");
	}
	char *encoded = r_base64_encode_dyn ((const ut8 *)script, strlen (script));

	if (!encoded) {
		return jsonrpc_error_response (-32603, "Failed to encode script", NULL, NULL);
	}

	char *cmd = r_str_newf (": base64:%s", encoded);
	char *res = r2mcp_cmd (ss, cmd);
	free (cmd);
	free (encoded);
	return tool_cmd_response (res);
}

static char *tool_list_sessions(ServerState *ss, RJson *tool_args) {
	if (!ss->use_sessions) {
		return jsonrpc_error_response (-32603, "Start r2mcp with -L to support sessions", NULL, NULL);
	}
	(void)tool_args;
	(void)ss;
	// r2agent command doesn't require an open file, run it directly
	char *res = NULL;
	if (ss && ss->http_mode) {
		// In HTTP mode, we can't run r2agent locally, return empty result
		res = strdup ("[]");
	} else {
		res = r_sys_cmd_str ("r2agent -Lj 2>/dev/null", NULL, NULL);
		if (R_STR_ISEMPTY (res)) {
			free (res);
			res = strdup ("[]");
		}
	}
	return tool_cmd_response (res);
}

static bool is_localhost(const char *url) {
	if (R_STR_ISEMPTY (url)) {
		return false;
	}
	if (!r_str_startswith (url, "http://") && !r_str_startswith (url, "https://")) {
		return false;
	}
	const char *host = strstr (url, "://");
	if (!host) {
		return false;
	}
	host += 3;
	if (R_STR_ISEMPTY (host)) {
		return false;
	}
	if (r_str_startswith (host, "localhost")) {
		char ch = host[9];
		return ch == 0 || ch == ':' || ch == '/' || ch == '?';
	}
	if (r_str_startswith (host, "127.0.0.1")) {
		char ch = host[9];
		return ch == 0 || ch == ':' || ch == '/' || ch == '?';
	}
	if (r_str_startswith (host, "[::1]")) {
		char ch = host[5];
		return ch == 0 || ch == ':' || ch == '/' || ch == '?';
	}
	return false;
}

static char *tool_open_session(ServerState *ss, RJson *tool_args) {
	if (!ss->use_sessions) {
		return jsonrpc_error_response (-32603, "Start r2mcp with -L to support sessions", NULL, NULL);
	}
	const char *url;
	if (!validate_required_string_param (tool_args, "url", &url)) {
		return jsonrpc_error_missing_param ("url");
	}
	if (!is_localhost (url)) {
		return jsonrpc_error_response (-32603, "Only localhost session URLs are allowed", NULL, NULL);
	}

	// Preserve the previous baseurl even when reconnecting from one remote
	// session to another, so failed probes can fully restore the old state.
	char *old_baseurl = NULL;
	bool old_http_mode = ss->http_mode;
	if (ss->baseurl) {
		old_baseurl = strdup (ss->baseurl);
	}

	// Set up HTTP mode for this session
	ss->http_mode = true;
	free (ss->baseurl);
	ss->baseurl = strdup (url);

	// Test the connection by running a simple command
	char *test_result = r2mcp_cmd (ss, "i");
	if (!test_result || strstr (test_result, "HTTP request failed")) {
		// Restore previous state if connection failed
		ss->http_mode = old_http_mode;
		free (ss->baseurl);
		ss->baseurl = old_baseurl;
		free (test_result);

		char *error_msg = r_str_newf ("Failed to connect to URL: %s", url);
		char *error_resp = jsonrpc_error_response (-32603, error_msg, NULL, NULL);
		free (error_msg);
		return error_resp;
	}

	free (test_result);
	free (old_baseurl);

	ss->rstate.file_opened = true;

	char *success_msg = r_str_newf ("Successfully connected to remote r2 instance at %s", url);
	char *response = jsonrpc_tooltext_response (success_msg);
	free (success_msg);
	return response;
}

static char *tool_close_session(ServerState *ss, RJson *tool_args) {
	if (!ss->use_sessions) {
		return jsonrpc_error_response (-32603, "Start r2mcp with -L to support sessions", NULL, NULL);
	}
	(void)tool_args;

	if (!ss->http_mode) {
		return jsonrpc_tooltext_response ("No active remote session to close.");
	}

	// Clear the HTTP mode and baseurl
	ss->http_mode = false;
	ss->frida_mode = false;
	ss->rstate.file_opened = false;
	free (ss->rstate.current_file);
	ss->rstate.current_file = NULL;
	free (ss->baseurl);
	ss->baseurl = NULL;

	return jsonrpc_tooltext_response ("Remote session closed successfully.");
}

// AITODO: move move into pj API?
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

static char *check_supervisor_permission(ServerState *ss, const char *tool_name, RJson *tool_args, char **new_tool_name_out, RJson **new_tool_args_out, RJson **parsed_json_out, char **parsed_buf_out) {
	if (!ss->svc_baseurl) {
		return NULL;
	}
	*parsed_json_out = NULL;
	*parsed_buf_out = NULL;
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "tool", tool_name);
	pj_k (pj, "arguments");
	pj_append_rjson (pj, tool_args);
	pj_k (pj, "available_tools");
	pj_a (pj);
	for (size_t i = 0; tool_specs[i].name; i++) {
		if (tools_is_tool_allowed (ss, tool_specs[i].name)) {
			pj_s (pj, tool_specs[i].name);
		}
	}
	pj_end (pj);
	pj_end (pj);
	char *req = pj_drain (pj);
	int rc;
	char *resp = curl_post_capture (ss->svc_baseurl, req, &rc);
	free (req);
	if (!resp || rc != 0) {
		free (resp);
		return NULL;
	}
	*parsed_json_out = r_json_parse (resp);
	if (!*parsed_json_out) {
		free (resp);
		return NULL;
	}
	const char *err = r_json_get_str (*parsed_json_out, "error");
	if (err) {
		char *error_resp = jsonrpc_error_response (-32000, err, NULL, NULL);
		r_json_free (*parsed_json_out);
		*parsed_json_out = NULL;
		free (resp);
		return error_resp;
	}
	const char *r2cmd = r_json_get_str (*parsed_json_out, "r2cmd");
	if (r2cmd) {
		r_json_free (*parsed_json_out);
		*parsed_json_out = NULL;
		free (resp);
		return jsonrpc_error_response (-32000, "Supervisor responses with 'r2cmd' are not allowed. Return 'tool' + 'arguments' instead.", NULL, NULL);
	}
	const RJson *new_args = r_json_get (*parsed_json_out, "arguments");
	if (new_args) {
		const char *new_tool = r_json_get_str (*parsed_json_out, "tool");
		if (new_tool && strcmp (new_tool, tool_name)) {
			*new_tool_name_out = strdup (new_tool);
		}
		*new_tool_args_out = (RJson *)new_args;
		*parsed_buf_out = resp;
	} else {
		r_json_free (*parsed_json_out);
		*parsed_json_out = NULL;
		free (resp);
	}
	return NULL;
}

// Main dispatcher that handles tool calls. Returns heap-allocated JSON
// string representing the tool "result" (caller must free it).
char *tools_call(ServerState *ss, const char *tool_name, RJson *tool_args) {
	RJson nil = { 0 };
	if (!tool_args) {
		tool_args = &nil;
	}
	char *result = NULL;
	char *allocated_tool_name = NULL;
	RJson *parsed_json = NULL;
	char *parsed_buf = NULL;
	if (!tool_name) {
		result = jsonrpc_error_missing_param ("name");
		goto cleanup;
	}
	// Enforce tool availability per mode unless permissive is enabled
	if (!tools_is_tool_allowed (ss, tool_name)) {
		result = jsonrpc_error_tool_not_allowed (tool_name);
		goto cleanup;
	}

	// Supervisor control check
	char *supervisor_override = check_supervisor_permission (ss, tool_name, tool_args, &allocated_tool_name, &tool_args, &parsed_json, &parsed_buf);
	if (supervisor_override) {
		result = supervisor_override;
		goto cleanup;
	}
	if (allocated_tool_name) {
		tool_name = allocated_tool_name;
	}

	// Special-case: open_file
	if (!strcmp (tool_name, "open_file")) {
		if (ss->http_mode) {
			char *res = r2mcp_cmd (ss, "i");
			char *foo = r_str_newf ("File was already opened, this are the details:\n%s", res);
			char *out = jsonrpc_tooltext_response (foo);
			free (res);
			free (foo);
			result = out;
			goto cleanup;
		}
		const char *filepath;
		if (!validate_required_string_param (tool_args, "file_path", &filepath)) {
			result = jsonrpc_error_missing_param ("file_path");
			goto cleanup;
		}

		char *filteredpath = strdup (filepath);
		r_str_replace_ch (filteredpath, '`', 0, true);
		if (ss->rstate.file_opened && ss->rstate.current_file && !strcmp (ss->rstate.current_file, filteredpath)) {
			char *text = r_str_newf ("File already opened: %s", ss->rstate.current_file);
			result = jsonrpc_tooltext_response (text);
			free (text);
			free (filteredpath);
			goto cleanup;
		}

		bool is_uri = strstr (filteredpath, "://") != NULL;
		bool had_file_opened = ss->rstate.file_opened;
		char *previous_file = (had_file_opened && ss->rstate.current_file)? strdup (ss->rstate.current_file): NULL;
		if (had_file_opened && !is_uri && r2mcp_sandbox_check (ss, filteredpath)) {
			had_file_opened = false;
			R_FREE (previous_file);
		}
		if (had_file_opened) {
			char *close_res = tool_close_file (ss, &nil);
			free (close_res);
		}
		bool success = r2_open_file (ss, filteredpath);
		free (filteredpath);
		if (success && previous_file) {
			char *text = r_str_newf ("Closed previously opened file: %s\nFile opened successfully.", previous_file);
			result = jsonrpc_tooltext_response (text);
			free (text);
		} else {
			result = jsonrpc_tooltext_response (success? "File opened successfully.": "Failed to open file.");
		}
		free (previous_file);
		goto cleanup;
	}

	// Special-case: open_session
	if (!strcmp (tool_name, "open_session")) {
		result = tool_open_session (ss, tool_args);
		goto cleanup;
	}

	// Special-case: list_sessions
	if (!strcmp (tool_name, "list_sessions")) {
		result = tool_list_sessions (ss, tool_args);
		goto cleanup;
	}

	if (!ss->http_mode && !ss->rstate.file_opened) {
		if (!strcmp (tool_name, "list_functions")) {
			result = jsonrpc_tooltext_response ("No file is currently open. Call open_file first, then call list_functions again.");
			goto cleanup;
		}
		result = jsonrpc_error_file_required ();
		goto cleanup;
	}

	// Find the tool spec and validate arguments against schema
	ToolSpec *found_tool = NULL;
	for (size_t i = 0; tool_specs[i].name; i++) {
		ToolSpec *t = &tool_specs[i];
		if (!strcmp (tool_name, t->name)) {
			found_tool = t;
			break;
		}
	}

	if (found_tool && found_tool->schema_json) {
		ValidationResult vr = validate_arguments (tool_args, found_tool->schema_json);
		if (!vr.valid) {
			result = jsonrpc_error_response (-32602, vr.error_message, NULL, NULL);
			free (vr.error_message);
			goto cleanup;
		}
	}

	// Dispatch to tool functions
	for (size_t i = 0; tool_specs[i].name; i++) {
		ToolSpec *t = &tool_specs[i];
		if (!strcmp (tool_name, t->name)) {
			result = t->func (ss, tool_args);
			goto cleanup;
		}
	}

	char *tmp = r_str_newf ("Unknown tool: %s", tool_name);
	char *err = jsonrpc_error_response (-32602, tmp, NULL, NULL);
	free (tmp);
	result = err;
	goto cleanup;

cleanup:
	free (allocated_tool_name);
	r_json_free (parsed_json);
	free (parsed_buf);
	return result;
}
ToolSpec tool_specs[] = {
	{ "open_file", "Opens a binary file with radare2 for analysis <think>Call this tool before any other one from r2mcp. Use an absolute file_path</think>", "{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"file_path\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI, NULL },
	{ "run_javascript", "Executes JavaScript code using radare2's qjs runtime", "{\"type\":\"object\",\"properties\":{\"script\":{\"type\":\"string\",\"description\":\"The JavaScript code to execute\"}},\"required\":[\"script\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP, tool_run_javascript },
	{ "run_frida_script", "Executes Frida JavaScript code", "{\"type\":\"object\",\"properties\":{\"script\":{\"type\":\"string\",\"description\":\"The script code to execute\"}},\"required\":[\"script\"]}", TOOL_MODE_FRIDA, tool_run_frida_script },
	{ "run_command", "Executes a raw radare2 command directly", "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"The radare2 command to execute\"}},\"required\":[\"command\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP, tool_run_command },
	{ "list_sessions", "Lists available r2agent sessions in JSON format", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_SESSIONS, tool_list_sessions },
	{ "open_session", "Connects to a remote r2 instance using r2pipe API", "{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\",\"description\":\"URL of the remote r2 instance to connect to\"}},\"required\":[\"url\"]}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP | TOOL_MODE_SESSIONS, tool_open_session },
	{ "close_session", "Close the currently open remote session", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP | TOOL_MODE_SESSIONS, tool_close_session },
	{ "close_file", "Close the currently open file", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL, tool_close_file },
	{ "list_functions", "Lists all functions discovered during analysis", "{\"type\":\"object\",\"properties\":{\"only_named\":{\"type\":\"boolean\",\"description\":\"If true, only list functions with named symbols (excludes functions with numeric suffixes like sym.func.1000016c8)\"},\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"},\"start\":{\"type\":\"integer\",\"description\":\"Starting index for pagination (default: 0)\"},\"max_length\":{\"type\":\"integer\",\"description\":\"Maximum number of results to return, -1 for all (default: 50)\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO, tool_list_functions },
	{ "list_functions_tree", "Lists functions and successors (aflmu)", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO, tool_list_functions_tree },
	{ "list_libraries", "Lists all shared libraries linked to the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_libraries },
	{ "list_imports", "Lists imported symbols (note: use list_symbols for addresses with sym.imp. prefix)", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_imports },
	{ "list_exports", "Lists exported symbols from the binary or process", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_exports },
	{ "list_sections", "Displays memory sections and segments from the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_sections },
	{ "list_memory_maps", "Lists memory regions of the process with addresses and permissions", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP | TOOL_MODE_FRIDA, tool_list_memory_maps },
	{ "show_function_details", "Displays detailed information about the current function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_show_function_details },
	{ "get_current_address", "Shows the current position and function name", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_get_current_address },
	{ "show_info", "Displays information about the binary or target process", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_show_info },
	{ "list_symbols", "Shows all symbols (functions, variables, imports) with addresses", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_symbols },
	{ "list_entrypoints", "Displays program entrypoints, constructors and main function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_entrypoints },
	{ "list_methods", "Lists all methods belonging to the specified class", "{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list methods for\"}},\"required\":[\"classname\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_methods },
	{ "list_classes", "Lists class names from various languages (C++, ObjC, Swift, Java, Dalvik)", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_classes },
	{ "list_decompilers", "Shows all available decompiler backends", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_list_decompilers },
	{ "rename_function", "Renames the function at the specified address", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"New function name\"},\"address\":{\"type\":\"string\",\"description\":\"Address of the function to rename\"}},\"required\":[\"name\",\"address\"]}", TOOL_MODE_NORMAL, tool_rename_function },
	{ "rename_flag", "Renames a local variable or data reference within the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the flag containing the variable or data reference\"},\"name\":{\"type\":\"string\",\"description\":\"Current variable name or data reference\"},\"new_name\":{\"type\":\"string\",\"description\":\"New variable name or data reference\"}},\"required\":[\"address\",\"name\",\"new_name\"]}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP, tool_rename_flag },
	{ "use_decompiler", "Selects which decompiler backend to use (default: pdc)", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}", TOOL_MODE_NORMAL, tool_use_decompiler },
	{ "get_function_prototype", "Retrieves the function signature at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_get_function_prototype },
	{ "set_function_prototype", "Sets the function signature (return type, name, arguments)", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"},\"prototype\":{\"type\":\"string\",\"description\":\"Function signature in C-like syntax\"}},\"required\":[\"address\",\"prototype\"]}", TOOL_MODE_NORMAL, tool_set_function_prototype },
	{ "set_comment", "Adds a comment at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"message\":{\"type\":\"string\",\"description\":\"Comment text to use\"}},\"required\":[\"address\",\"message\"]}", TOOL_MODE_NORMAL | TOOL_MODE_HTTP, tool_set_comment },
	{ "list_strings", "Lists strings from data sections with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_list_strings },
	{ "list_all_strings", "Scans the entire binary for strings with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_list_all_strings },
	{ "analyze", "Runs binary analysis with optional depth level", "{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0-4, higher is more thorough)\"},\"timeout_seconds\":{\"type\":\"integer\",\"description\":\"Optional maximum analysis time in seconds for this call only. Use 0 to disable the timeout.\"}},\"required\":[]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_FRIDA, tool_analyze },
	{ "xrefs_to", "Finds all code references to the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to check for cross-references\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO, tool_xrefs_to },
	{ "decompile_function", "Show C-like pseudocode of the function in the given address. <think>Use this to inspect the code in a function, do not run multiple times in the same offset</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO, tool_decompile_function },
	{ "list_files", "Lists files in the specified path using radare2's ls -q command. Files ending with / are directories, otherwise they are files.", "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Path to list files from\"}},\"required\":[\"path\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_HTTP | TOOL_MODE_RO, tool_list_files },
	{ "disassemble_function", "Shows assembly listing of the function at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"},\"cursor\":{\"type\":\"string\",\"description\":\"Cursor for pagination (line number to start from)\"},\"page_size\":{\"type\":\"integer\",\"description\":\"Number of lines per page (default: 1000, max: 10000)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO, tool_disassemble_function },
	{ "disassemble", "Disassembles a specific number of instructions from an address <think>Use this tool to inspect a portion of memory as code without depending on function analysis boundaries. Use this tool when functions are large and you are only interested on few instructions</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"num_instructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble (default: 10)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_disassemble },
	{ "calculate", "Evaluate a math expression using core->num (r_num_math). Usecases: do proper 64-bit math, resolve addresses for flag names/symbols, and avoid hallucinated results.", "{\"type\":\"object\",\"properties\":{\"expression\":{\"type\":\"string\",\"description\":\"Math expression to evaluate (eg. 0x100 + sym.flag - 4)\"}},\"required\":[\"expression\"]}", TOOL_MODE_NORMAL | TOOL_MODE_MINI | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_calculate },
	{ "get_pid", "Get the process ID of the target process", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_get_pid },
	{ "list_threads", "List all threads in the target process with their IDs and state", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_list_threads },
	{ "dump_registers", "Show register values for the target process threads", "{\"type\":\"object\",\"properties\":{\"thread_id\":{\"type\":\"integer\",\"description\":\"Optional thread ID to show registers for a specific thread\"}}}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_dump_registers },
	{ "hexdump", "Print memory contents in hexdump style at the given address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to hexdump\"},\"size\":{\"type\":\"string\",\"description\":\"Number of bytes to dump (empty string for default size)\"}},\"required\":[\"address\",\"size\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_hexdump },
	{ "memory_map_here", "Show memory map information at the current address", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_memory_map_here },
	{ "list_heap_allocations", "List malloc/heap memory ranges in the target process", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_list_heap_allocations },
	{ "alloc_memory", "Allocate memory in the target process heap. Provide either size (bytes) or string to allocate", "{\"type\":\"object\",\"properties\":{\"size\":{\"type\":\"integer\",\"description\":\"Number of bytes to allocate\"},\"string\":{\"type\":\"string\",\"description\":\"String to allocate in target heap (returns its address)\"}}}", TOOL_MODE_FRIDA, tool_alloc_memory },
	{ "change_memory_protection", "Change memory protection (rwx) at the given address and size", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the memory region\"},\"size\":{\"type\":\"integer\",\"description\":\"Size in bytes of the region\"},\"protection\":{\"type\":\"string\",\"description\":\"New protection string (e.g. rwx, r-x, rw-)\"}},\"required\":[\"address\",\"size\",\"protection\"]}", TOOL_MODE_FRIDA, tool_change_memory_protection },
	{ "search", "Search for strings, hex patterns, wide strings, or numeric values", "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"The search query (string, hex bytes, or numeric value)\"},\"type\":{\"type\":\"string\",\"description\":\"Search type: string (default), hex, wide, or value\"},\"value_size\":{\"type\":\"integer\",\"description\":\"For value search: byte width 1, 2, 4 (default), or 8\"}},\"required\":[\"query\"]}", TOOL_MODE_NORMAL | TOOL_MODE_FRIDA, tool_search },
	{ "lookup_address", "Describe what is at a given address (flag name, symbol, module)", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to describe\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_lookup_address },
	{ "lookup_export", "Resolve an export name to its implementation address", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Export name to look up\"}},\"required\":[\"name\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_lookup_export },
	{ "lookup_symbol", "Resolve an address to its symbol name", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to resolve\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | TOOL_MODE_RO | TOOL_MODE_FRIDA, tool_lookup_symbol },
	{ NULL, NULL, NULL, 0, NULL }
};
