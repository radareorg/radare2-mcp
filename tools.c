#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"
#include "utils.inc.c" // bring in shared helpers like jsonrpc_tooltext_response

static inline ToolMode current_mode(const ServerState *ss) {
	if (ss->http_mode) {
		return TOOL_MODE_HTTP;
	}
	if (ss->minimode) {
		return TOOL_MODE_MINI;
	}
	return TOOL_MODE_NORMAL;
}

static ToolSpec *tool(const char *name, const char *desc, const char *schema, int modes) {
	ToolSpec *t = R_NEW0 (ToolSpec);
	if (!t) {
		return NULL;
	}
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

	// Normal mode: full set
	r_list_append ( (RList *)ss->tools, tool ("openFile", "Opens a binary file with radare2 for analysis <think>Call this tool before any other one from r2mcp. Use an absolute filePath</think>", "{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"filePath\"]}", TOOL_MODE_NORMAL | M_MINI));

	if (ss->enable_run_command_tool) {
		r_list_append((RList *)ss->tools, tool("runCommand", "Executes a raw radare2 command directly", "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"The radare2 command to execute\"}},\"required\":[\"command\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));
	}

	r_list_append ( (RList *)ss->tools, tool ("closeFile", "Close the currently open file", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listFunctions", "Lists all functions discovered during analysis", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));
	r_list_append ( (RList *)ss->tools, tool ("listFunctionsTree", "Lists functions and successors (aflmu)", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listLibraries", "Lists all shared libraries linked to the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listImports", "Lists imported symbols (note: use listSymbols for addresses with sym.imp. prefix)", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listSections", "Displays memory sections and segments from the binary", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("showFunctionDetails", "Displays detailed information about the current function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("getCurrentAddress", "Shows the current position and function name", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("showHeaders", "Displays binary headers and file information", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listSymbols", "Shows all symbols (functions, variables, imports) with addresses", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listEntrypoints", "Displays program entrypoints, constructors and main function", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listMethods", "Lists all methods belonging to the specified class", "{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list methods for\"}},\"required\":[\"classname\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listClasses", "Lists class names from various languages (C++, ObjC, Swift, Java, Dalvik)", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listDecompilers", "Shows all available decompiler backends", "{\"type\":\"object\",\"properties\":{}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("renameFunction", "Renames the function at the specified address", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"New function name\"},\"address\":{\"type\":\"string\",\"description\":\"Address of the function to rename\"}},\"required\":[\"name\",\"address\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("useDecompiler", "Selects which decompiler backend to use (default: pdc)", "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("getFunctionPrototype", "Retrieves the function signature at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("setFunctionPrototype", "Sets the function signature (return type, name, arguments)", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"},\"prototype\":{\"type\":\"string\",\"description\":\"Function signature in C-like syntax\"}},\"required\":[\"address\",\"prototype\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("setComment", "Adds a comment at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"message\":{\"type\":\"string\",\"description\":\"Comment text to use\"}},\"required\":[\"address\",\"message\"]}", TOOL_MODE_NORMAL | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listStrings", "Lists strings from data sections with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listAllStrings", "Scans the entire binary for strings with optional regex filter", "{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("analyze", "Runs binary analysis with optional depth level", "{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0-4, higher is more thorough)\"}},\"required\":[]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("xrefsTo", "Finds all code references to the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to check for cross-references\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("decompileFunction", "Show C-like pseudocode of the function in the given address. <think>Use this to inspect the code in a function, do not run multiple times in the same offset</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("disassembleFunction", "Shows assembly listing of the function at the specified address", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("disassemble", "Disassembles a specific number of instructions from an address <think>Use this tool to inspect a portion of memory as code without depending on function analysis boundaries. Use this tool when functions are large and you are only interested on few instructions</think>", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"numInstructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble (default: 10)\"}},\"required\":[\"address\"]}", TOOL_MODE_NORMAL));
}

void tools_registry_fini(ServerState *ss) {
	if (ss && ss->tools) {
		r_list_free ( (RList *)ss->tools);
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
	r_list_foreach ( ( (RList *)ss->tools), it, t) {
		if (tool_matches_mode (t, mode)) {
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
	r_list_foreach ( ( (RList *)ss->tools), it, t) {
		if (!strcmp (t->name, name)) {
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

// Filter lines in `input` by `pattern` regex. Returns a newly allocated string.
static char *filter_lines_by_regex(const char *input, const char *pattern) {
	const char *src = input ? input : "";
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

// Main dispatcher that handles tool calls. Returns heap-allocated JSON
// string representing the tool "result" (caller must free it).
char *tools_call(ServerState *ss, const char *tool_name, RJson *tool_args) {
	if (!tool_name) {
		return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
	}
	// Enforce tool availability per mode unless permissive is enabled
	if (!tools_is_tool_allowed (ss, tool_name)) {
		return jsonrpc_error_response (-32611, "Tool not available in current mode (use -p for permissive)", NULL, NULL);
	}

	// Special-case: openFile
	if (!strcmp (tool_name, "openFile")) {
		if (ss->http_mode) {
			char *res = r2mcp_cmd (ss, "i");
			char *foo = r_str_newf ("File was already opened, this are the details:\n%s", res);
			char *out = jsonrpc_tooltext_response (foo);
			free (res);
			free (foo);
			return out;
		}
		const char *filepath = r_json_get_str (tool_args, "filePath");
		if (!filepath) {
			return jsonrpc_error_response (-32602, "Missing required parameter: filePath", NULL, NULL);
		}

		char *filteredpath = strdup (filepath);
		r_str_replace_ch (filteredpath, '`', 0, true);
		bool success = r2mcp_open_file (ss, filteredpath);
		free (filteredpath);
		return jsonrpc_tooltext_response (success ? "File opened successfully." : "Failed to open file.");
	}

	if (!ss->http_mode && !ss->rstate.file_opened) {
		return jsonrpc_error_response (-32611, "Use the openFile method before calling any other method", NULL, NULL);
	}

	// Map simple tools to commands or handlers
	if (!strcmp (tool_name, "listMethods")) {
		const char *classname = r_json_get_str (tool_args, "classname");
		if (!classname) {
			return jsonrpc_tooltext_response ("Missing classname parameter");
		}
		char *res = r2mcp_cmdf (ss, "'ic %s", classname);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listClasses")) {
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
	if (!strcmp (tool_name, "listDecompilers")) {
		char *res = r2mcp_cmd (ss, "e cmd.pdc=?");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listFunctions")) {
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
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listFunctionsTree")) {
		char *res = r2mcp_cmd (ss, "aflmu");
		r_str_trim (res);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listImports")) {
		char *res = r2mcp_cmd (ss, "iiq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listSections")) {
		char *res = r2mcp_cmd (ss, "iS;iSS");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "showHeaders")) {
		char *res = r2mcp_cmd (ss, "i;iH");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "showFunctionDetails")) {
		char *res = r2mcp_cmd (ss, "afi");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "getCurrentAddress")) {
		char *res = r2mcp_cmd (ss, "s;fd");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listSymbols")) {
		char *res = r2mcp_cmd (ss, "isq~!func.,!imp.");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listEntrypoints")) {
		char *res = r2mcp_cmd (ss, "ies");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "listLibraries")) {
		char *res = r2mcp_cmd (ss, "ilq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}
	if (!strcmp (tool_name, "closeFile")) {
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

	if (!strcmp (tool_name, "setComment")) {
		const char *address = r_json_get_str (tool_args, "address");
		const char *message = r_json_get_str (tool_args, "message");
		if (!address || !message) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address and message", NULL, NULL);
		}

		char *cmd_cc = r_str_newf ("'@%s'CC %s", address, message);
		char *tmpres_cc = r2mcp_cmd (ss, cmd_cc);
		free (tmpres_cc);
		free (cmd_cc);
		return strdup ("ok");
	}

	if (!strcmp (tool_name, "setFunctionPrototype")) {
		const char *address = r_json_get_str (tool_args, "address");
		const char *prototype = r_json_get_str (tool_args, "prototype");
		if (!address || !prototype) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address and prototype", NULL, NULL);
		}
		char *cmd_afs = r_str_newf ("'@%s'afs %s", address, prototype);
		char *tmpres_afs = r2mcp_cmd (ss, cmd_afs);
		free (tmpres_afs);
		free (cmd_afs);
		return strdup ("ok");
	}

	if (!strcmp (tool_name, "getFunctionPrototype")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address", NULL, NULL);
		}
		char *s = r_str_newf ("'@%s'afs", address);
		char *res = r2mcp_cmd (ss, s);
		free (s);
		return res;
	}

	if (!strcmp (tool_name, "listStrings") || !strcmp (tool_name, "listAllStrings")) {
		const char *filter = r_json_get_str (tool_args, "filter");

		char *result = r2mcp_cmd (ss, (!strcmp (tool_name, "listStrings") ? "izqq" : "izzzqq"));
		if (R_STR_ISNOTEMPTY (filter)) {
			char *r = filter_lines_by_regex (result, filter);
			free (result);
			result = r;
		}
		if (!strcmp (tool_name, "listAllStrings") && R_STR_ISEMPTY (result)) {
			free (result);
			result = r_str_newf ("Error: No strings with regex %s", filter);
		}
		char *response = jsonrpc_tooltext_response (result);
		free (result);
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
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}

		RJson *num_instr_json = (RJson *)r_json_get (tool_args, "numInstructions");
		int num_instructions = 10;
		if (num_instr_json && num_instr_json->type == R_JSON_INTEGER) {
			num_instructions = (int)num_instr_json->num.u_value;
		}

		char *disasm = r2mcp_cmdf (ss, "'@%s'pd %d", address, num_instructions);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp (tool_name, "useDecompiler")) {
		const char *deco = r_json_get_str (tool_args, "name");
		if (!deco) {
			return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
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

	if (!strcmp (tool_name, "xrefsTo")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'axt", address);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp (tool_name, "disassembleFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'pdf", address);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp (tool_name, "renameFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		const char *name = r_json_get_str (tool_args, "name");
		if (!name) {
			return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
		}
		free (r2mcp_cmdf (ss, "'@%s'afn %s", address, name));
		return jsonrpc_tooltext_response ("ok");
	}

	if (!strcmp (tool_name, "decompileFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *disasm = r2mcp_cmdf (ss, "'@%s'pdc", address);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	if (!strcmp(tool_name, "runCommand")) {
		const char *command = r_json_get_str(tool_args, "command");
		if (!command) {
			return jsonrpc_error_response(-32602, "Missing required parameter: command", NULL, NULL);
		}
		char *res = r2mcp_cmd(ss, command);
		char *o = jsonrpc_tooltext_response(res);
		free(res);
		return o;
	}

	{
		char *tmp = r_str_newf ("Unknown tool: %s", tool_name);
		char *err = jsonrpc_error_response (-32602, tmp, NULL, NULL);
		free (tmp);
		return err;
	}
}
