/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include "readbuffer.h"
#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_print.h>

#define R2MCP_DEBUG 1
#define R2MCP_LOGFILE "/tmp/r2mcp.txt"
#define R2MCP_VERSION "1.0.0"
#define JSON_RPC_VERSION "2.0"
#define MCP_VERSION "2024-11-05"
#define READ_CHUNK_SIZE 32768
#define LATEST_PROTOCOL_VERSION "2024-11-05"

typedef struct {
	const char *name;
	const char *version;
} ServerInfo;

typedef struct {
	bool logging;
	bool tools;
} ServerCapabilities;

typedef struct {
	RCore *core;
	bool file_opened;
	char *current_file;
} RadareState;

typedef struct {
	ServerInfo info;
	ServerCapabilities capabilities;
	const char *instructions;
	bool initialized;
	const RJson *client_capabilities;
	const RJson *client_info;
	RadareState rstate;
} ServerState;

#include "utils.inc.c"
#include "r2api.inc.c"

static volatile sig_atomic_t running = 1;
static void signal_handler(int signum) {
	const char msg[] = "\nInterrupt received, shutting down...\n";
	write (STDERR_FILENO, msg, sizeof (msg) - 1);
	running = 0;
	signal (signum, SIG_DFL);
}
static void setup_signals(void) {
	// Set up signal handlers
	struct sigaction sa = { 0 };
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	sigemptyset (&sa.sa_mask);

	sigaction (SIGINT, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);
	sigaction (SIGHUP, &sa, NULL);
	signal (SIGPIPE, SIG_IGN);
}

static bool check_client_capability(ServerState *ss, const char *capability) {
	if (ss->client_capabilities) {
		RJson *cap = (RJson *)r_json_get (ss->client_capabilities, capability);
		return cap != NULL;
	}
	return false;
}

static bool check_server_capability(ServerState *ss, const char *capability) {
	if (!strcmp (capability, "logging")) {
		return ss->capabilities.logging;
	}
	if (!strcmp (capability, "tools")) {
		return ss->capabilities.tools;
	}
	return false;
}

static bool assert_capability_for_method(ServerState *ss, const char *method, char **error) {
	if (!strcmp (method, "sampling/createMessage")) {
		if (!check_client_capability (ss, "sampling")) {
			*error = strdup ("Client does not support sampling");
			return false;
		}
	} else if (!strcmp (method, "roots/list")) {
		if (!check_client_capability (ss, "roots")) {
			*error = strdup ("Client does not support listing roots");
			return false;
		}
	}
	return true;
}

static bool assert_request_handler_capability(ServerState *ss, const char *method, char **error) {
	if (!strcmp (method, "sampling/createMessage")) {
		if (!check_server_capability (ss, "sampling")) {
			*error = strdup ("Server does not support sampling");
			return false;
		}
	} else if (!strcmp (method, "logging/setLevel")) {
		if (!check_server_capability (ss, "logging")) {
			*error = strdup ("Server does not support logging");
			return false;
		}
	} else if (r_str_startswith (method, "prompts/")) {
		if (!check_server_capability (ss, "prompts")) {
			*error = strdup ("Server does not support prompts");
			return false;
		}
	} else if (r_str_startswith (method, "tools/")) {
		if (!check_server_capability (ss, "tools")) {
			*error = strdup ("Server does not support tools");
			return false;
		}
	}
	return true;
}

// Helper function to create JSON-RPC error responses
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

static char *handle_initialize(ServerState *ss, RJson *params) {
	ss->client_capabilities = r_json_get (params, "capabilities");
	ss->client_info = r_json_get (params, "clientInfo");

	// Create a proper initialize response
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "protocolVersion", LATEST_PROTOCOL_VERSION);

	pj_k (pj, "serverInfo");
	pj_o (pj);
	pj_ks (pj, "name", ss->info.name);
	pj_ks (pj, "version", ss->info.version);
	pj_end (pj);

	// Capabilities need to be objects with specific structure, not booleans
	pj_k (pj, "capabilities");
	pj_o (pj);

	// Tools capability - needs to be an object
	pj_k (pj, "tools");
	pj_o (pj);
	pj_kb (pj, "listChanged", false);
	pj_end (pj);

	// For any capability we don't support, don't include it at all
	// Don't add: prompts, roots, resources, notifications, logging, sampling

	pj_end (pj); // End capabilities

	if (ss->instructions) {
		pj_ks (pj, "instructions", ss->instructions);
	}

	pj_end (pj);

	ss->initialized = true;
	return pj_drain (pj);
}

// Create a proper success response
static char *jsonrpc_success_response(const char *result, const char *id) {
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
	char *s = pj_drain (pj);
	r2mcp_log (">>>");
	r2mcp_log (s);
	return s;
}

static char *handle_list_tools(RJson *params) {
	// Add pagination support
	const char *cursor = r_json_get_str (params, "cursor");
	int page_size = 32; // Default page size XXX pagination doesnt work. just use > len (tools)
	int start_index = 0;

	// Parse cursor if provided
	if (cursor) {
		start_index = atoi (cursor);
		if (start_index < 0) {
			start_index = 0;
		}
	}

	// Use more straightforward JSON construction for tools list
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "{\"tools\":[");

	// Define our tools with their descriptions and schemas
	// Format: {name, description, schema_definition}
	const char *tools[26][3] = {
		{ "openFile",
			"Open given file with radare2 to start the analysis",
			"{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"(required) Path to the file to open\"}},\"required\":[\"filePath\"]}" },
		{ "closeFile",
			"Close the currently open file",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listFunctions",
			"List all functions found after the analysis",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listLibraries",
			"List libraries linked to this binary",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listImports",
			"Enumerate imported symbols (does not contain address, use sym.imp. prefixed entries from `listSymbols`)",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listSections",
			"Show program sections and segments",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "showFunctionDetails",
			"Show function details",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "getCurrentAddress",
			"Get name and address for the current offset",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "showHeaders",
			"Show program headers details and information from the binary",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listSymbols",
			"Enumerate all the symbols defined in the program, imports plt address and function tags",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listEntrypoints",
			"Show address of program entrypoints, constructor functions and main symbol",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listMethods",
			"Enumerate address and methods for the specified classname",
			"{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list its methods\"}},\"required\":[\"classname\"]}" },
		{ "listClasses",
			"List C++, ObjC, Swift, Java, Dalvik class names",
			"{\"type\":\"object\",\"properties\":{\"regexpFilter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}" },
		{ "listDecompilers",
			"List all the decompilers available for radare2",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "renameFunction",
			"Change the name of the function located in given address",
			"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"},\"address\":{\"type\":\"string\",\"description\":\"address of the function to rename\"}},\"required\":[\"name\",\"address\"]}" },
		{ "useDecompiler",
			"Select decompiler (`pdc` is the default)",
			"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}" },
		{ "getFunctionPrototype",
			"Get the function signature / prototype from the given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"(required) Address of the function\"},\"prototype\":{\"type\":\"string\",\"description\":\"function signature or prototype description\"}},\"required\":[\"address\"]}" },
		{ "setFunctionPrototype",
			"Define the function signature (return type, symbol name and argument types and names)",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"prototype\":{\"type\":\"string\",\"description\":\"function signature or prototype description\"}},\"required\":[\"address\",\"prototype\"]}" },
		{ "setComment",
			"List strings in the rodata section of the binary matching the given regexp",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"message\":{\"type\":\"string\",\"description\":\"comment text to use\"}},\"required\":[\"address\",\"message\"]}" },
		{ "listStrings",
			"List strings in the rodata section of the binary matching the given regexp",
			"{\"type\":\"object\",\"properties\":{\"regexpFilter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}" },
		{ "listAllStrings",
			"Scan the whole binary looking for hardcoded strings matching the given regexp if specified (consider using this method when analyzing malware)",
			"{\"type\":\"object\",\"properties\":{\"regexpFilter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}" },
#if 0
		{ "runCommand", // TODO: optional
			"Run a radare2 command and get the output",
			"{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"Command to execute\"}},\"required\":[\"command\"]}" },
#endif
		{ "analyze",
			"Run analysis on the current file",
			"{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0, 1, 2, 3, 4)\"}},\"required\":[]}" },
		{ "xrefsTo",
			"List all the references to the given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the address to check for crossed references\"}},\"required\":[\"address\"]}" },
		{ "decompileFunction",
			"Decompile function at given address, consider using this method instead of disassembleFunction",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"}},\"required\":[\"address\"]}" },
		{ "disassembleFunction",
			"Disassemble function at given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"}},\"required\":[\"address\"]}" },
		{ "disassemble",
			"Disassemble (numInstructions) at a given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"numInstructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble\"}},\"required\":[\"address\"]}" }
	};

	int total_tools = sizeof (tools) / sizeof (tools[0]);
	int end_index = start_index + page_size;
	if (end_index > total_tools) {
		end_index = total_tools;
	}

	// Add tools for this page
	for (int i = start_index; i < end_index; i++) {
		if (i > start_index) {
			r_strbuf_appendf (sb, ",");
		}
		r_strbuf_appendf (sb, "{\"name\":\"%s\",\"description\":\"%s\",\"inputSchema\":%s}",
			tools[i][0], tools[i][1], tools[i][2]);
	}

	r_strbuf_append (sb, "]");

	// Add nextCursor if there are more tools
	if (end_index < total_tools) {
		r_strbuf_appendf (sb, ",\"nextCursor\":\"%d\"", end_index);
	}

	r_strbuf_appendf (sb, "}");
	return r_strbuf_drain (sb);
}

static char *handle_call_tool(ServerState *ss, RJson *params) {
	RCore *core = ss->rstate.core;
	const char *tool_name = r_json_get_str (params, "name");

	if (!tool_name) {
		return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
	}

	RJson *tool_args = (RJson *)r_json_get (params, "arguments");

	// Handle openFile tool
	if (!strcmp (tool_name, "openFile")) {
		const char *filepath = r_json_get_str (tool_args, "filePath");
		if (!filepath) {
			return jsonrpc_error_response (-32602, "Missing required parameter: filePath", NULL, NULL);
		}

		bool success = r2_open_file (ss, filepath);
		return jsonrpc_tooltext_response (success ? "File opened successfully." : "Failed to open file.");
	}
	if (!ss->rstate.file_opened) {
		return jsonrpc_error_response (-32611, "Use the openFile method before calling any other method", NULL, NULL);
		// return jsonrpc_tooltext_response ("Use the openFile method toNo file was open.");
	}
	// Handle listMethods tool
	if (!strcmp (tool_name, "listMethods")) {
		const char *classname = r_json_get_str (tool_args, "classname");
		if (!classname) {
			return jsonrpc_tooltext_response ("Missing classname parameter");
		}
		char *cmd = r_str_newf ("'ic %s", classname);
		char *res = r2_cmd (ss, cmd);
		free (cmd);
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listClasses tool
	if (!strcmp (tool_name, "listClasses")) {
		const char *filter = r_json_get_str (tool_args, "filter");
		char *res = r2_cmd (ss, "icqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			RStrBuf *sb = r_strbuf_new ("");
			RList *strings = r_str_split_list (res, "\n", 0);
			RListIter *iter;
			const char *str;
			RRegex rx;
			int re_flags = r_regex_flags ("e");
			bool ok = r_regex_init (&rx, filter, re_flags) == 0;
			if (ok) {
				r_list_foreach (strings, iter, str) {
					if (r_regex_exec (&rx, str, 0, 0, 0) == 0) {
						r_strbuf_appendf (sb, "%s\n", str);
					}
				}
				r_regex_fini (&rx);
			} else {
				r_strbuf_appendf (sb, "Invalid regex used in filter parameter, try a simpler expression");
			}
			free (res);
			res = r_strbuf_drain (sb);
		}
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listDecompilers tool
	if (!strcmp (tool_name, "listDecompilers")) {
		char *res = r2_cmd (ss, "e cmd.pdc=?");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listFunctions tool
	if (!strcmp (tool_name, "listFunctions")) {
		char *res = r2_cmd (ss, "afl,addr/cols/name");
		r_str_trim (res);
		if (R_STR_ISEMPTY (res)) {
			free (res);
			res = strdup ("No functions found. Run the analysis first.");
		}
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listImports tool
	if (!strcmp (tool_name, "listImports")) {
		char *res = r2_cmd (ss, "iiq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listSections tool
	if (!strcmp (tool_name, "listSections")) {
		char *res = r_core_cmd_str (core, "iS;iSS");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle showHeaders tool
	if (!strcmp (tool_name, "showHeaders")) {
		char *res = r_core_cmd_str (core, "i;iH");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle showFunctionDetails tool
	if (!strcmp (tool_name, "showFunctionDetails")) {
		char *res = r_core_cmd_str (core, "afi");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle getCurrentAddress tool
	if (!strcmp (tool_name, "getCurrentAddress")) {
		char *res = r_core_cmd_str (core, "s;fd");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listSymbols tool
	if (!strcmp (tool_name, "listSymbols")) {
		char *res = r_core_cmd_str (core, "isq~!func.,!imp.");
		// TODO: remove imports and func
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listEntrypoints tool
	if (!strcmp (tool_name, "listEntrypoints")) {
		char *res = r_core_cmd_str (core, "ies");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listLibraries tool
	if (!strcmp (tool_name, "listLibraries")) {
		char *res = r_core_cmd_str (core, "ilq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle closeFile tool
	if (!strcmp (tool_name, "closeFile")) {
		if (core) {
			r_core_cmd0 (core, "o-*");
			ss->rstate.file_opened = false;
			ss->rstate.current_file = NULL;
		}

		return jsonrpc_tooltext_response ("File closed successfully.");
	}

#if 0
	// Handle runCommand tool
	if (!strcmp (tool_name, "runCommand")) {
		if (!r_core || !file_opened) {
			return strdup ("Error: No file is open");
		}
		const char *command = r_json_get_str (tool_args, "command");
		if (!command) {
			return jsonrpc_error_response (-32602, "Missing required parameter: command", NULL, NULL);
		}

		char *result = r2_cmd (command);
		char *response = jsonrpc_tooltext_response (result);
		free (result);
		return response;
	}
#endif
	// Handle setComment tool
	if (!strcmp (tool_name, "setComment")) {
		const char *address = r_json_get_str (tool_args, "address");
		const char *message = r_json_get_str (tool_args, "message");
		if (!address || !message) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address and message", NULL, NULL);
		}

		r_core_cmdf (core, "'@%s'%s", address, message);
		return strdup ("ok");
	}

	// Handle setFunctionPrototype tool
	if (!strcmp (tool_name, "setFunctionPrototype")) {
		const char *address = r_json_get_str (tool_args, "address");
		const char *prototype = r_json_get_str (tool_args, "prototype");
		if (!address || !prototype) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address and prototype", NULL, NULL);
		}
		r_core_cmdf (core, "'@%s'afs %s", address, prototype);
		return strdup ("ok");
	}

	// Handle getFunctionPrototype tool
	if (!strcmp (tool_name, "getFunctionPrototype")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address", NULL, NULL);
		}
		char *s = r_str_newf ("'@%s'afs", address);
		char *res = r2_cmd (ss, s);
		free (s);
		return res;
	}

	// Handle listStrings tool
	if (!strcmp (tool_name, "listStrings")) {
		const char *filter = r_json_get_str (tool_args, "filter");

		char *result = r2_cmd (ss, "izqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			RStrBuf *sb = r_strbuf_new ("");
			RList *strings = r_str_split_list (result, "\n", 0);
			RListIter *iter;
			const char *str;
			RRegex rx;
			int re_flags = r_regex_flags ("e");
			bool ok = r_regex_init (&rx, filter, re_flags) == 0;
			if (ok) {
				r_list_foreach (strings, iter, str) {
					if (r_regex_exec (&rx, str, 0, 0, 0) == 0) {
						r_strbuf_appendf (sb, "%s\n", str);
					}
				}
				r_regex_fini (&rx);
			} else {
				r_strbuf_appendf (sb, "Invalid regex used in filter parameter, try a simpler expression");
			}
			free (result);
			result = r_strbuf_drain (sb);
		}
		char *response = jsonrpc_tooltext_response (result);
		free (result);
		return response;
	}

	// Handle listAllStrings tool
	if (!strcmp (tool_name, "listAllStrings")) {
		const char *filter = r_json_get_str (tool_args, "filter");

		char *result = r2_cmd (ss, "izzzqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			RStrBuf *sb = r_strbuf_new ("");
			RList *strings = r_str_split_list (result, "\n", 0);
			RListIter *iter;
			const char *str;
			RRegex rx;
			int re_flags = r_regex_flags ("e");
			bool ok = r_regex_init (&rx, filter, re_flags) == 0;
			if (ok) {
				r_list_foreach (strings, iter, str) {
					if (r_regex_exec (&rx, str, 0, 0, 0) == 0) {
						r_strbuf_appendf (sb, "%s\n", str);
					}
				}
				r_regex_fini (&rx);
			} else {
				r_strbuf_appendf (sb, "Invalid regex used in filter parameter, try a simpler expression");
			}
			free (result);
			result = r_strbuf_drain (sb);
		}
		if (R_STR_ISEMPTY (result)) {
			free (result);
			result = r_str_newf ("Error: No strings with regex %s", filter);
		}
		char *response = jsonrpc_tooltext_response (result);
		free (result);
		return response;
	}

	// Handle analyze tool
	if (!strcmp (tool_name, "analyze")) {
		const int level = r_json_get_num (tool_args, "level");
		r2_analyze (ss, level);
		char *result = r2_cmd (ss, "aflc");
		char *text = r_str_newf ("Analysis completed with level %d.\n\nfound %d functions", level, atoi (result));
		char *response = jsonrpc_tooltext_response (text);
		free (result);
		free (text);
		return response;
	}

	// Handle disassemble tool
	if (!strcmp (tool_name, "disassemble")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}

		// Use const_cast pattern
		RJson *num_instr_json = (RJson *)r_json_get (tool_args, "numInstructions");
		int num_instructions = 10;
		if (num_instr_json && num_instr_json->type == R_JSON_INTEGER) {
			num_instructions = (int)num_instr_json->num.u_value;
		}

		char *cmd = r_str_newf ("'@%s'pd %d", address, num_instructions);
		char *disasm = r2_cmd (ss, cmd);
		free (cmd);
		char *response = jsonrpc_tooltext_response (disasm);
		free (disasm);
		return response;
	}

	// Handle useDecompiler tool
	if (!strcmp (tool_name, "useDecompiler")) {
		const char *deco = r_json_get_str (tool_args, "name");
		if (!deco) {
			return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
		}
		char *decompilersAvailable = r_core_cmd_str (core, "e cmd.pdc=?");
		const char *response = "ok";
		if (strstr (deco, "ghidra")) {
			if (strstr (decompilersAvailable, "pdg")) {
				r_core_cmd0 (core, "-e cmd.pdc=pdg");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "decai")) {
			if (strstr (decompilersAvailable, "decai")) {
				r_core_cmd0 (core, "-e cmd.pdc=decai -d");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "r2dec")) {
			if (strstr (decompilersAvailable, "pdd")) {
				r_core_cmd0 (core, "-e cmd.pdc=pdd");
			} else {
				response = "This decompiler is not available";
			}
		} else {
			response = "Unknown decompiler";
		}
		return jsonrpc_tooltext_response (response);
	}

	// Handle xrefsTo tool
	if (!strcmp (tool_name, "xrefsTo")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'axt", address);
		char *disasm = r2_cmd (ss, cmd);
		char *response = jsonrpc_tooltext_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	// Handle disassembleFunction tool
	if (!strcmp (tool_name, "disassembleFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'pdf", address);
		char *disasm = r2_cmd (ss, cmd);
		char *response = jsonrpc_tooltext_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	// Handle renameFunction tool
	if (!strcmp (tool_name, "renameFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		const char *name = r_json_get_str (tool_args, "name");
		if (!name) {
			return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'afn %s", address, name);
		r_core_cmd0 (core, cmd);
		return jsonrpc_tooltext_response ("ok");
	}

	// Handle decompileFunction tool
	if (!strcmp (tool_name, "decompileFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return jsonrpc_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'pdc", address);
		char *disasm = r2_cmd (ss, cmd);
		char *response = jsonrpc_tooltext_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	return jsonrpc_error_response (-32602, r_str_newf ("Unknown tool: %s", tool_name), NULL, NULL);
}
//

static char *handle_mcp_request(ServerState *ss, const char *method, RJson *params, const char *id) {
	char *error = NULL;
	char *result = NULL;

	if (!assert_capability_for_method (ss, method, &error) || !assert_request_handler_capability (ss, method, &error)) {
		char *response = jsonrpc_error_response (-32601, error, id, NULL);
		free (error);
		return response;
	}

	if (!strcmp (method, "initialize")) {
		result = handle_initialize (ss, params);
	} else if (!strcmp (method, "notifications/initialized")) {
		return NULL; // No response for notifications
	} else if (!strcmp (method, "ping")) {
		result = strdup ("{}");
	} else if (!strcmp (method, "resources/templates/list")) {
		return jsonrpc_error_response (-32601, "Method not implemented: templates are not supported", id, NULL);
	} else if (!strcmp (method, "resources/list")) {
		return jsonrpc_error_response (-32601, "Method not implemented: resources are not supported", id, NULL);
	} else if (!strcmp (method, "resources/read") || !strcmp (method, "resource/read")) {
		return jsonrpc_error_response (-32601, "Method not implemented: resources are not supported", id, NULL);
	} else if (!strcmp (method, "resources/subscribe") || !strcmp (method, "resource/subscribe")) {
		return jsonrpc_error_response (-32601, "Method not implemented: subscriptions are not supported", id, NULL);
	} else if (!strcmp (method, "tools/list") || !strcmp (method, "tool/list")) {
		result = handle_list_tools (params);
	} else if (!strcmp (method, "tools/call") || !strcmp (method, "tool/call")) {
		result = handle_call_tool (ss, params);
	} else {
		return jsonrpc_error_response (-32601, "Unknown method", id, NULL);
	}

	char *response = jsonrpc_success_response (result, id);
	free (result);
	return response;
}

// Modified process_mcp_message to handle the protocol correctly
static void process_mcp_message(ServerState *ss, const char *msg) {
	r2mcp_log ("<<<");
	r2mcp_log (msg);

	RJson *request = r_json_parse ((char *)msg);
	if (!request) {
		R_LOG_ERROR ("Invalid JSON");
		return;
	}

	const char *method = r_json_get_str (request, "method");
	RJson *params = (RJson *)r_json_get (request, "params");
	RJson *id_json = (RJson *)r_json_get (request, "id");

	if (!method) {
		R_LOG_ERROR ("Invalid JSON-RPC message: missing method");
		r_json_free (request);
		return;
	}

	// Proper handling of notifications vs requests
	if (id_json) {
		// This is a request that requires a response
		const char *id = NULL;
		char id_buf[32] = { 0 };

		if (id_json->type == R_JSON_STRING) {
			id = id_json->str_value;
		} else if (id_json->type == R_JSON_INTEGER) {
			snprintf (id_buf, sizeof (id_buf), "%lld", (long long)id_json->num.u_value);
			id = id_buf;
		}

		char *response = handle_mcp_request (ss, method, params, id);
		if (response) {
			r2mcp_log (">>>");
			r2mcp_log (response);

			// Ensure the response ends with a newline
			size_t resp_len = strlen (response);
			bool has_newline = (resp_len > 0 && response[resp_len - 1] == '\n');

			if (!has_newline) {
				write (STDOUT_FILENO, response, resp_len);
				write (STDOUT_FILENO, "\n", 1);
			} else {
				write (STDOUT_FILENO, response, resp_len);
			}

			fsync (STDOUT_FILENO);
			free (response);
		}
	} else {
		// This is a notification, don't send a response
		// Just handle it internally
		if (!strcmp (method, "notifications/cancelled")) {
			r2mcp_log ("Received cancelled notification");
		} else if (!strcmp (method, "notifications/initialized")) {
			r2mcp_log ("Received initialized notification");
		} else {
			r2mcp_log ("Received unknown notification");
		}
	}

	r_json_free (request);
}

// MCPO protocol-compliant direct mode loop
static void r2mcp_eventloop(ServerState *ss) {
	r2mcp_log ("Starting MCP direct mode (stdin/stdout)");

	// Use consistent unbuffered mode for stdout
	setvbuf (stdout, NULL, _IONBF, 0);

	// Set to blocking I/O for simplicity
	set_nonblocking_io (false);

	ReadBuffer *buffer = read_buffer_new ();
	char chunk[READ_CHUNK_SIZE];

	while (running) {
		// Read data from stdin
		ssize_t bytes_read = read (STDIN_FILENO, chunk, sizeof (chunk) - 1);

		if (bytes_read > 0) {
			// Append to our buffer
			read_buffer_append (buffer, chunk, bytes_read);

			// Try to process any complete messages
			char *msg;
			while ((msg = read_buffer_get_message (buffer)) != NULL) {
				r2mcp_log ("Complete message received:");
				r2mcp_log (msg);
				process_mcp_message (ss, msg);
				free (msg);
			}
		} else if (bytes_read == 0) {
			// EOF - stdin closed
			r2mcp_log ("End of input stream - exiting");
			break;
		} else {
			// Error
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				r2mcp_log ("Read error");
				break;
			}
		}
	}

	read_buffer_free (buffer);
	r2mcp_log ("Direct mode loop terminated");
}

// Main function with proper initialization
int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	ServerState ss = {
		.info = {
			.name = "Radare2 MCP Connector",
			.version = R2MCP_VERSION },
		.capabilities = { .logging = true, .tools = true },
		.instructions = "Use this server to analyze binaries with radare2",
		.initialized = false,
		.client_capabilities = NULL,
		.client_info = NULL
	};

	// Enable logging
	r2mcp_log ("r2mcp starting");

	setup_signals ();

	// Initialize r2
	if (!r2state_init (&ss)) {
		R_LOG_ERROR ("Failed to initialize radare2");
		r2mcp_log ("Failed to initialize radare2");
		return 1;
	}

	running = 1;
	r2mcp_eventloop (&ss);
	r2state_fini (&ss);
	return 0;
}
