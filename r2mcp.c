/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_print.h>
#include "config.h"
#include "r2mcp.h"
#include "tools.h"

#define R2MCP_DEBUG 1

#ifndef R2MCP_VERSION
#warning R2MCP_VERSION is not defined
#define R2MCP_VERSION "1.1.0"
#endif

#define JSON_RPC_VERSION        "2.0"
#define MCP_VERSION             "2024-11-05"
#define READ_CHUNK_SIZE         32768
#define LATEST_PROTOCOL_VERSION "2024-11-05"

#include "utils.inc.c"
#include "r2api.inc.c"

static volatile sig_atomic_t running = 1;
void r2mcp_running_set(int value) {
	running = value ? 1 : 0;
}

/* Public wrappers to expose internal static helpers from r2api.inc.c */
bool r2mcp_state_init(ServerState *ss) {
	return r2state_init (ss);
}
void r2mcp_state_fini(ServerState *ss) {
	r2state_fini (ss);
}
char *r2mcp_cmd(ServerState *ss, const char *cmd) {
	return r2_cmd (ss, cmd);
}
void r2mcp_log_pub(ServerState *ss, const char *msg) {
	r2mcp_log (ss, msg);
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
static char *jsonrpc_success_response(ServerState *ss, const char *result, const char *id) {
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
	r2mcp_log (ss, ">>>");
	r2mcp_log (ss, s);
	return s;
}

static char *handle_list_tools(ServerState *ss, RJson *params) {
	const char *cursor = r_json_get_str (params, "cursor");
	int page_size = 32;
	return tools_build_catalog_json (ss, cursor, page_size);
}

static char *handle_call_tool(ServerState *ss, RJson *params) {
	RCore *core = ss->rstate.core;
	const char *tool_name = r_json_get_str (params, "name");

	if (!tool_name) {
		return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
	}

	// Enforce tool availability per mode unless permissive is enabled
	if (!tools_is_tool_allowed (ss, tool_name)) {
		return jsonrpc_error_response (-32611, "Tool not available in current mode (use -p for permissive)", NULL, NULL);
	}

	RJson *tool_args = (RJson *)r_json_get (params, "arguments");

	// Handle openFile tool
	if (!strcmp (tool_name, "openFile")) {
		if (ss->http_mode) {
			char *res = r2_cmd (ss, "i");
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
		bool success = r2_open_file (ss, filteredpath);
		free (filteredpath);
		return jsonrpc_tooltext_response (success ? "File opened successfully." : "Failed to open file.");
	}
	if (!ss->http_mode) {
		if (!ss->rstate.file_opened) {
			return jsonrpc_error_response (-32611, "Use the openFile method before calling any other method", NULL, NULL);
			// return jsonrpc_tooltext_response ("Use the openFile method toNo file was open.");
		}
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
		// char *res = r2_cmd (ss, "aflm"); // "afl,addr/cols/name");
		char *res = r2_cmd (ss, "afl,addr/cols/name");
		r_str_trim (res);
		if (R_STR_ISEMPTY (res)) {
			free (res);
#if 1
			free (r2_cmd (ss, "aaa"));
			// res = r2_cmd (ss, "afl,addr/cols/name");
			res = r2_cmd (ss, "afl,addr/cols/name");
			//	res = r2_cmd (ss, "aflm");
			r_str_trim (res);
#endif
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
		char *res = r2_cmd (ss, "iS;iSS");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle showHeaders tool
	if (!strcmp (tool_name, "showHeaders")) {
		char *res = r2_cmd (ss, "i;iH");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle showFunctionDetails tool
	if (!strcmp (tool_name, "showFunctionDetails")) {
		char *res = r2_cmd (ss, "afi");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle getCurrentAddress tool
	if (!strcmp (tool_name, "getCurrentAddress")) {
		char *res = r2_cmd (ss, "s;fd");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listSymbols tool
	if (!strcmp (tool_name, "listSymbols")) {
		char *res = r2_cmd (ss, "isq~!func.,!imp.");
		// TODO: remove imports and func
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listEntrypoints tool
	if (!strcmp (tool_name, "listEntrypoints")) {
		char *res = r2_cmd (ss, "ies");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle listLibraries tool
	if (!strcmp (tool_name, "listLibraries")) {
		char *res = r2_cmd (ss, "ilq");
		char *o = jsonrpc_tooltext_response (res);
		free (res);
		return o;
	}

	// Handle closeFile tool
	if (!strcmp (tool_name, "closeFile")) {
		if (ss->http_mode) {
			// do not close
			return jsonrpc_tooltext_response ("In r2pipe mode we won't close the file.");
		}
		if (core) {
			r2_run_cmd (ss, "o-*");
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

		r2_run_cmdf (ss, "'@%s'CC %s", address, message);
		return strdup ("ok");
	}

	// Handle setFunctionPrototype tool
	if (!strcmp (tool_name, "setFunctionPrototype")) {
		const char *address = r_json_get_str (tool_args, "address");
		const char *prototype = r_json_get_str (tool_args, "prototype");
		if (!address || !prototype) {
			return jsonrpc_error_response (-32602, "Missing required parameters: address and prototype", NULL, NULL);
		}
		r2_run_cmdf (ss, "'@%s'afs %s", address, prototype);
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
		char *err = r2_analyze (ss, level);
		char *result = r2_cmd (ss, "aflc");
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
		char *decompilersAvailable = r2_cmd (ss, "e cmd.pdc=?");
		const char *response = "ok";
		if (strstr (deco, "ghidra")) {
			if (strstr (decompilersAvailable, "pdg")) {
				r2_run_cmd (ss, "-e cmd.pdc=pdg");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "decai")) {
			if (strstr (decompilersAvailable, "decai")) {
				r2_run_cmd (ss, "-e cmd.pdc=decai -d");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "r2dec")) {
			if (strstr (decompilersAvailable, "pdd")) {
				r2_run_cmd (ss, "-e cmd.pdc=pdd");
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
		r2_run_cmd (ss, cmd);
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
		result = handle_list_tools (ss, params);
	} else if (!strcmp (method, "tools/call") || !strcmp (method, "tool/call")) {
		result = handle_call_tool (ss, params);
	} else {
		return jsonrpc_error_response (-32601, "Unknown method", id, NULL);
	}

	char *response = jsonrpc_success_response (ss, result, id);
	free (result);
	return response;
}

// Modified process_mcp_message to handle the protocol correctly
static void process_mcp_message(ServerState *ss, const char *msg) {
	r2mcp_log (ss, "<<<");
	r2mcp_log (ss, msg);

	RJson *request = r_json_parse ( (char *)msg);
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
			r2mcp_log (ss, ">>>");
			r2mcp_log (ss, response);

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
			r2mcp_log (ss, "Received cancelled notification");
		} else if (!strcmp (method, "notifications/initialized")) {
			r2mcp_log (ss, "Received initialized notification");
		} else {
			r2mcp_log (ss, "Received unknown notification");
		}
	}

	r_json_free (request);
}

// MCPO protocol-compliant direct mode loop
void r2mcp_eventloop(ServerState *ss) {
	r2mcp_log (ss, "Starting MCP direct mode (stdin/stdout)");

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
			while ( (msg = read_buffer_get_message (buffer)) != NULL) {
				r2mcp_log (ss, "Complete message received:");
				r2mcp_log (ss, msg);
				process_mcp_message (ss, msg);
				free (msg);
			}
		} else if (bytes_read == 0) {
			// EOF - stdin closed
			r2mcp_log (ss, "End of input stream - exiting");
			break;
		} else {
			// Error
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				r2mcp_log (ss, "Read error");
				break;
			}
		}
	}

	read_buffer_free (buffer);
	r2mcp_log (ss, "Direct mode loop terminated");
}
