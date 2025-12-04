/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/pj.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include "jsonrpc.h"

#if defined(R2__UNIX__)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#elif defined(R2__WINDOWS__)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <signal.h>
#else
#error please define R2__WINDOWS__ or R2__UNIX__ for platform detection
#endif
#include "config.h"
#include "r2mcp.h"
#include "tools.h"
#include "prompts.h"

#define R2MCP_DEBUG 1

#ifndef R2MCP_VERSION
#warning R2MCP_VERSION is not defined
#define R2MCP_VERSION "1.5.0"
#endif

#define JSON_RPC_VERSION "2.0"
#define MCP_VERSION "2024-11-05"
#define READ_CHUNK_SIZE 32768
#define LATEST_PROTOCOL_VERSION "2024-11-05"

#include "utils.inc.c"
#include "r2api.inc.c"

static volatile sig_atomic_t running = 1;
void r2mcp_running_set(int value) {
	running = value? 1: 0;
}

// Local I/O mode helper (moved from utils.inc.c to avoid unused warnings in other TUs)
static void set_nonblocking_io(bool nonblocking) {
#if defined(R2__UNIX__)
	int flags = fcntl (STDIN_FILENO, F_GETFL, 0);
	if (nonblocking) {
		fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	} else {
		fcntl (STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
	}
	setvbuf (stdout, NULL, _IOLBF, 0);
#elif defined(R2__WINDOWS__)
	// Windows doesn't support POSIX fcntl/O_NONBLOCK on stdin reliably.
	// We set stdin mode to binary/text depending on requested mode and
	// keep line-buffered stdout. This is a best-effort no-op for nonblocking.
	if (nonblocking) {
		_setmode (_fileno (stdin), _O_BINARY);
	} else {
		_setmode (_fileno (stdin), _O_TEXT);
	}
	setvbuf (stdout, NULL, _IOLBF, 0);
#else
	(void)nonblocking;
#endif
}

/* Public wrappers to expose internal static helpers from r2api.inc.c */
bool r2mcp_state_init(ServerState *ss) {
	RCore *core = r_core_new ();
	if (!core) {
		R_LOG_ERROR ("Failed to initialize radare2 core");
		return false;
	}

	r2state_settings (core);
	ss->rstate.core = core;

	R_LOG_INFO ("Radare2 core initialized");
	r_log_add_callback (logcb, ss);
	return true;
}

void r2mcp_state_fini(ServerState *ss) {
	RCore *core = ss->rstate.core;
	if (core) {
		r_core_free (core);
		r_strbuf_free (ss->sb);
		ss->sb = NULL;
		ss->rstate.core = NULL;
		ss->rstate.file_opened = false;
		ss->rstate.current_file = NULL;
	}
}

char *r2mcp_cmd(ServerState *ss, const char *cmd) {
	if (ss && ss->http_mode) {
		char *res = r2cmd_over_http (ss, cmd);
		if (!res) {
			return strdup ("HTTP request failed");
		}
		return res;
	}
	RCore *core = ss->rstate.core;
	if (!core || !ss->rstate.file_opened) {
		return strdup ("Use the open_file method before calling any other method");
	}
	bool changed = false;
	char *filteredCommand = r2_cmd_filter (cmd, &changed);
	if (changed) {
		r2mcp_log (ss, "command injection prevented");
	}
	r2mcp_log_reset (ss);
	char *res = r_core_cmd_str (core, filteredCommand);
	char *err = r2mcp_log_drain (ss);
	free (filteredCommand);
	// r2state_settings (core);
	if (err) {
		char *newres = r_str_newf ("%s<log>\n%s\n</log>\n", res, err);
		free (res);
		res = newres;
	}
	return res;
}

void r2mcp_log_pub(ServerState *ss, const char *msg) {
	r2mcp_log (ss, msg);
}

// New wrappers to expose functionality from r2api.inc.c to other modules
bool r2mcp_open_file(ServerState *ss, const char *filepath) {
	return r2_open_file (ss, filepath);
}
char *r2mcp_analyze(ServerState *ss, int level) {
	return r2_analyze (ss, level);
}

static bool check_client_capability(ServerState *ss, const char *capability) {
	if (ss->client_capabilities) {
		RJson *cap = (RJson *)r_json_get (ss->client_capabilities, capability);
		return cap != NULL;
	}
	return false;
}

static bool check_server_capability(ServerState *ss, const char *capability) {
	if (!strcmp (capability, "tools")) {
		return ss->capabilities.tools;
	}
	if (!strcmp (capability, "prompts")) {
		return ss->capabilities.prompts;
	}
	if (!strcmp (capability, "resources")) {
		return ss->capabilities.resources;
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
	} else if (r_str_startswith (method, "resources/")) {
		if (!check_server_capability (ss, "resources")) {
			*error = strdup ("Server does not support resources");
			return false;
		}
	}
	return true;
}

// Helper function to create JSON-RPC error responses
// (moved to utils.inc.c earlier, keep this for compatibility if needed)
// static char *jsonrpc_error_response (int code, const char *message, const char *id, const char *uri) { ... }

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

	// Prompts capability - object with listChanged
	pj_k (pj, "prompts");
	pj_o (pj);
	pj_kb (pj, "listChanged", false);
	pj_end (pj);

	// Resources capability - empty object since we only support list
	pj_k (pj, "resources");
	pj_o (pj);
	pj_end (pj);

	// For any capability we don't support, don't include it at all
	// Don't add: roots, notifications, sampling

	pj_end (pj); // End capabilities

	if (ss->instructions) {
		pj_ks (pj, "instructions", ss->instructions);
	}

	pj_end (pj);

	ss->initialized = true;
	return pj_drain (pj);
}

static char *handle_list_tools(ServerState *ss, RJson *params) {
	const char *cursor = r_json_get_str (params, "cursor");
	int page_size = 32;
	return tools_build_catalog_json (ss, cursor, page_size);
}

static char *handle_list_prompts(ServerState *ss, RJson *params) {
	const char *cursor = r_json_get_str (params, "cursor");
	int page_size = 32;
	return prompts_build_list_json (ss, cursor, page_size);
}

static char *handle_get_prompt(ServerState *ss, RJson *params) {
	const char *name = r_json_get_str (params, "name");
	if (!name) {
		return jsonrpc_error_response (-32602, "Missing required parameter: name", NULL, NULL);
	}
	RJson *args = (RJson *)r_json_get (params, "arguments");
	char *prompt = prompts_get_json (ss, name, args);
	if (!prompt) {
		return jsonrpc_error_response (-32602, "Unknown prompt name", NULL, NULL);
	}
	return prompt;
}

// Thin wrapper that delegates to the tools module. This keeps r2mcp.c small
// and moves the tool-specific logic into tools.c where it belongs.
static char *handle_call_tool(ServerState *ss, const char *tool_name, RJson *tool_args) {
	return tools_call (ss, tool_name, tool_args);
}

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

	} else if (!strcmp (method, "tools/list") || !strcmp (method, "tool/list")) {
		result = handle_list_tools (ss, params);
	} else if (!strcmp (method, "tools/call") || !strcmp (method, "tool/call")) {
		const char *tool_name = r_json_get_str (params, "name");
		if (!tool_name) {
			tool_name = r_json_get_str (params, "tool");
		}
		RJson *tool_args = (RJson *)r_json_get (params, "arguments");
		if (!tool_args) {
			tool_args = (RJson *)r_json_get (params, "args");
		}
		if (ss->svc_baseurl) {
			PJ *pj = pj_new ();
			pj_o (pj);
			pj_ks (pj, "tool", tool_name);
			pj_k (pj, "arguments");
			pj_append_rjson (pj, tool_args);
			pj_k (pj, "available_tools");
			pj_a (pj);
			for (size_t i = 0; tool_specs[i].name; i++) {
				pj_s (pj, tool_specs[i].name);
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
						return jsonrpc_error_response (-32000, err, id, NULL);
					}
					const char *r2cmd = r_json_get_str (rj, "r2cmd");
					if (r2cmd) {
						char *cmd_out = r2mcp_cmd (ss, r2cmd);
						char *res = jsonrpc_tooltext_response (cmd_out? cmd_out: "");
						free (cmd_out);
						r_json_free (rj);
						result = res;
					} else {
						const char *new_tool = r_json_get_str (rj, "tool");
						const RJson *new_args = r_json_get (rj, "arguments");
						if (new_tool && strcmp (new_tool, tool_name)) {
							tool_name = new_tool;
						}
						if (new_args) {
							tool_args = (RJson *)new_args;
						}
						result = handle_call_tool (ss, tool_name, tool_args);
						r_json_free (rj);
					}
				} else {
					result = handle_call_tool (ss, tool_name, tool_args);
				}
			} else {
				result = handle_call_tool (ss, tool_name, tool_args);
			}
		} else {
			result = handle_call_tool (ss, tool_name, tool_args);
		}
	} else if (!strcmp (method, "prompts/list") || !strcmp (method, "prompt/list")) {
		result = handle_list_prompts (ss, params);
	} else if (!strcmp (method, "prompts/get") || !strcmp (method, "prompt/get")) {
		result = handle_get_prompt (ss, params);
	} else if (!strcmp (method, "resources/list")) {
		result = strdup ("{\"resources\":[]}");
	} else if (!strcmp (method, "resources/templates/list")) {
		result = strdup ("{\"resourceTemplates\":[]}");
	} else {
		return jsonrpc_error_response (-32601, "Unknown method", id, NULL);
	}

	char *response = jsonrpc_success_response (ss, result, id);
	free (result);
	return response;
}

// Send a JSON-RPC response to stdout with proper framing
static void send_response(ServerState *ss, const char *response) {
	if (!response) {
		return;
	}
	r2mcp_log (ss, ">>>");
	r2mcp_log (ss, response);
	size_t len = strlen (response);
	write (STDOUT_FILENO, response, len);
	if (len == 0 || response[len - 1] != '\n') {
		write (STDOUT_FILENO, "\n", 1);
	}
#if R2__UNIX__
	fsync (STDOUT_FILENO);
#endif
}

// Process a JSON-RPC message from the client
static void process_mcp_message(ServerState *ss, const char *msg) {
	r2mcp_log (ss, "<<<");
	r2mcp_log (ss, msg);

	RJson *request = r_json_parse ((char *)msg);
	if (!request) {
		char *err = jsonrpc_error_response (-32700, "Parse error: invalid JSON", NULL, NULL);
		send_response (ss, err);
		free (err);
		return;
	}

	RJson *id_json = (RJson *)r_json_get (request, "id");
	const char *method = r_json_get_str (request, "method");
	RJson *params = (RJson *)r_json_get (request, "params");

	// Extract id for error responses (may be NULL for notifications)
	const char *id = NULL;
	char id_buf[32] = { 0 };
	if (id_json) {
		if (id_json->type == R_JSON_STRING) {
			id = id_json->str_value;
		} else if (id_json->type == R_JSON_INTEGER) {
			snprintf (id_buf, sizeof (id_buf), "%lld", (long long)id_json->num.u_value);
			id = id_buf;
		}
	}

	if (!method) {
		// Per JSON-RPC 2.0, missing method is an invalid request
		char *err = jsonrpc_error_response (-32600, "Invalid Request: missing method", id, NULL);
		send_response (ss, err);
		free (err);
		r_json_free (request);
		return;
	}

	if (id_json) {
		// Request: requires a response
		char *response = handle_mcp_request (ss, method, params, id);
		if (response) {
			send_response (ss, response);
			free (response);
		}
	} else {
		// Notification: no response
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
			while ((msg = read_buffer_get_message (buffer)) != NULL) {
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
