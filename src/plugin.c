/* r2mcp - MIT - Copyright 2025-2026 - pancake */

#define R_LOG_ORIGIN "core.r2mcp"

#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"
#include "prompts.h"
#include "sessions.h"

#define R2MCP_DEFAULT_PLUGIN_PORT 8765
#define R2MCP_DEFAULT_SVC_URL "http://localhost:8080"

int r2mcp_run_dsl_tests(ServerState *ss, const char *dsl, RCore *core);

typedef struct r2mcp_data_t {
	ServerState *ss;
	RThread *http_thread;
	char *http_port;
	bool http_running;
} R2mcpData;

static bool r2mcp_cfg_has(RCore *core, const char *key) {
	return core && core->config && r_config_node_get (core->config, key);
}

static RConfigNode *r2mcp_cfg_set_b(RCore *core, const char *key, bool value, const char *desc) {
	RConfigNode *node = r_config_set_b (core->config, key, value);
	return r_config_node_desc (node, desc);
}

static RConfigNode *r2mcp_cfg_set_i(RCore *core, const char *key, int value, const char *desc) {
	RConfigNode *node = r_config_set_i (core->config, key, value);
	return r_config_node_desc (node, desc);
}

static RConfigNode *r2mcp_cfg_set_s(RCore *core, const char *key, const char *value, const char *desc) {
	RConfigNode *node = r_config_set (core->config, key, value);
	return r_config_node_desc (node, desc);
}

static void r2mcp_config_init(RCore *core) {
	if (!core || !core->config || r2mcp_cfg_has (core, "r2mcp.port")) {
		return;
	}
	bool was_locked = core->config->lock;
	if (was_locked) {
		r_config_lock (core->config, false);
	}
	RConfigNode *node = NULL;
	r2mcp_cfg_set_i (core, "r2mcp.port", R2MCP_DEFAULT_PLUGIN_PORT, "r2mcp HTTP server port for plugin mode");
	r2mcp_cfg_set_b (core, "r2mcp.log", false, "enable r2mcp debug logging in plugin mode");
	r2mcp_cfg_set_s (core, "r2mcp.logfile", "", "file path to append r2mcp debug logs");
	r2mcp_cfg_set_s (core, "r2mcp.auth", "", "HTTP Bearer auth token for plugin server mode (use 'random' to generate)");
	r2mcp_cfg_set_b (core, "r2mcp.approve", false, "send tool calls to r2mcp.svc for approval before execution");
	r2mcp_cfg_set_s (core, "r2mcp.svc", "", "supervisor approval URL (default when approve is true: " R2MCP_DEFAULT_SVC_URL ")");
	r2mcp_cfg_set_b (core, "r2mcp.yolo", false, "accept tool calls without supervisor approval and expose dangerous tools");
	r2mcp_cfg_set_b (core, "r2mcp.mini", false, "expose the minimum r2mcp tool set");
	r2mcp_cfg_set_b (core, "r2mcp.permissive", false, "allow calling tools not exposed by the current mode");
	r2mcp_cfg_set_b (core, "r2mcp.run", false, "enable the dangerous run_command and run_javascript tools");
	r2mcp_cfg_set_b (core, "r2mcp.readonly", false, "expose only read-only tools");
	r2mcp_cfg_set_b (core, "r2mcp.ignore_analysis", false, "ignore the analysis level requested by analyze calls");
	r2mcp_cfg_set_b (core, "r2mcp.prompts", true, "load r2mcp prompts");
	r2mcp_cfg_set_s (core, "r2mcp.prompts.dir", "", "colon-separated prompt directories");
	r2mcp_cfg_set_s (core, "r2mcp.sandbox", "", "restrict open_file to this sandbox directory");
	r2mcp_cfg_set_s (core, "r2mcp.sandbox.grain", "", "radare2 sandbox grain mask (disk,files,exec,socket,network,environ,all,none)");
	node = r2mcp_cfg_set_s (core, "r2mcp.content", "text", "tool response content mode");
	r_config_node_add_option (node, "text");
	r_config_node_add_option (node, "json");
	r_config_node_add_option (node, "structured");
	r_config_node_add_option (node, "both");
	r2mcp_cfg_set_s (core, "r2mcp.enabled", "", "comma-separated allowlist of r2mcp tools");
	r2mcp_cfg_set_s (core, "r2mcp.disabled", "", "comma-separated denylist of r2mcp tools");
	r2mcp_cfg_set_b (core, "r2mcp.session_tools", false, "expose remote session management tools");
	r2mcp_cfg_set_b (core, "r2mcp.sessions", false, "enable HTTP X-Session-ID state multiplexing");
	r2mcp_cfg_set_i (core, "r2mcp.sessions.max", 8, "maximum HTTP X-Session-ID sessions");
	r2mcp_cfg_set_i (core, "r2mcp.sessions.timeout", 600, "idle timeout in seconds for HTTP X-Session-ID sessions");
	r2mcp_cfg_set_s (core, "r2mcp.decompiler", "", "decompiler command to assign to cmd.pdc");
	r2mcp_cfg_set_s (core, "r2mcp.baseurl", "", "remote r2 webserver URL for proxy mode instead of the live core");
	if (was_locked) {
		r_config_lock (core->config, true);
	}
}

static char *r2mcp_cfg_get_dup(RCore *core, const char *key) {
	const char *value = r_config_get (core->config, key);
	return R_STR_ISNOTEMPTY (value)? strdup (value): NULL;
}

static RList *r2mcp_cfg_get_list(RCore *core, const char *key) {
	const char *value = r_config_get (core->config, key);
	if (R_STR_ISEMPTY (value)) {
		return NULL;
	}
	RList *items = r_str_split_duplist (value, ",", true);
	RListIter *iter;
	char *item;
	r_list_foreach (items, iter, item) {
		r_str_trim (item);
	}
	return items;
}

static char *r2mcp_cfg_get_svc_url(RCore *core) {
	char *svc = r2mcp_cfg_get_dup (core, "r2mcp.svc");
	if (svc) {
		return svc;
	}
	if (r_config_get_b (core->config, "r2mcp.approve")) {
		return strdup (R2MCP_DEFAULT_SVC_URL);
	}
	return NULL;
}

static void r2mcp_state_free(ServerState *ss) {
	if (!ss) {
		return;
	}
	if (ss->load_prompts) {
		prompts_registry_fini (ss);
	}
	if (ss->sessions) {
		r2mcp_sessions_free (ss->sessions);
		ss->sessions = NULL;
	}
	r2mcp_state_fini (ss);
	free (ss->baseurl);
	free (ss->svc_baseurl);
	free (ss->auth_token);
	free (ss->sandbox);
	free (ss->sandbox_grain);
	free (ss->logfile);
	free (ss->prompts_dir);
	if (ss->enabled_tools) {
		r_list_free (ss->enabled_tools);
	}
	if (ss->disabled_tools) {
		r_list_free (ss->disabled_tools);
	}
	free (ss);
}

static ServerState *r2mcp_state_new_from_config(RCore *core) {
	ServerState *ss = R_NEW0 (ServerState);
	bool yolo = r_config_get_b (core->config, "r2mcp.yolo");
	char *content_mode = r2mcp_cfg_get_dup (core, "r2mcp.content");
	R2McpContentMode mode = r2mcp_content_mode_from_string (content_mode);
	free (content_mode);
	if (mode == R2MCP_CONTENT_INVALID) {
		R_LOG_WARN ("Invalid r2mcp.content value, using text");
		mode = R2MCP_CONTENT_TEXT;
	}
	ss->info.name = "Radare2 MCP Connector";
	ss->info.version = R2MCP_VERSION;
	ss->load_prompts = r_config_get_b (core->config, "r2mcp.prompts");
	ss->capabilities.tools = true;
	ss->capabilities.prompts = ss->load_prompts;
	ss->capabilities.resources = true;
	ss->instructions = "Use this server to analyze binaries with radare2";
	ss->initialized = false;
	ss->minimode = r_config_get_b (core->config, "r2mcp.mini");
	ss->readonly_mode = r_config_get_b (core->config, "r2mcp.readonly");
	ss->permissive_tools = yolo || r_config_get_b (core->config, "r2mcp.permissive");
	ss->enable_run_command_tool = yolo || r_config_get_b (core->config, "r2mcp.run");
	ss->log_enabled = r_config_get_b (core->config, "r2mcp.log");
	ss->use_sessions = r_config_get_b (core->config, "r2mcp.session_tools");
	ss->baseurl = r2mcp_cfg_get_dup (core, "r2mcp.baseurl");
	ss->http_mode = R_STR_ISNOTEMPTY (ss->baseurl);
	ss->svc_baseurl = yolo? NULL: r2mcp_cfg_get_svc_url (core);
	ss->auth_token = r2mcp_cfg_get_dup (core, "r2mcp.auth");
	if (ss->auth_token && !strcmp (ss->auth_token, "random")) {
		R_FREE (ss->auth_token);
		ss->auth_token = r2mcp_auth_token_random ();
		ss->auth_token_generated = true;
		if (!ss->auth_token) {
			R_LOG_ERROR ("Failed to generate r2mcp HTTP bearer token");
		}
	}
#if !R2MCP_HAS_HTTP_HEADERS
	if (R_STR_ISNOTEMPTY (ss->auth_token)) {
		R_LOG_WARN ("r2mcp.auth requires radare2 ABI >= 91");
		R_FREE (ss->auth_token);
	}
#endif
	ss->sandbox = r2mcp_cfg_get_dup (core, "r2mcp.sandbox");
	ss->sandbox_grain = r2mcp_cfg_get_dup (core, "r2mcp.sandbox.grain");
	ss->logfile = r2mcp_cfg_get_dup (core, "r2mcp.logfile");
	if (ss->logfile) {
		ss->log_enabled = true;
	}
	ss->prompts_dir = r2mcp_cfg_get_dup (core, "r2mcp.prompts.dir");
	ss->ignore_analysis_level = r_config_get_b (core->config, "r2mcp.ignore_analysis");
	ss->content_mode = mode;
	ss->enabled_tools = r2mcp_cfg_get_list (core, "r2mcp.enabled");
	ss->disabled_tools = r2mcp_cfg_get_list (core, "r2mcp.disabled");
	ss->frida_mode = false;
	ss->default_rstate.current_baddr = UT64_MAX;
	ss->default_rstate.analyze_level = -1;
	ss->rstate = &ss->default_rstate;
	if (!ss->http_mode) {
		r2mcp_state_use_core (ss, core);
	} else {
		ss->rstate->current_baddr = UT64_MAX;
		ss->rstate->analyze_level = -1;
	}
	if (ss->load_prompts) {
		prompts_registry_init (ss);
	}
	if (r_config_get_b (core->config, "r2mcp.sessions")) {
#if R2MCP_HAS_HTTP_HEADERS
		int max = (int)r_config_get_i (core->config, "r2mcp.sessions.max");
		int timeout = (int)r_config_get_i (core->config, "r2mcp.sessions.timeout");
		if (max <= 0) {
			max = 8;
		}
		if (timeout < 0) {
			timeout = 600;
		}
		ss->sessions = r2mcp_sessions_new (max, timeout);
#else
		R_LOG_WARN ("r2mcp.sessions requires radare2 ABI >= 91");
#endif
	}
	return ss;
}

static void r2mcp_apply_runtime_config(R2mcpData *data, RCore *core) {
	if (!data || !data->ss) {
		return;
	}
	bool yolo = r_config_get_b (core->config, "r2mcp.yolo");
	data->ss->log_enabled = r_config_get_b (core->config, "r2mcp.log");
	R_FREE (data->ss->logfile);
	data->ss->logfile = r2mcp_cfg_get_dup (core, "r2mcp.logfile");
	if (data->ss->logfile) {
		data->ss->log_enabled = true;
	}
	data->ss->permissive_tools = yolo || r_config_get_b (core->config, "r2mcp.permissive");
	data->ss->enable_run_command_tool = yolo || r_config_get_b (core->config, "r2mcp.run");
	R_FREE (data->ss->svc_baseurl);
	data->ss->svc_baseurl = yolo? NULL: r2mcp_cfg_get_svc_url (core);
}

static ServerState *r2mcp_ensure_state(R2mcpData *data, RCore *core) {
	if (!data->ss) {
		data->ss = r2mcp_state_new_from_config (core);
	} else {
		r2mcp_apply_runtime_config (data, core);
	}
	return data->ss;
}

static RThreadFunctionRet r2mcp_http_thread(RThread *th) {
	R2mcpData *data = th? (R2mcpData *)th->user: NULL;
	if (!data || !data->ss) {
		return R_TH_STOP;
	}
	r2mcp_running_set (1);
	data->http_running = true;
	r2mcp_eventloop_http (data->ss, data->http_port);
	data->http_running = false;
	return R_TH_STOP;
}

static bool r2mcp_http_start(RCore *core, R2mcpData *data) {
	if (data->http_thread && data->http_running) {
		r_cons_printf (core->cons, "r2mcp HTTP server is already running on port %s\n", data->http_port);
		return true;
	}
	if (data->http_thread) {
		r_th_wait (data->http_thread);
		r_th_free (data->http_thread);
		data->http_thread = NULL;
	}
	if (data->ss) {
		r2mcp_state_free (data->ss);
		data->ss = NULL;
	}
	R_FREE (data->http_port);
	data->http_port = r_str_newf ("%" PFMT64d, r_config_get_i (core->config, "r2mcp.port"));
	data->ss = r2mcp_state_new_from_config (core);
	const char *decompiler = r_config_get (core->config, "r2mcp.decompiler");
	if (R_STR_ISNOTEMPTY (decompiler)) {
		char *cmd = !strcmp (decompiler, "decai")? strdup ("e cmd.pdc=decai -d"): r_str_newf ("e cmd.pdc=%s", decompiler);
		char *res = r2mcp_cmd (data->ss, cmd);
		free (res);
		free (cmd);
	}
	data->http_thread = r_th_new (r2mcp_http_thread, data, 0);
	if (!data->http_thread) {
		r_cons_printf (core->cons, "Cannot create r2mcp HTTP thread\n");
		return false;
	}
	r_th_setname (data->http_thread, "r2mcp-http");
	data->http_running = true;
	if (!r_th_start (data->http_thread)) {
		r_cons_printf (core->cons, "Cannot start r2mcp HTTP thread\n");
		data->http_running = false;
		r_th_free (data->http_thread);
		data->http_thread = NULL;
		return false;
	}
	if (R_STR_ISNOTEMPTY (data->ss->auth_token)) {
		r_cons_printf (core->cons, "r2mcp HTTP bearer auth enabled\n");
		if (data->ss->auth_token_generated) {
			r_cons_printf (core->cons, "r2mcp HTTP bearer token: %s\n", data->ss->auth_token);
		}
	}
	r_cons_printf (core->cons, "r2mcp HTTP server starting on http://localhost:%s/\n", data->http_port);
	return true;
}

static void r2mcp_http_stop(RCore *core, R2mcpData *data) {
	if (!data->http_thread) {
		r_cons_printf (core->cons, "r2mcp HTTP server is not running\n");
		return;
	}
	r2mcp_break ();
	r_th_wait (data->http_thread);
	r_th_free (data->http_thread);
	data->http_thread = NULL;
	data->http_running = false;
	r_cons_printf (core->cons, "r2mcp HTTP server stopped\n");
}

static void r2mcp_http_status(RCore *core, R2mcpData *data) {
	ServerState *ss = data? data->ss: NULL;
	const char *port = data && data->http_port? data->http_port: "";
	r_cons_printf (core->cons, "http: %s\n", (data && data->http_thread && data->http_running)? "running": "stopped");
	if (R_STR_ISNOTEMPTY (port)) {
		r_cons_printf (core->cons, "url: http://localhost:%s/\n", port);
	}
	r_cons_printf (core->cons, "log: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.log")));
	r_cons_printf (core->cons, "approve: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.approve")));
	r_cons_printf (core->cons, "yolo: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.yolo")));
	if (ss && R_STR_ISNOTEMPTY (ss->svc_baseurl)) {
		r_cons_printf (core->cons, "svc: %s\n", ss->svc_baseurl);
	}
	r_cons_printf (core->cons, "auth: %s\n", (ss && R_STR_ISNOTEMPTY (ss->auth_token))? "enabled": "disabled");
	r_cons_printf (core->cons, "content: %s\n", r_config_get (core->config, "r2mcp.content"));
	r_cons_printf (core->cons, "readonly: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.readonly")));
	r_cons_printf (core->cons, "permissive: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.permissive")));
	r_cons_printf (core->cons, "run_command: %s\n", r_str_bool (r_config_get_b (core->config, "r2mcp.run")));
}

static void r2mcp_print_help(RCore *core) {
	r_cons_printf (core->cons,
		"Usage: r2mcp[?] [subcommand]\n"
		" r2mcp                 list tools\n"
		" r2mcp http|start      start HTTP MCP server in background\n"
		" r2mcp stop            stop HTTP MCP server\n"
		" r2mcp restart         restart HTTP MCP server\n"
		" r2mcp status          show plugin server status\n"
		" r2mcp logs on|off     enable or disable plugin debug logs\n"
		" r2mcp logs file <path> set r2mcp.logfile and enable logs\n"
		" r2mcp approve on|off  enable or disable supervisor approval\n"
		" r2mcp approve url <u> set supervisor URL\n"
		" r2mcp yolo on|off     accept calls without approval and expose dangerous tools\n"
		" r2mcp config          show r2mcp.* eval keys\n"
		" r2mcp <dsl>           run existing tool DSL\n");
}

static void r2mcp_print_config(RCore *core) {
	r_cons_printf (core->cons,
		"r2mcp.port\n"
		"r2mcp.log\n"
		"r2mcp.logfile\n"
		"r2mcp.auth\n"
		"r2mcp.approve\n"
		"r2mcp.svc\n"
		"r2mcp.yolo\n"
		"r2mcp.mini\n"
		"r2mcp.permissive\n"
		"r2mcp.run\n"
		"r2mcp.readonly\n"
		"r2mcp.ignore_analysis\n"
		"r2mcp.prompts\n"
		"r2mcp.prompts.dir\n"
		"r2mcp.sandbox\n"
		"r2mcp.sandbox.grain\n"
		"r2mcp.content\n"
		"r2mcp.enabled\n"
		"r2mcp.disabled\n"
		"r2mcp.session_tools\n"
		"r2mcp.sessions\n"
		"r2mcp.sessions.max\n"
		"r2mcp.sessions.timeout\n"
		"r2mcp.decompiler\n"
		"r2mcp.baseurl\n");
}

static void r2mcp_set_bool_command(RCore *core, const char *key, const char *arg) {
	if (R_STR_ISEMPTY (arg) || !strcmp (arg, "status")) {
		r_cons_printf (core->cons, "%s=%s\n", key, r_str_bool (r_config_get_b (core->config, key)));
		return;
	}
	if (!strcmp (arg, "on") || !strcmp (arg, "true") || !strcmp (arg, "1")) {
		r_config_set_b (core->config, key, true);
	} else if (!strcmp (arg, "off") || !strcmp (arg, "false") || !strcmp (arg, "0")) {
		r_config_set_b (core->config, key, false);
	} else {
		r_cons_printf (core->cons, "Expected on/off\n");
	}
}

static void r2mcp_handle_logs(RCore *core, R2mcpData *data, const char *args) {
	const char *arg = r_str_trim_head_ro (args);
	if (r_str_startswith (arg, "file ")) {
		const char *path = r_str_trim_head_ro (arg + 5);
		r_config_set (core->config, "r2mcp.logfile", path);
		r_config_set_b (core->config, "r2mcp.log", true);
	} else {
		r2mcp_set_bool_command (core, "r2mcp.log", arg);
	}
	r2mcp_apply_runtime_config (data, core);
}

static void r2mcp_handle_approve(RCore *core, R2mcpData *data, const char *args) {
	const char *arg = r_str_trim_head_ro (args);
	if (r_str_startswith (arg, "url ")) {
		const char *url = r_str_trim_head_ro (arg + 4);
		r_config_set (core->config, "r2mcp.svc", url);
		r_config_set_b (core->config, "r2mcp.approve", true);
		r_config_set_b (core->config, "r2mcp.yolo", false);
	} else {
		r2mcp_set_bool_command (core, "r2mcp.approve", arg);
		if (r_config_get_b (core->config, "r2mcp.approve")) {
			r_config_set_b (core->config, "r2mcp.yolo", false);
		}
	}
	r2mcp_apply_runtime_config (data, core);
}

static void r2mcp_handle_yolo(RCore *core, R2mcpData *data, const char *args) {
	r2mcp_set_bool_command (core, "r2mcp.yolo", r_str_trim_head_ro (args));
	if (r_config_get_b (core->config, "r2mcp.yolo")) {
		r_config_set_b (core->config, "r2mcp.approve", false);
	}
	r2mcp_apply_runtime_config (data, core);
}

static bool r2mcp_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	R2mcpData *data = cps->data;

	if (!r_str_startswith (input, "r2mcp")) {
		return false;
	}

	r2mcp_config_init (core);
	const char *args = r_str_trim_head_ro (input + strlen ("r2mcp"));
	if (!strcmp (args, "?") || !strcmp (args, "help")) {
		r2mcp_print_help (core);
		return true;
	}
	if (R_STR_ISEMPTY (args) || !strcmp (args, "tools")) {
		tools_print_table (r2mcp_ensure_state (data, core));
		return true;
	}
	if (!strcmp (args, "http") || !strcmp (args, "start")) {
		r2mcp_http_start (core, data);
		return true;
	}
	if (!strcmp (args, "stop")) {
		r2mcp_http_stop (core, data);
		return true;
	}
	if (!strcmp (args, "restart")) {
		r2mcp_http_stop (core, data);
		r2mcp_http_start (core, data);
		return true;
	}
	if (!strcmp (args, "status")) {
		r2mcp_http_status (core, data);
		return true;
	}
	if (!strcmp (args, "config")) {
		r2mcp_print_config (core);
		return true;
	}
	if (r_str_startswith (args, "logs")) {
		r2mcp_handle_logs (core, data, args + 4);
		return true;
	}
	if (r_str_startswith (args, "approve")) {
		r2mcp_handle_approve (core, data, args + 7);
		return true;
	}
	if (r_str_startswith (args, "yolo")) {
		r2mcp_handle_yolo (core, data, args + 4);
		return true;
	}

	if (r2mcp_run_dsl_tests (r2mcp_ensure_state (data, core), args, core) != 0) {
		R_LOG_ERROR ("Error executing r2mcp command");
	}
	return true;
}

static bool r2mcp_init(RCorePluginSession *cps) {
	R2mcpData *data = R_NEW0 (R2mcpData);
	cps->data = data;
	r2mcp_config_init (cps->core);
	return true;
}

static bool r2mcp_fini(RCorePluginSession *cps) {
	R2mcpData *data = cps->data;
	if (data) {
		if (data->http_thread) {
			r2mcp_http_stop (cps->core, data);
		}
		r2mcp_state_free (data->ss);
		free (data->http_port);
		free (data);
	}
	return true;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_r2mcp = {
	.meta = {
		.name = "r2mcp",
		.desc = "r2mcp command integration for radare2",
		.author = "pancake",
		.license = "MIT",
	},
	.call = r2mcp_call,
	.init = r2mcp_init,
	.fini = r2mcp_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2mcp,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
