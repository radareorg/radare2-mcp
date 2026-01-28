/* r2mcp - MIT - Copyright 2025 - pancake */

#define R_LOG_ORIGIN "core.r2mcp"

#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"

int r2mcp_run_dsl_tests(ServerState *ss, const char *dsl, RCore *core);

typedef struct r2mcp_data_t {
	ServerState *ss;
} R2mcpData;

// Global data for old API (no session support)
static R2mcpData *global_data = NULL;

#if R2_VERSION_NUMBER >= 50909

static bool r2mcp_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	R2mcpData *data = cps->data;

	if (!r_str_startswith (input, "r2mcp")) {
		return false;
	}

	// Skip "r2mcp" command name
	const char *args = r_str_trim_head_ro (input + strlen ("r2mcp"));

	// Initialize server state if not already done
	if (!data->ss) {
		data->ss = R_NEW0 (ServerState);
		// Initialize the tools registry
		// Set up the core reference
		data->ss->rstate.core = core;
		data->ss->rstate.file_opened = true; // We're already in r2 with a file
	}

	if (R_STR_ISEMPTY (args)) {
		tools_print_table (data->ss);
	} else {
		if (r2mcp_run_dsl_tests (data->ss, args, core) != 0) {
			R_LOG_ERROR ("Error executing r2mcp command");
		}
	}

	return true;
}

static bool r2mcp_init(RCorePluginSession *cps) {
	R2mcpData *data = R_NEW0 (R2mcpData);
	cps->data = data;
	return true;
}

static bool r2mcp_fini(RCorePluginSession *cps) {
	R2mcpData *data = cps->data;
	if (data) {
		if (data->ss) {
			free (data->ss);
		}
		free (data);
	}
	return true;
}

#else // R2_VERSION_NUMBER < 50909 (old API)

static int r2mcp_call(void *user, const char *input) {
	RCore *core = (RCore *)user;

	if (!r_str_startswith (input, "r2mcp")) {
		return false;
	}

	// Skip "r2mcp" command name
	const char *args = r_str_trim_head_ro (input + strlen ("r2mcp"));

	// Initialize global data if not already done
	if (!global_data) {
		global_data = R_NEW0 (R2mcpData);
	}

	// Initialize server state if not already done
	if (!global_data->ss) {
		global_data->ss = R_NEW0 (ServerState);
		// Set up the core reference
		global_data->ss->rstate.core = core;
		global_data->ss->rstate.file_opened = true; // We're already in r2 with a file
	}

	if (R_STR_ISEMPTY (args)) {
		tools_print_table (global_data->ss);
	} else {
		if (r2mcp_run_dsl_tests (global_data->ss, args, core) != 0) {
			R_LOG_ERROR ("Error executing r2mcp command");
		}
	}

	return true;
}

static int r2mcp_init(void *user, const char *input) {
	(void)user;
	(void)input;
	return true;
}

static int r2mcp_fini(void *user, const char *input) {
	(void)user;
	(void)input;
	if (global_data) {
		if (global_data->ss) {
			free (global_data->ss);
		}
		free (global_data);
		global_data = NULL;
	}
	return true;
}

#endif

// PLUGIN Definition Info
RCorePlugin r_core_plugin_r2mcp = {
	.meta = {
		.name = "core-r2mcp",
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
#if R2_VERSION_NUMBER >= 50909
	.abiversion = R2_ABIVERSION
#endif
};
#endif
