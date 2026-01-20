#pragma once
#include <stdbool.h>
#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_strbuf.h>
#include "readbuffer.h"

/* Version fallback if not provided by build */
#ifndef R2MCP_VERSION
#define R2MCP_VERSION "1.5.2"
#endif

/* Pagination limits for tool responses */
#define R2MCP_DEFAULT_PAGE_SIZE 1000
#define R2MCP_MAX_PAGE_SIZE 10000

typedef struct {
	const char *name;
	const char *version;
} ServerInfo;

typedef struct {
	bool tools;
	bool prompts;
	bool resources;
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
	bool minimode;
	bool permissive_tools; // allow calling tools not exposed for current mode
	bool enable_run_command_tool;
	/* When true operate in read-only mode: only expose non-mutating tools */
	bool readonly_mode;
	/* When true, operate in HTTP r2pipe client mode and do NOT use r2 C APIs */
	bool http_mode;
	/* Base URL of the remote r2 webserver (if http_mode is true) */
	char *baseurl;
	/* Base URL of the supervisor control service (if set) */
	char *svc_baseurl;
	/* Optional sandbox path. When set, only allow opening files under this dir */
	char *sandbox;
	/* Optional path to append debug logs when set via -l */
	char *logfile;
	/* Optional custom prompts directory path */
	char *prompts_dir;
	/* When true, load prompts (false when -N flag is used) */
	bool load_prompts;
	/* When true, ignore the analysis level specified in analyze calls */
	bool ignore_analysis_level;
	const RJson *client_capabilities;
	const RJson *client_info;
	RadareState rstate;
	RStrBuf *sb;
	/* Optional whitelist of tool names enabled via command line -e options.
	 * When non-NULL, only tools whose name appears in this list will be
	 * registered in the runtime tools registry. Items are heap-allocated
	 * strings and the list should be created with `r_list_newf(free)`.
	 */
	RList *enabled_tools;
	void *prompts; // registry of PromptSpec* (RList*), opaque here
} ServerState;

/* Entry point wrapper implemented in r2mcp.c */
int r2mcp_main(int argc, const char **argv);

/* Exposed helpers implemented in r2mcp.c */
void setup_signals(void);
void r2mcp_eventloop(ServerState *ss);
void r2mcp_help(void);
void r2mcp_version(void);
void r2mcp_running_set(int value);

/* Public wrappers for internal r2 helpers (implemented in r2mcp.c) */
bool r2mcp_state_init(ServerState *ss);
void r2mcp_state_fini(ServerState *ss);
char *r2mcp_cmd(ServerState *ss, const char *cmd);
char *r2mcp_cmdf(ServerState *ss, const char *fmt, ...);
void r2mcp_log_pub(ServerState *ss, const char *msg);

// Additional public wrappers exposed so other modules (eg. tools.c) can use
// functionality implemented in r2api.inc.c. These simply forward to the
// internal static helpers so we keep the original separation.
bool r2mcp_open_file(ServerState *ss, const char *filepath);
char *r2mcp_analyze(ServerState *ss, int level);

// Run a small domain-specific language (DSL) used for testing tools from the
// command-line. The DSL describes a sequence of tool calls with arguments and
// prints their results. If core is provided, output goes to r2 console, else stdout.
// Returns 0 on success, non-zero on failure.
int r2mcp_run_dsl_tests(ServerState *ss, const char *dsl, RCore *core);

// HTTP POST helper for svc communication
char *curl_post_capture(const char *url, const char *msg, int *exit_code_out);
