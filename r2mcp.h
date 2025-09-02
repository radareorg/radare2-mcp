#pragma once
#include <stdbool.h>
#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_strbuf.h>
#include "readbuffer.h"

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
    bool minimode;
    bool permissive_tools; // allow calling tools not exposed for current mode
    /* When true, operate in HTTP r2pipe client mode and do NOT use r2 C APIs */
    bool http_mode;
    /* Base URL of the remote r2 webserver (if http_mode is true) */
    char *baseurl;
    const RJson *client_capabilities;
    const RJson *client_info;
    RadareState rstate;
    RStrBuf *sb;
    void *tools; // registry of ToolSpec* (RList*), opaque here
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
void r2mcp_log_pub(const char *msg);

/* Version fallback if not provided by build */
#ifndef R2MCP_VERSION
#define R2MCP_VERSION "1.1.0"
#endif
