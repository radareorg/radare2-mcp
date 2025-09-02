#pragma once

#include <stdbool.h>

typedef enum {
    TOOL_MODE_MINI   = 1 << 0,
    TOOL_MODE_HTTP   = 1 << 1,
    TOOL_MODE_NORMAL = 1 << 2,
} ToolMode;

typedef struct {
    const char *name;
    const char *description;
    const char *schema_json;
    int modes; // bitmask of ToolMode
} ToolSpec;

// Initialize and shutdown the tools registry stored in ServerState
#include "r2mcp.h"
void tools_registry_init(ServerState *ss);
void tools_registry_fini(ServerState *ss);

// Build catalog JSON for the current server mode with optional pagination
char *tools_build_catalog_json(const ServerState *ss, const char *cursor, int page_size);

// Check if a tool is allowed for the current mode (honors permissive flag)
bool tools_is_tool_allowed(const ServerState *ss, const char *name);
