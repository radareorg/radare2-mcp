#pragma once

#include <stdbool.h>
#include "r2mcp.h"

typedef enum {
	TOOL_MODE_MINI = 1 << 0,
	TOOL_MODE_HTTP = 1 << 1,
	TOOL_MODE_NORMAL = 1 << 2,
} ToolMode;

typedef struct {
	const char *name;
	const char *description;
	const char *schema_json;
	int modes; // bitmask of ToolMode
} ToolSpec;

// Tool handler signature: returns heap-allocated JSON string describing
// the tool result (typically jsonrpc_tooltext_response() content or other
// structured JSON). Caller must free the returned string.
typedef char *(*ToolHandler)(ServerState *ss, RJson *args);

// Tool flags (for future use). For now, we use one to require an open file.
#define TOOL_FLAG_REQUIRES_OPENFILE (1 << 0)

// Initialize and shutdown the tools registry stored in ServerState
void tools_registry_init(ServerState *ss);
void tools_registry_fini(ServerState *ss);

// Build catalog JSON for the current server mode with optional pagination
char *tools_build_catalog_json(const ServerState *ss, const char *cursor, int page_size);

// Check if a tool is allowed for the current mode (honors permissive flag)
bool tools_is_tool_allowed(const ServerState *ss, const char *name);

// Call a tool by name; returns heap-allocated JSON (tool "result") or
// a JSON error result if the tool is unavailable or arguments are invalid.
// The returned string must be freed by the caller.
char *tools_call(ServerState *ss, const char *tool_name, RJson *args);
