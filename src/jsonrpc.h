#ifndef JSONRPC_H
#define JSONRPC_H

#include <r_core.h>
#include "r2mcp.h"

char *jsonrpc_tooltext_response(const char *text);
char *jsonrpc_tooltext_response_paginated(const char *text, bool has_more, const char *next_cursor);
char *jsonrpc_tool_response(const char *text, const char *structured_json, R2McpContentMode mode);
char *jsonrpc_tool_response_paginated(const char *text, const char *structured_json, R2McpContentMode mode, bool has_more, const char *next_cursor);
char *jsonrpc_error_response(int code, const char *message, const char *id, const char *uri);
char *jsonrpc_success_response(ServerState *ss, const char *result, const char *id);
char *jsonrpc_error_response_typed(int code, const char *message, const char *id, bool id_is_number, const char *uri);
char *jsonrpc_success_response_typed(ServerState *ss, const char *result, const char *id, bool id_is_number);
char *jsonrpc_error_missing_param(const char *param_name);
char *jsonrpc_error_tool_not_allowed(const char *tool_name);
char *jsonrpc_error_file_required(void);

#endif
