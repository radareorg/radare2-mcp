# Agentic Coding Guidelines for r2mcp

MCP server for radare2. Source lives in `src/`. Files named `*.inc.c` are `#include`d into other `.c` files — they are not separate compilation units.

## Build & Test

- `make -C src -j` — fast incremental build (from repo root)
- `make -C src asan` — AddressSanitizer build
- `make -C src fmt` — auto-format with `clang-format-radare2`
- `src/r2mcp -h` — CLI help
- `src/r2mcp -t` — list available tools
- `src/r2mcp -T 'open_file file_path="/bin/ls"; list_functions; close_file'` — run DSL tests
- `make test` — run test suite (`test.sh`, `test2.sh`)

## Code Style

- **Tabs** for indentation
- Space before parens: `foo ()`, `if (`, `for (`
- Always use braces `{}` even for single-statement blocks
- Declare loop variables before `for` (C89 style)
- Prefer `!strcmp ()` over `strcmp () == 0`
- Prefer `r_str_startswith ()` over `!strncmp ()`
- Use `R_STR_ISEMPTY()` / `R_STR_ISNOTEMPTY()` instead of manual null+empty checks
- Use `R_RETURN_VAL_IF_FAIL()` / `R_RETURN_IF_FAIL()` for preconditions in `R_API` functions
- Use `R_LOG_ERROR()`, `R_LOG_WARN()`, `R_LOG_INFO()` for diagnostics

## Memory

- `R_NEW()` / `R_NEW0()` — assumed never to return NULL
- `R_FREE(ptr)` — frees and sets to NULL
- No NULL-check before `free()` or `*_free()` helpers
- `r_str_newf()` for formatted string allocation (not manual malloc+snprintf)
- `RStrBuf` for building strings in loops:
  ```c
  RStrBuf *sb = r_strbuf_new ("");
  r_strbuf_appendf (sb, "...", ...);
  return r_strbuf_drain (sb); // caller frees
  ```
- `r_json_parse()` does NOT own the input buffer — caller must free it separately after `r_json_free()`

## JSON (PJ API)

Build JSON responses with the `pj_*` helpers:
```c
PJ *pj = pj_new ();
pj_o (pj);           // open object
pj_ks (pj, "type", "text"); // key-string
pj_ki (pj, "count", 5);     // key-int
pj_kb (pj, "ok", true);     // key-bool
pj_k (pj, "items"); pj_a (pj); /* ... */ pj_end (pj); // key + array
pj_end (pj);         // close object
return pj_drain (pj); // extract string, free builder
```

Parse with `r_json_parse()`, query with `r_json_get()` / `r_json_get_str()` / `r_json_get_num()`. Check types via `field->type == R_JSON_STRING`, etc.

## Adding Tools

Tool handler signature — returns heap-allocated JSON, caller frees:
```c
static char *tool_example(ServerState *ss, RJson *tool_args) { ... }
```

Register in `tool_specs[]` array in `tools.c`:
```c
{ "tool_name", "description", "{\"type\":\"object\",\"properties\":{...}}", TOOL_MODE_NORMAL, tool_example },
```

Tool modes are a bitmask: `TOOL_MODE_MINI`, `TOOL_MODE_HTTP`, `TOOL_MODE_NORMAL`, `TOOL_MODE_RO`, `TOOL_MODE_SESSIONS`, `TOOL_MODE_FRIDA`. Combine with `|`.

Implementation pattern:
1. Validate params: `validate_required_string_param()`, `validate_address_param()`
2. On failure: `return jsonrpc_error_missing_param("param_name");`
3. Execute r2 command: `r2mcp_cmd(ss, "cmd")` or `r2mcp_cmdf(ss, "cmd %s", arg)`
4. Wrap result: `return tool_cmd_response(res);` (wraps in JSON + frees `res`)
5. Or build custom response with `jsonrpc_tooltext_response()`, `jsonrpc_tooltext_response_paginated()`

Use `fx(ss)` prefix for commands that need Frida mode support (returns `":"` or `""`).

## Protocol

- JSON-RPC 2.0. Notifications (no `id`) must not produce a response.
- Use `jsonrpc_error_response()` / `jsonrpc_success_response()` for building responses.
- `r2_cmd_filter()` strips dangerous patterns (`!`, `$(...)`, `|`, `` ` ``, `>`) from r2 commands.

## Platform

- Use `R2__UNIX__` / `R2__WINDOWS__` for platform-specific code.
- No new dependencies — build only against radare2 headers (`r_core.h`, `r_util/*`).

## Logging

- `r2mcp_log()` / `r2mcp_log_pub()` for structured log capture around r2 operations
- `r2mcp_log_reset()` / `r2mcp_log_drain()` to manage log buffer lifecycle

## Working with `*.inc.c`

These are included into `r2mcp.c`. Keep functions `static`. For new public APIs, create a `.c` + `.h` pair instead.

## Patch Checklist

- `make -C src -j` compiles clean
- Exercise: `src/r2mcp -t`, `src/r2mcp -h`, and a direct-mode roundtrip
- New public APIs use `R_RETURN_*` macros
- Follows tab indentation and style rules above
- Flag style inconsistencies in the PR rather than applying large reformats
