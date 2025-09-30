# Agentic Coding Guidelines for the r2mcp (radare2 MCP) server

This document contains repository- and project-specific guidance for editing and building the r2mcp server. It augments the general AGENTS rules and encodes conventions observed in `src/`.

**Scope**
- The primary source lives in `src/`. Small helper headers and include-fragments (files named `*.inc.c`) are included into TUs and must be treated accordingly.

**Repository layout (important files)**
- `src/main.c` - program entry, CLI parsing, signal setup and high-level program lifecycle.
- `src/r2mcp.c` - main server machinery: JSON-RPC handling, event loop, dispatch to `tools` and `prompts` registries.
- `src/tools.c`, `src/prompts.c` - registries and implementations for tools and prompts.
- `src/readbuffer.c` - framed message reader used by the MCP direct mode loop.
- `src/r2api.inc.c`, `src/utils.inc.c` - implementation fragments included into `r2mcp.c`. These are not separate compilation units.
- `src/r2mcp.h`, `src/tools.h`, `src/readbuffer.h`, `src/prompts.h` - public headers for the modules above.

Coding style and rules (project-specific)
- Indentation: use TABS for indentation (project convention).
- Function calls: include a space before the parenthesis, e.g. `foo ()`.
- Always use braces `{}` for conditionals and loops, even if a single statement.
- `case` labels in `switch` statements must be aligned at the same column as other cases.
- Define loop variables before the `for` statement (older C style used in this codebase).
- Prefer `!strcmp ()` instead of `strcmp () == 0`.
- Use `R_RETURN_*` macros in public APIs (functions exported as `R_API`) to declare preconditions and avoid returning invalid values.

Memory and ownership
- `R_NEW`/`R_NEW0` macros in this project are assumed never to return NULL; code can rely on that.
- Do not check for NULL before calling `free` or other `*_free` helpers (the codebase follows this convention).
- `r_json_parse` does not take ownership of the input string: after calling `r_json_parse (buf)` and later `r_json_free (parser)`, the caller is still responsible for freeing the original buffer if it was dynamically allocated. When parsing string data that will be reused or freed, prefer calling `strdup` or ensure the buffer lifetime outlives the parser.
- When using `r_strbuf_free`, `r_core_free`, `r_list_free` or similar, pass only previously-initialized objects; do not NULL-check before freeing.

Build and test
- To quickly compile only the code in `src/`, run: `make -C src -j` (run this from the repo root or from `src/`). This avoids rebuilding unrelated targets.
- The primary output binary is `src/r2mcp`. Run `src/r2mcp -t` to list available tools and `src/r2mcp -h` for CLI help.
- Use `make -C src -j > /dev/null` when you want quieter output during iterative development.

Guidelines for editing the code
- Keep changes minimal and narrowly scoped; prefer fixing the root cause.
- When adding new tools or commands, implement a `?` subcommand to print help for that tool.
- Prefer using `r_str_newf` for formatted strings instead of manual `malloc` + `snprintf`.
- Avoid `r_str_append` for large concatenations; favour `RStrBuf *sb = r_strbuf_new (NULL);` and `r_strbuf_appendf` / `r_strbuf_append` loops, then `r_strbuf_drain` / `r_strbuf_free`.
- Use `r_str_pad2` to construct repeated-character strings when needed.
- When introducing new public APIs, follow the `R_API` and `R_RETURN_*` conventions already present in the repo.

Working with `*.inc.c` files
- Files such as `r2api.inc.c` and `utils.inc.c` are included into `r2mcp.c` (see `#include "utils.inc.c"`). They are not standalone translation units. Keep these files self-contained (no duplicate symbol definitions across other TUs) and avoid adding non-static global symbols there. If you need new public functions, prefer adding a `.c` + `.h` pair.

Logging and diagnostics
- This codebase uses `r2mcp_log`, `r2mcp_log_pub`, `r2mcp_log_reset` and `r2mcp_log_drain` for structured log capture surrounding r2 core operations. Use these helpers where appropriate so logs can be captured and emitted in responses.

JSON and protocol handling
- The server implements a JSON-RPC 2.0-like protocol. Use the existing helpers to build responses (`pj_new`/`pj_*` helpers in this repo) and follow existing patterns in `r2mcp.c` for success and error responses.
- For request parsing: `r_json_parse` returns a parser which must be freed with `r_json_free`. The code should then free the original message buffer if it was dynamically allocated.
- Distinguish between notifications (no `id` field) and requests (have `id`). Notifications must not produce a response.

Signals and event loop
- `setup_signals` is defined in `src/main.c`. Use `write` in signal handlers (no non-reentrant calls). Changing signal handling should be done with care.
- The main MCP direct mode loop is in `r2mcp_eventloop` in `r2mcp.c` and uses `readbuffer.c` to accumulate framed messages. When modifying framing or message parsing, update `readbuffer.c` accordingly and test the loop with piped input.

Incidental tips
- When making changes that affect only `src/` files, run `make -C src -j` from the repo root to recompile only `src/`.
- Avoid adding new dependencies. This project expects to build against existing radare2 headers (`r_core.h`, `r_util/*`).
- When adding tests or additional tooling, prefer placing small test drivers under `b/` (repo already uses `b/` for auxiliary build/test files).

Checklist before submitting a patch
- Run `make -C src -j` and exercise the binary: `src/r2mcp -t`, `src/r2mcp -h`, and a simple direct-mode message roundtrip using `printf` or `jq`.
- Ensure all new public APIs use `R_RETURN_*` where appropriate.
- Follow TAB indentation and other style rules above.

If something in the codebase looks inconsistent with these rules, point it out in the PR rather than applying large style-only changes across many files.
