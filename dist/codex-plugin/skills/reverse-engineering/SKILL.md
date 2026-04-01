---
name: reverse-engineering
description: Use the bundled r2mcp MCP server for binary analysis, disassembly, and reverse-engineering tasks.
---

Use the bundled `r2mcp` MCP tools when the user asks about binaries, executables, libraries, firmware, shellcode, functions, symbols, strings, control flow, or patching with radare2.

Preferred workflow:

1. Open the target file or session first.
2. Run the minimum analysis needed for the task.
3. Prefer structured r2mcp tools over raw command execution when both are available.
4. Summarize findings in reverse-engineering terms the user can act on.
5. Close files or sessions when the task is finished.

Be explicit about uncertainty when analysis is partial or when the binary has not been fully analyzed yet.
