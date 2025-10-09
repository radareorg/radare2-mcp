# SuperVisor Console for r2mcp

## Overview

The R2 MCP SBC (Supervisor Control) acts as a supervisor for every tool execution within the R2 MCP (Model Context Protocol) environment. It provides an additional layer of protection and control over what agents execute in headless MCP sessions, where users typically lack real-time oversight.

## Purpose

While some MCP agents offer built-in controls like accept, execute, cancel, reject, or JOLO (Just One Look Over) modes, these capabilities depend on the specific agent implementation rather than the MCP itself. The R2 MCP SBC extends these protection capabilities universally, allowing any agent to benefit from enhanced supervision.

## How It Works

When running the R2 MCP SBC service, it collects all calls made to R2 MCP tools. Upon receiving a connection from an MCP instance, the SBC provides users with options to:

- **Accept**: Allow the tool call to proceed as requested
- **Reject**: Block the tool call entirely
- **Modify**: Alter the query or parameters before execution
- **Respond with Error**: Return a custom error message
- **Provide Different Instructions**: Substitute alternative instructions

## Integration with R2 MCP

The SBC integrates seamlessly with R2 MCP through a simple flag-based mechanism:

- Run R2 MCP with a specific flag specifying the SBC host and port
- R2 MCP will then execute tool calls against the target SBC URL
- The SBC service receives these connections and prompts the user via command-line interface for the desired action

## Control Protocol

The supervision control is implemented using JSON over HTTP, ensuring compatibility and ease of integration.

## User Interface

The SBC provides a command-line tool interface for user interaction and decision-making.

## Default Behavior

By default, R2 MCP operates normally without supervision. When the SBC flag is provided:

- R2 MCP attempts to connect to the specified SBC endpoint
- If connection fails, R2 MCP falls back to normal operation (no supervision)
- If connection succeeds, R2 MCP waits for SBC responses before proceeding with tool executions

This design ensures that supervision is optional and doesn't break existing workflows when the SBC is unavailable.

## Building and Running

To build the R2 MCP-SBC tool:

```bash
make
```

This will create the `r2mcp-svc` executable.

To run the SBC server on a specific port:

```bash
./r2mcp-svc <port>
```

For example:

```bash
./r2mcp-svc 8080
```

The SBC will listen for HTTP POST requests containing JSON tool call data. When a request is received, it will prompt the user interactively for the desired action.

## Integration with R2 MCP

In R2 MCP, use the supervision flag to specify the SBC endpoint:

```
r2mcp --supervise http://localhost:8080
```

If the SBC is unreachable, R2 MCP will operate normally without supervision.


