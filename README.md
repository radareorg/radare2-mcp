# Radare2 MCP Server

[![ci](https://github.com/radareorg/radare2-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/radare2-mcp/actions/workflows/ci.yml)
[![radare2](https://img.shields.io/badge/radare2-6.0.4-green)](https://github.com/radareorg/radare2)

<img width="400" alt="Screenshot_2025-03-22_at_5 34 47_PM" src="https://github.com/user-attachments/assets/5322c3fc-fc07-4770-96a3-5a6d82d439c2" />
<img width="400" alt="Screenshot_2025-03-22_at_5 36 17_PM" src="https://github.com/user-attachments/assets/132a1de0-6978-4202-8dce-aa3d60551b9a" />

An MCP server for using radare2 with AI assistants such as Claude, VSCode, CLION, Mai, OpenCode, ...

## Features

This implementation provides a simple MCP server that:

- Uses a direct stdin/stdout communication model
- Provides basic tool capabilities
- Allows seamless binary analysis with radare2
- Integrates radare2 directly with AI assistants
- Enables file exploration and inspection

## Installation

### Using r2pm

The simplest way to install the package is by using `r2pm`:

```bash
$ r2pm -Uci r2mcp
```

The `r2mcp` executable will be copied into r2pm's bindir in your home directory. However, this binary is not supposed to be executed directly from the shell; it will only work when launched by the MCP service handler of your language model of choice.

```bash
$ r2pm -r mcp
```

### Using Docker

Alternatively, you can build the Docker image:

```bash
docker build -t r2mcp .
```

Update your MCP client configuration file (see below) to use the Docker image to use:

- `"command": "docker"`
- `"args": ["run", "--rm", "-i", "-v", "/tmp/data:/data", "r2mcp"]`.

## Configuration

### Claude Desktop Integration

In the Claude Desktop app, press `CMD + ,` to open the Developer settings. Edit the configuration file and restart the client after editing the JSON file as explained below:

1. Locate your Claude Desktop configuration file:

   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the following to your configuration file:

```json
{
  "mcpServers": {
    "radare2": {
      "command": "r2pm",
      "args": ["-r", "r2mcp"]
    }
  }
}
```

## VS Code Integration

To use r2mcp with GitHub Copilot Chat in Visual Studio Code by [adding it to your user configuration](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_add-an-mcp-server-to-your-user-configuration) (see other options [here](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_add-an-mcp-server)):

1. Open the Command Palette with `CMD + Shift + P` (macOS) or `Ctrl + Shift + P` (Windows/Linux).
2. Search for and select `Copilot: Open User Configuration` (typically found in `~/Library/Application Support/Code/User/mcp.json` in macOS).
3. Add the following to your configuration file:

```json
{
  "servers": {
    "radare2": {
      "type": "stdio",
      "command": "r2pm",
      "args": ["-r", "r2mcp"]
    }
  },
  "inputs": []
}
```

## Zed Integration

You can use r2mcp with Zed as well by [adding it to your configuration](https://zed.dev/docs/ai/mcp):

1. Open the command palette: `CMD + Shift + P` (macOS) or `Ctrl + Shift + P` (Windows/Linux). 
2. Search of `agent: open configuration` or search of `settings`.
3. Add your server as such:

```json
  "context_servers": {
    "r2-mcp-server": {
      "source": "custom",
      "command": "r2pm",
      "args": ["-r", "r2mcp"],
      "env": {}
    }
  }
```
Note: you will need another LLM agent, such as Claude, Gemini or else to be able to use it.

## For Developers

### Build from Source

#### Linux/macOS

To test the server locally, you can build and install it with make:

```bash
make install
```

This will compile the server and place the `r2mcp` binary in `/usr/local/bin` on macOS.

#### Windows

For Windows, just use meson and ninja like it's done in the CI:

```cmd
meson b
ninja -C b
```
