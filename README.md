# Radare2 MCP Server

A microcontrol protocol (MCP) server for using radare2 with AI assistants like Claude.

## Implementation Details

This implementation provides a simple MCP server that:
- Uses a direct stdin/stdout communication model
- Does not support stateful subscriptions 
- Provides basic resource and tool capabilities
- Allows binary analysis with radare2

## Installation

### Prerequisites

- radare2 with development headers
- pkg-config
- gcc or compatible C compiler

### Building

```bash
# Clone the repository
git clone https://github.com/yourusername/radare2-mcp.git
cd radare2-mcp

# Build the server
make
```

### Installing

```bash
# Install to /usr/local/bin (may require sudo)
make install
```

## Usage

Once built, you can run the server directly:

```bash
./r2_mcp
```

## Configuration

### Claude Desktop Integration

To use this with Claude Desktop, update your Claude configuration file:

1. Locate your Claude Desktop configuration file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the following to your configuration file:

```json
{
  "mcpServers": {
    "radare2": {
      "command": "/path/to/r2_mcp"
    }
  }
}
```

Replace `/path/to/r2_mcp` with the actual path to the installed server.

### Example

```json
{
  "mcpServers": {
    "radare2": {
      "command": "/Users/username/dev/radare2-mcp/r2_mcp"
    }
  }
}
```

## Features

- Direct integration of radare2 with AI assistants
- Binary analysis capabilities for AI tools
- File exploration and inspection