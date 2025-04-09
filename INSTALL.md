Add the following JSON in your claude's config:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

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

To use r2mcp with OpenWebUI and local models run the mcp-server proxy like this:

```bash
pip install mcpo
mcpo -- r2pm -r r2mcp
```
