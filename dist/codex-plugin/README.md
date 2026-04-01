# r2mcp Codex Plugin

This directory is a local Codex plugin bundle for `r2mcp`. It packages the metadata and configuration Codex needs to expose the radare2 MCP server in the Codex app or CLI plugin directory.

## What Codex plugins are

OpenAI's Codex plugin docs describe plugins as reusable workflow bundles. A plugin can package:

- skills
- app integrations
- MCP servers

The required entry point is `.codex-plugin/plugin.json`. Optional companion files live at the plugin root, including `skills/`, `.app.json`, `.mcp.json`, and `assets/`.

For local development and private distribution, Codex reads plugin catalogs from marketplace files:

- repo marketplace: `$REPO_ROOT/.agents/plugins/marketplace.json`
- personal marketplace: `~/.agents/plugins/marketplace.json`

Codex can install any plugin exposed through one of those marketplaces. The current Codex docs also state that local plugins are copied into `~/.codex/plugins/cache/$MARKETPLACE_NAME/$PLUGIN_NAME/local/`, and that plugin enable or disable state is stored in `~/.codex/config.toml`.

OpenAI's current public docs also say official Plugin Directory publishing is not generally open yet: adding plugins to the official directory is "coming soon", and self-serve publishing and management are also "coming soon".

## What is in this bundle

- `.codex-plugin/plugin.json`: the Codex plugin manifest
- `.mcp.json`: bundled MCP server configuration for `r2mcp`
- `skills/reverse-engineering/SKILL.md`: a small skill that nudges Codex toward radare2 workflows
- `assets/`: icon and logo files for install surfaces
- `examples/repo-marketplace.json`: ready-to-copy repo marketplace entry
- `examples/personal-marketplace.json`: ready-to-copy personal marketplace entry

The release packaging in this repository wraps this directory into archives that extract as a top-level `r2mcp/` plugin folder, which matches the plugin id and the expected marketplace path examples.

## Runtime expectation

The bundled MCP configuration launches:

```json
{
  "mcpServers": {
    "r2mcp": {
      "command": "r2pm",
      "args": ["-r", "r2mcp"]
    }
  }
}
```

That means the recommended way to prepare the server is:

```sh
r2pm -Uci r2mcp
```

If you installed `r2mcp` another way and have the binary on `PATH`, edit `.mcp.json` before installing the plugin and replace:

```json
"command": "r2pm",
"args": ["-r", "r2mcp"]
```

with:

```json
"command": "r2mcp"
```

## Repo-scoped install

Use this when you want the plugin to show up only for one repository.

1. Build or install `r2mcp` first.

```sh
r2pm -Uci r2mcp
```

2. Copy this plugin bundle into the repo under `./plugins/r2mcp`.

```sh
mkdir -p ./plugins
cp -R ./dist/codex-plugin ./plugins/r2mcp
```

3. Create or update `./.agents/plugins/marketplace.json`.

You can copy `./dist/codex-plugin/examples/repo-marketplace.json` as a starting point, or merge this entry into an existing marketplace:

```json
{
  "name": "r2-local",
  "interface": {
    "displayName": "Local radare2 plugins"
  },
  "plugins": [
    {
      "name": "r2mcp",
      "source": {
        "source": "local",
        "path": "./plugins/r2mcp"
      },
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL"
      },
      "category": "Coding"
    }
  ]
}
```

4. Restart Codex.

5. Open the plugin directory, choose your local marketplace, and install `r2mcp`.

## Personal install

Use this when you want the plugin available across repositories for your local user.

1. Build or install `r2mcp` first.

```sh
r2pm -Uci r2mcp
```

2. Copy the plugin bundle into your home Codex plugin area.

```sh
mkdir -p ~/.codex/plugins
cp -R /absolute/path/to/dist/codex-plugin ~/.codex/plugins/r2mcp
```

3. Create or update `~/.agents/plugins/marketplace.json`.

You can copy `examples/personal-marketplace.json` as a starting point, or merge this entry:

```json
{
  "name": "r2-personal",
  "interface": {
    "displayName": "Personal radare2 plugins"
  },
  "plugins": [
    {
      "name": "r2mcp",
      "source": {
        "source": "local",
        "path": "./.codex/plugins/r2mcp"
      },
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL"
      },
      "category": "Coding"
    }
  ]
}
```

4. Restart Codex.

5. Open the plugin directory and install `r2mcp` from your personal marketplace.

## How users use it after install

OpenAI's Codex plugin docs say users can access plugins:

- in the Codex app via the Plugins directory
- in Codex CLI by starting `codex` and running `/plugins`

After installation, users can:

- ask directly for an outcome and let Codex choose the plugin tools
- type `@r2mcp` to invoke the plugin or one of its bundled skills explicitly

Examples:

- `@r2mcp inspect /bin/ls and summarize the entry point`
- `@r2mcp analyze this ELF and list interesting functions`
- `use r2mcp to explain what this function does`

## How local distribution works today

Based on the current Codex docs, local plugin distribution is file based:

- share the plugin folder
- point a marketplace entry at that folder
- restart Codex
- install the plugin from the plugin directory

At the moment, the public docs do not describe a self-serve public publishing flow for third-party Codex plugins. For now, the reliable path is private or team distribution through repo or personal marketplaces.

## Release artifacts

This repository can package this plugin as release artifacts. The recommended artifact names are:

- `r2mcp-codex-plugin-<version>.tar.gz`
- `r2mcp-codex-plugin-<version>.zip`

Both archives extract to:

```text
r2mcp/
```

That folder can then be copied directly to one of the locations documented above:

- repo install target: `./plugins/r2mcp`
- personal install target: `~/.codex/plugins/r2mcp`

## Notes and limitations

- This plugin bundle does not ship the `r2mcp` binary itself. It ships Codex metadata and MCP wiring.
- The default launcher assumes `r2pm` is installed and can run `r2pm -r r2mcp`.
- If you change the plugin contents, update the plugin directory your marketplace points to and restart Codex so a fresh local install is picked up.
- If a plugin is installed but should be disabled temporarily, Codex stores that state in `~/.codex/config.toml`.

## Sources

These notes were compiled from the current public Codex documentation on 2026-04-01:

- https://developers.openai.com/codex/plugins
- https://developers.openai.com/codex/plugins/build
- https://developers.openai.com/codex/mcp
- https://developers.openai.com/codex/config-reference
