# r2r tests

Run `make test-r2r` from the repository root to build the CLI and core plugin
and run this suite. `make test` also runs it before the existing tests.
The only requirements are the build dependencies, radare2, r2r, and a POSIX
shell. No jq, Python, network services, installed r2mcp plugin, or downloaded
test binaries are needed.

To run the tests directly after building:

```sh
r2r -u -C test db
r2r -u -C test db/cli
r2r -u -C test db/plugin
```

`-u` keeps r2r offline. Tests use handcrafted `hex://` files: `90c3` is x86
`nop; ret`, and `68656c6c6f00776f726c6400` contains `hello` and `world`.
Architecture and bitness are explicit when interpreting code. r2r disables
user plugins and startup files; CLI calls also use `-nN` to disable plugins,
startup files, and prompts. Plugin tests load `../src/libcore_r2mcp` with the
extension reported by `r2 -H R2_LIBEXT`, then disable prompt loading.

`db/cli` checks DSL and stdio JSON-RPC calls to the freshly built program.
`db/plugin` checks the `r2mcp` command against the current radare2 core,
including state shared with native commands. Expected output is checked by
r2r, including stderr for CLI calls.
