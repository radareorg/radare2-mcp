# HTTP sessions

`r2mcp` can serve multiple agents in parallel from a single HTTP process by
keying each request on the `X-Session-ID` header. Every distinct session id
gets its own independent `RadareState` (its own `RCore`, its own loaded file,
its own analysis level), so agents don't trample each other's open files,
flags, or analysis state.

## Starting the server

The HTTP server is enabled with `-H <port>`. By itself, `-H` runs a single
shared `RadareState` for every request, like before. To enable per-client
state isolation, add `-X`.

```sh
# Single shared state (legacy behavior)
r2mcp -H 8765

# Per-session state, defaults: max=8 sessions, idle_timeout=600s
r2mcp -H 8765 -X 8

# Custom limits: up to 16 sessions, evict after 5 minutes idle
r2mcp -H 8765 -X 16:300
```

`-X` accepts `max[:idle_seconds]`. Bare numbers fall back to the defaults for
the unspecified field. Both knobs can also be supplied via the
`R2MCP_SESSIONS` environment variable using the same syntax (the `-X` flag
takes precedence when both are set).

```sh
R2MCP_SESSIONS=16:300 r2mcp -H 8765 -X 1
```

## Identifying a session

Clients pick an opaque session id and pass it on every request as
`X-Session-ID`. The string is treated as a key — there is no required format.
Reuse the same id across requests to reuse the same `RadareState`.

```sh
curl -X POST http://localhost:8765/ \
    -H 'Content-Type: application/json' \
    -H 'X-Session-ID: agent-alice' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"alice","version":"0.1"}}}'
```

Requests **without** `X-Session-ID` are routed to the default state (the
same single state used when `-X` is not enabled). This keeps existing clients
working without changes.

## End-to-end example

Open a different binary in two parallel sessions and confirm they don't
collide:

```sh
# Start the server with sessions enabled
r2mcp -H 8765 -X 4:600 &

# alice: open /bin/ls
curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: alice' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"alice"}}}'

curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: alice' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_file","arguments":{"file_path":"/bin/ls"}}}'

# bob: open /bin/cat in a different session
curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: bob' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bob"}}}'

curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: bob' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_file","arguments":{"file_path":"/bin/cat"}}}'

# alice's view still points at /bin/ls
curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: alice' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"show_info","arguments":{}}}'

# bob's view still points at /bin/cat
curl -s -X POST http://localhost:8765/ \
    -H 'X-Session-ID: bob' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"show_info","arguments":{}}}'
```

## How sessions are managed

The registry is a bounded LRU list. Two policies decide when a session goes
away:

1. **Idle timeout** — before each accept, every session whose `last_used`
   timestamp is older than `idle_timeout` seconds is evicted and its
   `RCore` freed. Set `idle_timeout` to `0` (only via `R2MCP_SESSIONS=N:0`)
   to disable this sweep.
2. **Capacity cap** — when a request arrives with a new `X-Session-ID` and
   the registry already holds `max` sessions, the least-recently-used
   session is evicted to make room. Every successful request promotes its
   session to most-recently-used.

There is no explicit "close session" call — clients simply stop using an id
and the timeout / cap will reclaim it. If you want predictable eviction,
keep agents under the cap and make sure long-lived agents send periodic
requests (anything routed through their session id resets its idle timer).

The HTTP server is single-threaded, so requests for the same session id are
serialised naturally. Concurrent requests across different session ids are
also serialised today (one accept loop), but each request is independent
state-wise.

## Server logs

Session lifecycle events are logged via `R_LOG_INFO`:

```
INFO: r2mcp: created session 'alice'
INFO: r2mcp: created session 'bob'
INFO: r2mcp: evicting LRU session 'alice' (cap=2)
INFO: r2mcp: evicting idle session 'bob'
```

Use `-l <file>` to capture them to disk if running detached.

## When not to use sessions

If you only have one agent talking to the server, leave `-X` off — there is
no benefit and a small per-request lookup cost. Sessions are intended for
deployments where two or more independent agents share one `r2mcp` process
and must not see each other's state.
