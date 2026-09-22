#!/usr/bin/env python3
"""HTTP transport regression: large responses must be framed completely.

Starts ``r2mcp`` in HTTP mode, asks for a response well above 64 KiB and reads
it back with a deliberately slow client. The important assertion is complete
framing/content: ``Content-Length`` must match the body length and the JSON-RPC
payload must parse. Buffer sizing alone (SO_SNDBUF) is not a guarantee, Winsock
permits a short ``send``.

Guarded by the environment so it can run on Linux CI and Windows dev boxes:

    R2MCP_BIN        binary to run (default: src/r2mcp)
    R2MCP_TEST_FILE  file passed to open_file (default: /bin/ls)
"""

import json
import os
import socket
import subprocess
import sys
import time

BIN = os.environ.get("R2MCP_BIN", "src/r2mcp")
TEST_FILE = os.environ.get("R2MCP_TEST_FILE", "/bin/ls")
MIN_BYTES = 64 * 1024


def fail(message):
    print("FAIL: " + message, file=sys.stderr)
    sys.exit(1)


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def post(port, payload, slow=False):
    """POST a JSON-RPC message and return (headers, body) as bytes."""
    body = json.dumps(payload).encode()
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Connection: close\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
    ) + body

    sock = socket.create_connection(("127.0.0.1", port), timeout=60)
    chunks = []
    try:
        sock.sendall(request)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if slow:
                # Stretch the transfer so a short send/small send buffer shows up.
                time.sleep(0.001)
    finally:
        sock.close()

    raw = b"".join(chunks)
    headers, sep, response_body = raw.partition(b"\r\n\r\n")
    if not sep:
        fail("response has no header/body separator: %r" % raw[:200])
    return headers, response_body


def content_length(headers):
    for line in headers.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    return None


def main():
    if not os.path.exists(BIN):
        fail("binary not found: %s (run make -C src all first)" % BIN)
    if not os.path.exists(TEST_FILE):
        print("skip HTTP large-response test: %s not found" % TEST_FILE)
        return

    port = free_port()
    server = subprocess.Popen(
        [BIN, "-H", "127.0.0.1:%d" % port, "-r"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            fail("HTTP server did not start on port %d" % port)

        headers, body = post(
            port,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "test-http", "version": "1"},
                },
            },
        )
        expected = content_length(headers)
        if expected is None or expected != len(body):
            fail("initialize framing: content-length=%s body=%d" % (expected, len(body)))

        post(
            port,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "open_file", "arguments": {"file_path": TEST_FILE}},
            },
        )

        # px 131072 hexdumps ASCII as well, so this is comfortably >64 KiB for
        # any file larger than a few KiB.
        headers, body = post(
            port,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_command",
                    "arguments": {"command": "px 131072"},
                },
            },
            slow=True,
        )
        expected = content_length(headers)
        if expected is None:
            fail("large response is not Content-Length framed: %r" % headers[:200])
        if expected != len(body):
            fail(
                "large response truncated: content-length=%d received=%d"
                % (expected, len(body))
            )

        try:
            response = json.loads(body)
        except ValueError as exc:
            fail("large response is not valid JSON (%s): %r" % (exc, body[:200]))

        text = response.get("result", {}).get("content", [{}])[0].get("text", "")
        if len(text) < MIN_BYTES:
            fail("expected >%d bytes of tool output, got %d" % (MIN_BYTES, len(text)))
        print("HTTP large-response test passed: %d bytes framed and parsed" % len(body))
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    main()
