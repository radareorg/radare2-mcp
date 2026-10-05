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
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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


def run_remote_argument_regressions():
    """Check emitted commands without requiring a live Frida target."""
    commands = []

    class Backend(BaseHTTPRequestHandler):
        def do_POST(self):
            command = self.rfile.read(int(self.headers["Content-Length"])).decode()
            commands.append(command)
            body = b"file frida://test" if command == "i~file" else b"captured"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    literal = "C++'name;f __R2MCP_INJECTED__=1337\nsecond#part|>`$(x)"
    path = "/tmp/literal;quote'line\nbreak"
    cases = [
        ("hexdump", {"address": "0", "size": "0x10"}, "'@0x0'px 16"),
        ("hexdump", {"address": "0"}, "'@0x0'px"),
        ("hexdump", {"address": "0xffffffffffffffff", "size": "1"}, "'@0xffffffffffffffff'px 1"),
        ("hexdump", {"address": "010", "size": "010"}, "'@0xa'px 10"),
        ("lookup_address", {"address": "0"}, "':fd 0x0"),
        ("lookup_symbol", {"address": "0xffffffffffffffff"}, "'@0xffffffffffffffff':is."),
        ("lookup_export", {"name": literal}, "':iaE " + literal),
        ("alloc_memory", {"string": literal}, "':dmas " + literal),
        ("alloc_memory", {"size": "0x10"}, ":dma 16"),
        ("change_memory_protection", {"address": "0xffffffffffffffff", "size": "0x10", "protection": "r-x"}, ":dmp 0xffffffffffffffff 16 r-x"),
        ("change_memory_protection", {"address": "0", "size": 1, "protection": "---"}, ":dmp 0x0 1 ---"),
        ("search", {"query": literal}, "':/ " + literal),
        ("search", {"query": literal, "type": "wide"}, "':/w " + literal),
        ("search", {"query": "deadbeef", "type": "hex"}, "':/x deadbeef"),
        ("search", {"query": "42", "type": "value"}, "':/v4 0x2a"),
        ("list_files", {"path": path}, "'ls -q " + path),
        ("list_methods", {"classname": literal}, "':ic " + literal),
    ]
    invalid = [
        ("hexdump", {"address": "12junk"}, "address"),
        ("hexdump", {"address": "0'f __R2MCP_INJECTED__=1337;'"}, "address"),
        ("hexdump", {"address": "0", "size": "16;f injected=1"}, "size"),
        ("hexdump", {"address": "0", "size": False}, "size"),
        ("lookup_address", {"address": "0x10000000000000000"}, "address"),
        ("lookup_address", {"address": "02000000000000000000000"}, "address"),
        ("lookup_symbol", {"address": ""}, "address"),
        ("lookup_symbol", {"address": 0}, "address"),
        ("alloc_memory", {"size": 2147483648}, "size"),
        ("alloc_memory", {"size": 0}, "size"),
        ("alloc_memory", {"string": 1}, "string"),
        ("change_memory_protection", {"address": "entry0", "size": 1, "protection": "rwx"}, "address"),
        ("change_memory_protection", {"address": "0", "size": -1, "protection": "rwx"}, "size"),
        ("change_memory_protection", {"address": "0", "size": 1, "protection": "rwx;f injected=1"}, "protection"),
        ("change_memory_protection", {"address": "0", "size": 1, "protection": "rx"}, "protection"),
        ("search", {"type": "value", "query": "0;f injected=1"}, "query"),
        ("search", {"type": "value", "query": "0", "value_size": 3}, "value_size"),
    ]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}, "clientInfo": {"name": "test-remote", "version": "1"}}}
    ]
    for request_id, (tool, arguments, _) in enumerate(cases + invalid, 2):
        requests.append({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
    backend = HTTPServer(("127.0.0.1", 0), Backend)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    try:
        process = subprocess.run(
            [BIN, "-u", "http://127.0.0.1:%d/" % backend.server_port],
            input="\n\n".join(json.dumps(request) for request in requests) + "\n\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        if process.returncode != 0:
            fail("remote argument server failed: " + process.stderr)
        responses = {response["id"]: response for line in process.stdout.splitlines() if line.startswith("{") for response in [json.loads(line)]}
        expected_commands = ["i~file"] + [command for _, _, command in cases]
        if commands != expected_commands:
            fail("remote tool commands differ: expected %r, got %r" % (expected_commands, commands))
        for request_id, (tool, _, _) in enumerate(cases, 2):
            if "result" not in responses.get(request_id, {}):
                fail("remote %s rejected valid arguments: %r" % (tool, responses.get(request_id)))
        for request_id, (tool, _, parameter) in enumerate(invalid, len(cases) + 2):
            error = responses.get(request_id, {}).get("error", {})
            if error.get("code") != -32602 or parameter not in error.get("message", ""):
                fail("remote %s accepted invalid %s: %r" % (tool, parameter, responses.get(request_id)))
        print("HTTP remote tool argument regressions passed")
    finally:
        backend.shutdown()
        backend.server_close()
        worker.join(timeout=5)


def main():
    if not os.path.exists(BIN):
        fail("binary not found: %s (run make -C src all first)" % BIN)
    run_remote_argument_regressions()
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
