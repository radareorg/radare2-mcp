#!/usr/bin/env python3
"""Exercise open_file permissions through the real stdio MCP server."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest


@contextmanager
def http_fixture():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = bytes(range(64))
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield "http://127.0.0.1:%d/fixture.bin" % server.server_port, requests
        finally:
            server.shutdown()
            thread.join()


class OpenPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="r2mcp-open-paths-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fixture = self.directory / "fixture.bin"
        self.fixture.write_bytes(bytes(range(64)))

    def exchange(self, calls, *options, cwd=None):
        messages = [
            {"id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "open-paths-test", "version": "1"}}},
            {"method": "notifications/initialized", "params": {}},
        ]
        for index, (name, arguments) in enumerate(calls, 2):
            messages.append({"id": index, "method": "tools/call", "params": {
                "name": name, "arguments": arguments}})
        payload = "".join(json.dumps({"jsonrpc": "2.0", **message}) + "\n"
                          for message in messages)
        default_binary = Path(__file__).resolve().parent / "src" / (
            "r2mcp.exe" if os.name == "nt" else "r2mcp")
        default_binary = os.environ.get("R2MCP_BIN", str(default_binary))
        binary = Path(os.environ.get("R2MCP_TEST_BINARY", default_binary)).resolve()
        result = subprocess.run(
            [binary, "-n", "-N", "-r", *options], input=payload,
            capture_output=True, text=True, timeout=30, cwd=cwd)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = list(map(json.loads, result.stdout.splitlines()))
        self.assertEqual([reply["id"] for reply in replies],
                         list(range(1, len(calls) + 2)), result.stderr)
        return replies[1:], result.stderr

    def text(self, reply):
        self.assertNotIn("error", reply)
        return reply["result"]["content"][0]["text"]

    def test_local_and_memory_opens_work_without_optional_permissions(self):
        replies, _ = self.exchange([
            ("open_file", {"file_path": str(self.fixture)}),
            ("close_file", {}),
            ("open_file", {"file_path": "file://" + str(self.fixture)}),
            ("open_file", {"file_path": "malloc://64"}),
            ("run_command", {"command": "e cfg.sandbox"}),
            ("run_command", {"command": "e cfg.sandbox.grain"}),
            ("close_file", {}),
        ], "-g", "none")
        for index in [0, 2, 3]:
            self.assertIn("File opened successfully.", self.text(replies[index]))
        self.assertEqual(self.text(replies[4]).strip(), "true")
        self.assertEqual(self.text(replies[5]).strip(), "none")
        self.assertEqual(self.text(replies[6]), "File closed successfully.")

    def test_http_open_obeys_grain_on_first_and_subsequent_opens(self):
        denied_grains = ["none", "disk", "files", "exec", "environ"]
        for grain in denied_grains + ["socket", "network", "all"]:
            with self.subTest(grain=grain), http_fixture() as (url, requests):
                replies, _ = self.exchange([
                    ("open_file", {"file_path": url}),
                    ("open_file", {"file_path": str(self.fixture)}),
                    ("open_file", {"file_path": url}),
                ], "-g", grain)
                self.assertIn("File opened successfully.", self.text(replies[1]))
                for index in [0, 2]:
                    if grain in denied_grains:
                        self.assertEqual(self.text(replies[index]), "Failed to open file.")
                    else:
                        self.assertIn("File opened successfully.", self.text(replies[index]))
                self.assertEqual(len(requests), 0 if grain in denied_grains else 2)

    def test_hidden_local_targets_and_dot_components(self):
        hidden_dir = self.directory / ".build"
        hidden_dir.mkdir()
        hidden = hidden_dir / ".firmware.bin"
        hidden.write_bytes(bytes(range(64)))
        paths = [str(hidden), "file://" + str(hidden),
                 str(self.directory) + "/./.build/.firmware.bin",
                 str(self.directory) + "/./fixture.bin"]
        calls = []
        for path in paths:
            calls.extend([("open_file", {"file_path": path}), ("close_file", {})])
        for options in [(), ("-g", "none")]:
            with self.subTest(options=options):
                replies, _ = self.exchange(calls, *options)
                for index in range(0, len(replies), 2):
                    self.assertEqual(self.text(replies[index]), "File opened successfully.")
                    self.assertEqual(self.text(replies[index + 1]), "File closed successfully.")

    def test_hidden_directory_and_script_paths(self):
        hidden_dir = self.directory / ".build"
        hidden_dir.mkdir()
        script = hidden_dir / "commands.r2"
        script.write_text("?e R2MCP_HIDDEN_SCRIPT\n")
        replies, _ = self.exchange([
            ("open_file", {"file_path": str(self.fixture)}),
            ("list_files", {"path": str(hidden_dir)}),
            ("run_script", {"file_path": str(script)}),
        ], "-g", "all", "-s", str(self.directory))
        self.assertIn("File opened successfully.", self.text(replies[0]))
        self.assertIn("commands.r2", self.text(replies[1]))
        self.assertIn("R2MCP_HIDDEN_SCRIPT", self.text(replies[2]))

    def test_hidden_paths_cannot_escape_filesystem_sandbox(self):
        sandbox = self.directory / "sandbox"
        sandbox.mkdir()
        inside = sandbox / ".inside.bin"
        inside.write_bytes(bytes(range(64)))
        outside_dir = self.directory / ".outside"
        outside_dir.mkdir()
        outside = outside_dir / "fixture.bin"
        outside.write_bytes(bytes(range(64)))
        script = outside_dir / "commands.r2"
        script.write_text("?e R2MCP_OUTSIDE_SCRIPT\n")
        denied = [str(outside), "file://" + str(outside),
                  str(sandbox) + "/../.outside/fixture.bin"]
        if os.name != "nt":
            alias = sandbox / "escape.bin"
            alias.symlink_to(outside)
            denied.append(str(alias))
        calls = [("open_file", {"file_path": str(inside)})]
        calls.extend(("open_file", {"file_path": path}) for path in denied)
        calls.extend([
            ("list_files", {"path": str(outside_dir)}),
            ("run_script", {"file_path": str(script)}),
            ("show_info", {}),
        ])
        replies, _ = self.exchange(calls, "-g", "all", "-s", str(sandbox))
        self.assertEqual(self.text(replies[0]), "File opened successfully.")
        for reply in replies[1:1 + len(denied)]:
            self.assertEqual(self.text(reply), "Failed to open file.")
        for reply in replies[-3:-1]:
            self.assertIn("outside of the sandbox", reply["error"]["message"])
        self.assertIn(str(inside), self.text(replies[-1]))

    def test_native_hidden_grain_controls_command_file_reads(self):
        hidden_dir = self.directory / ".build"
        hidden_dir.mkdir()
        (hidden_dir / "data.md").write_text("R2MCP_HIDDEN_POLICY\n")
        (self.directory / "visible.md").write_text("R2MCP_VISIBLE_POLICY\n")
        for grain in ["disk,files", "disk,files,hidden"]:
            with self.subTest(grain=grain):
                replies, _ = self.exchange([
                    ("open_file", {"file_path": str(self.fixture)}),
                    ("run_command", {"command": "cat -m visible.md"}),
                    ("run_command", {"command": "cat -m .build/data.md"}),
                ], "-g", grain, cwd=self.directory)
                self.assertIn("R2MCP_VISIBLE_POLICY", self.text(replies[1]))
                self.assertEqual("R2MCP_HIDDEN_POLICY" in self.text(replies[2]),
                                 grain == "disk,files,hidden")

    def test_https_open_requires_permissions(self):
        with http_fixture() as (url, requests):
            url = url.replace("http://", "https://", 1)
            replies, _ = self.exchange([
                ("open_file", {"file_path": url}),
                ("open_file", {"file_path": str(self.fixture)}),
                ("open_file", {"file_path": url}),
            ], "-g", "none")
            for index in [0, 2]:
                self.assertEqual(self.text(replies[index]), "Failed to open file.")
            self.assertIn("File opened successfully.", self.text(replies[1]))
            self.assertEqual(requests, [])

    def test_filesystem_sandbox_rejects_uri_wrappers_without_closing_file(self):
        sandbox = self.directory / "sandbox"
        sandbox.mkdir()
        inside = sandbox / "inside.bin"
        inside.write_bytes(bytes(64))
        replies, _ = self.exchange([
            ("open_file", {"file_path": str(inside)}),
            ("open_file", {"file_path": "slurp://" + str(self.fixture)}),
            ("show_info", {}),
        ], "-g", "all", "-s", str(sandbox))
        self.assertIn("File opened successfully.", self.text(replies[0]))
        self.assertEqual(self.text(replies[1]), "Failed to open file.")
        self.assertIn(str(inside), self.text(replies[2]))

    def test_network_and_device_paths_are_rejected_by_all_path_tools(self):
        paths = [r"\\127.0.0.1\share\fixture.bin", "//127.0.0.1/share/fixture.bin",
                 r"\\?\UNC\127.0.0.1\share\fixture.bin", r"\\.\PhysicalDrive0"]
        calls = [("open_file", {"file_path": str(self.fixture)})]
        for path in paths:
            calls.extend([
                ("open_file", {"file_path": path}),
                ("list_files", {"path": path}),
                ("run_script", {"file_path": path}),
            ])
        calls.append(("show_info", {}))
        replies, _ = self.exchange(calls, "-g", "all")
        for index in range(1, len(replies) - 1, 3):
            self.assertEqual(self.text(replies[index]), "Failed to open file.")
            for reply in replies[index + 1:index + 3]:
                self.assertIn("Network and device paths", reply["error"]["message"])
        self.assertIn(str(self.fixture), self.text(replies[-1]))

    def test_non_regular_paths_are_rejected_without_closing_file(self):
        paths = [str(self.directory)]
        if os.name != "nt":
            paths.append("/dev/null")
            fifo = self.directory / "pipe"
            os.mkfifo(fifo)
            paths.append(str(fifo))
        calls = [("open_file", {"file_path": str(self.fixture)})]
        calls.extend(("open_file", {"file_path": path}) for path in paths)
        calls.append(("show_info", {}))
        replies, _ = self.exchange(calls, "-g", "all")
        for reply in replies[1:-1]:
            self.assertEqual(self.text(reply), "Failed to open file.")
        self.assertIn(str(self.fixture), self.text(replies[-1]))

    def test_frida_requires_explicit_process_and_network_permissions(self):
        for grain in ["none", "socket", "exec", "network"]:
            with self.subTest(grain=grain):
                replies, _ = self.exchange([
                    ("open_file", {"file_path": str(self.fixture)}),
                    ("open_file", {"file_path": "frida://0"}),
                    ("show_info", {}),
                ], "-g", grain)
                self.assertEqual(self.text(replies[1]), "Failed to open file.")
                self.assertIn(str(self.fixture), self.text(replies[2]))


if __name__ == "__main__":
    unittest.main()
