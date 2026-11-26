#!/usr/bin/env python3
"""Exercise command log ownership through the real stdio MCP server."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WARNING_COMMAND = "fu* 0xfffffffffffffff0"
WARNING = "Unable to find a flag by 0xfffffffffffffff0"
SANDBOX_ERROR = "Sandbox: system call disabled"


class JsonCommandLogTests(unittest.TestCase):
    def exchange(self, commands, mode="both", **arguments):
        with tempfile.TemporaryDirectory(prefix="r2mcp-json-logs-") as directory:
            fixture = Path(directory) / "fixture.bin"
            fixture.write_bytes(bytes(64))
            header = Path(directory) / "types.h"
            header.write_text("struct blocked_import { int member; };\n")
            requests = [
                {"id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "json-command-logs-test", "version": "1"}}},
                {"method": "notifications/initialized", "params": {}},
                {"id": 2, "method": "tools/call", "params": {
                    "name": "open_file", "arguments": {"file_path": str(fixture)}}},
            ]
            for index, command in enumerate(commands, 3):
                if command == "denied_import":
                    command = json.dumps({"cmd": "to " + str(header), "json": False})
                requests.append({"id": index, "method": "tools/call", "params": {
                    "name": "run_command", "arguments": {"command": command, **arguments}}})
            payload = "".join(json.dumps({"jsonrpc": "2.0", **request}) + "\n"
                              for request in requests)
            default_binary = os.environ.get("R2MCP_BIN", str(Path(__file__).parent / "src/r2mcp"))
            binary = Path(os.environ.get("R2MCP_TEST_BINARY", default_binary))
            result = subprocess.run(
                [str(binary), "-n", "-N", "-r", "-C", mode], input=payload,
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "R2_COLOR": "0", "R2_UTF8": "0"})
            self.assertEqual(result.returncode, 0, result.stderr)
            replies = {reply["id"]: reply for reply in
                       map(json.loads, result.stdout.splitlines())}
            self.assertEqual(set(replies), {1, 2, *range(3, len(commands) + 3)})
            self.assertNotIn("error", replies[2])
            return [replies[index]["result"] for index in range(3, len(commands) + 3)], result.stderr

    def test_json2_warning_survives_every_content_mode(self):
        command = json.dumps({"cmd": WARNING_COMMAND, "json": False, "trim": False})
        for mode in ["text", "json", "structured", "both"]:
            with self.subTest(mode=mode):
                results, stderr = self.exchange([command], mode)
                text = results[0]["content"][0]["text"]
                envelope = json.loads(text)
                self.assertFalse(envelope["error"])
                self.assertEqual(envelope["code"], 0)
                logs = [log for log in envelope.get("logs", []) if log["message"] == WARNING]
                self.assertEqual(len(logs), 1, text)
                self.assertEqual(logs[0]["type"], "WARN")
                self.assertEqual(stderr.count(WARNING), 1, stderr)
                self.assertNotIn("<log>", text)
                if mode in ["structured", "both"]:
                    self.assertEqual(results[0]["structuredContent"], envelope)

    def test_denied_import_keeps_failure_and_structured_error(self):
        results, stderr = self.exchange(["denied_import"])
        text = results[0]["content"][0]["text"]
        envelope = json.loads(text)
        # The native core owns the exit status. Older cores can emit an
        # ERROR without setting a failure code; retain that observation too.
        self.assertIsInstance(envelope["error"], bool)
        self.assertIsInstance(envelope["code"], int)
        self.assertEqual(envelope["error"], envelope["code"] != 0, text)
        logs = [log for log in envelope.get("logs", []) if log["message"] == SANDBOX_ERROR]
        self.assertEqual(len(logs), 1, text)
        self.assertEqual(logs[0]["type"], "ERROR")
        self.assertEqual(stderr.count(SANDBOX_ERROR), 1, stderr)
        self.assertNotIn("<log>", text)

    def test_plain_warning_keeps_one_log_block_and_stderr_copy(self):
        results, stderr = self.exchange([WARNING_COMMAND])
        text = results[0]["content"][0]["text"]
        self.assertEqual(text.count(WARNING), 1, text)
        self.assertEqual(text.count("<log>"), 1, text)
        self.assertEqual(text.count("</log>"), 1, text)
        self.assertEqual(stderr.count(WARNING), 1, stderr)

    def test_plain_logs_do_not_count_as_results(self):
        command = "?e alpha;?e beta"
        results, stderr = self.exchange([command, WARNING_COMMAND + ";" + command], page_size=2, cursor="1")
        clean, result = results
        self.assertEqual(result["structuredContent"], clean["structuredContent"])
        self.assertEqual(result.get("pagination"), clean.get("pagination"))
        text = result["content"][0]["text"]
        self.assertTrue(text.startswith("beta\n<log>\n"), text)
        self.assertEqual(text.count(WARNING), 1, text)
        self.assertEqual(stderr.count(WARNING), 1, stderr)

    def test_json_output_and_diagnostics_use_separate_blocks(self):
        for mode in ["json", "structured", "both"]:
            with self.subTest(mode=mode):
                results, stderr = self.exchange([WARNING_COMMAND + ";ij"], mode)
                result = results[0]
                data, logs = result["content"]
                info = json.loads(data["text"])
                self.assertEqual(info["core"]["size"], 64)
                self.assertNotIn("<log>", data["text"])
                self.assertEqual(logs["text"].count(WARNING), 1)
                self.assertEqual(stderr.count(WARNING), 1, stderr)
                if mode != "json":
                    self.assertEqual(result["structuredContent"], info)

    def test_plain_command_logs_are_unchanged_after_json2(self):
        structured = json.dumps({"cmd": WARNING_COMMAND, "json": False})
        results, stderr = self.exchange([structured, WARNING_COMMAND])
        envelope = json.loads(results[0]["content"][0]["text"])
        self.assertEqual(sum(log["message"] == WARNING for log in envelope.get("logs", [])), 1)
        plain = results[1]["content"][0]["text"]
        self.assertEqual(plain.count(WARNING), 1, plain)
        self.assertEqual(plain.count("<log>"), 1, plain)
        self.assertEqual(plain.count("</log>"), 1, plain)
        self.assertEqual(stderr.count(WARNING), 2, stderr)


if __name__ == "__main__":
    unittest.main()
