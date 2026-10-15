#!/usr/bin/env python3
"""Exercise JSON number preservation through the real stdio MCP server."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class JsonNumberTests(unittest.TestCase):
    def test_signed_unsigned_and_paged_values(self):
        values = [-1, -(2**63), 2**53 + 1, 2**64 - 1, {"nested": -2}]
        cases = [
            (values, {}, values),
            (values, {"page_size": 2}, values[:2]),
            (values, {"page_size": 2, "cursor": "2"}, values[2:4]),
            ({"negative": -1, "maximum": 2**64 - 1, "items": values},
             {"page_size": 2},
             {"negative": -1, "maximum": 2**64 - 1, "items": values[:2]}),
            (["18446744073709551615", "-1", True, None, 1.5], {},
             ["18446744073709551615", "-1", True, None, 1.5]),
        ]
        with tempfile.TemporaryDirectory(prefix="r2mcp-json-numbers-") as directory:
            artifact = Path(directory) / "fixture.bin"
            artifact.write_bytes(bytes(64))
            requests = [
                {"id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "json-numbers-test", "version": "1"}}},
                {"method": "notifications/initialized", "params": {}},
                {"id": 2, "method": "tools/call", "params": {
                    "name": "open_file", "arguments": {"file_path": str(artifact)}}},
            ]
            for index, (source, paging, _) in enumerate(cases, 3):
                requests.append({"id": index, "method": "tools/call", "params": {
                    "name": "run_command", "arguments": {
                        "command": "?e " + json.dumps(source).replace('"', r'\"'), **paging}}})
            payload = "".join(json.dumps({"jsonrpc": "2.0", **request}) + "\n"
                              for request in requests)
            for mode in ["text", "json", "structured", "both"]:
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        [str(Path(__file__).parent / "src/r2mcp"),
                         "-n", "-N", "-r", "-C", mode],
                        input=payload, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    replies = {reply["id"]: reply for reply in
                               map(json.loads, result.stdout.splitlines())}
                    self.assertEqual(len(replies), len(cases) + 2)
                    self.assertNotIn("error", replies[2])
                    for index, (_, paging, expected) in enumerate(cases, 3):
                        reply = replies[index]["result"]
                        self.assertEqual(json.loads(reply["content"][0]["text"]), expected)
                        if mode in ["structured", "both"]:
                            self.assertEqual(reply["structuredContent"], expected)
                        if paging:
                            end = int(paging.get("cursor", "0")) + paging["page_size"]
                            self.assertTrue(reply["pagination"]["hasMore"])
                            self.assertEqual(reply["pagination"]["nextCursor"], str(end))


if __name__ == "__main__":
    unittest.main()
