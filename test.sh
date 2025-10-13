#!/usr/bin/env bash
set -euo pipefail

echo "== Build =="
make -C src -j > /dev/null

BIN="src/r2mcp"

echo "== List tools =="
${BIN} -t | sed -n '1,10p'

echo "== DSL: open_file + listFunctions (no -p) =="
${BIN} -T 'open_file file_path="/bin/ls"; list_functions only_named=true; close_file' | sed -n '1,8p'

echo "== DSL: unquoted value and multiple tools =="
${BIN} -T 'open_file file_path=/bin/ls; show_headers; get_current_address; close_file' | sed -n '1,12p'

echo "== DSL: ensure error when missing open_file =="
set +e
${BIN} -T 'list_functions only_named=true' | grep -q "open_file" && echo "(expected) tool enforces open_file first" || echo "(warning) missing expected open_file hint"
set -e

echo "== OK =="

