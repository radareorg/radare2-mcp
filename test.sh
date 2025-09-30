#!/usr/bin/env bash
set -euo pipefail

echo "== Build =="
make -C src -j > /dev/null

BIN="src/r2mcp"

echo "== List tools =="
${BIN} -t | sed -n '1,10p'

echo "== DSL: openFile + listFunctions (no -p) =="
${BIN} -T 'openFile filePath="/bin/ls"; listFunctions onlyNamed=true; closeFile' | sed -n '1,8p'

echo "== DSL: unquoted value and multiple tools =="
${BIN} -T 'openFile filePath=/bin/ls; showHeaders; getCurrentAddress; closeFile' | sed -n '1,12p'

echo "== DSL: ensure error when missing openFile =="
set +e
${BIN} -T 'listFunctions onlyNamed=true' | grep -q "openFile" && echo "(expected) tool enforces openFile first" || echo "(warning) missing expected openFile hint"
set -e

echo "== OK =="

