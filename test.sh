#!/bin/sh
set -eu

echo "== Build =="
make -C src all -j > /dev/null

BIN="src/r2mcp"

echo "== List tools =="
${BIN} -t | sed -n '1,10p'
OUT=$(${BIN} -t)
if printf '%s\n' "$OUT" | grep -q '^run_command[[:space:]]'; then
	echo "run_command must stay hidden without -r"
	exit 1
fi
OUT=$(${BIN} -rt)
printf '%s\n' "$OUT" | grep -E -q '^run_command[[:space:]]+[A-Z]*X[A-Z]*[[:space:]]'

echo "== Help + list tools =="
for args in "-ht" "-th" "-t -h" "-h -t"; do
	OUT=$(${BIN} $args)
	printf '%s\n' "$OUT" | grep -q "Tool mode flags"
	printf '%s\n' "$OUT" | grep -q "M mini"
	printf '%s\n' "$OUT" | grep -q "S sessions"
	printf '%s\n' "$OUT" | grep -q "X exec"
	if printf '%s\n' "$OUT" | grep -q "Available tools for selected mode:"; then
		echo "-ht must not list the selected-mode tools"
		exit 1
	fi
	if printf '%s\n' "$OUT" | grep -q "name[[:space:]]*modes[[:space:]]*description"; then
		echo "-ht must not print the tools table"
		exit 1
	fi
	if printf '%s\n' "$OUT" | grep -q "Tools by mode:"; then
		echo "-ht must not list tools by mode"
		exit 1
	fi
done

echo "== HTTP bind address validation =="
set +e
${BIN} -H 192.0.2.1:8765 > /dev/null 2>&1
STATUS=$?
set -e
if [ "${STATUS}" -eq 0 ]; then
	echo "unsupported HTTP bind address must fail"
	exit 1
fi

echo "== DSL: open_file + listFunctions (no -p) =="
${BIN} -T 'open_file file_path="/bin/ls"; list_functions only_named=true; close_file' 2>&1 | sed -n '1,8p'

echo "== DSL: unquoted value and multiple tools =="
${BIN} -T 'open_file file_path=/bin/ls; show_headers; get_current_address; close_file' 2>&1 | sed -n '1,12p'

echo "== DSL: list_methods command prefix =="
OUT=$(${BIN} -T 'open_file file_path=/bin/ls; list_methods classname=main; close_file' 2>&1)
if printf '%s\n' "$OUT" | grep -F -q "Invalid command '''ic"; then
	echo "list_methods generated a malformed non-Frida command"
	exit 1
fi

echo "== DSL: ensure error when missing open_file =="
set +e
${BIN} -T 'list_functions only_named=true' 2>&1 | grep -q "open_file"
STATUS=$?
set -e
if [ "${STATUS}" -eq 0 ]; then
	echo "(expected) tool enforces open_file first"
else
	echo "(warning) missing expected open_file hint"
fi

echo "== OK =="
