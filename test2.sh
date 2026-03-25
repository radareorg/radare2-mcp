#!/bin/sh
set -eu

BIN="src/r2mcp"
INJECT_MARKER="__R2MCP_INJECTED__"

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

append_request() {
	local file="$1"
	local id="$2"
	local method="$3"
	local params_json="$4"
	jq -cn \
		--argjson id "$id" \
		--arg method "$method" \
		--argjson params "$params_json" \
		'{jsonrpc:"2.0", id:$id, method:$method, params:$params}' >> "$file"
	printf '\n' >> "$file"
}

append_notification() {
	local file="$1"
	local method="$2"
	local params_json="$3"
	jq -cn \
		--arg method "$method" \
		--argjson params "$params_json" \
		'{jsonrpc:"2.0", method:$method, params:$params}' >> "$file"
	printf '\n' >> "$file"
}

append_tool_call() {
	local file="$1"
	local id="$2"
	local tool="$3"
	local args_json="$4"
	jq -cn \
		--argjson id "$id" \
		--arg tool "$tool" \
		--argjson args "$args_json" \
		'{jsonrpc:"2.0", id:$id, method:"tools/call", params:{name:$tool, arguments:$args}}' >> "$file"
	printf '\n' >> "$file"
}

run_session() {
	local req="$1"
	local resp="$2"
	shift 2
	env ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 "$BIN" "$@" < "$req" | grep '^{' > "$resp" || true
	jq -s . "$resp" >/dev/null 2>&1 || fail "invalid JSON response stream in $resp"
}

response_by_id() {
	local resp="$1"
	local id="$2"
	jq -c --argjson id "$id" 'select(.id == $id)' "$resp" | tail -n 1
}

fetch_catalog() {
	local out="$1"
	shift
	local cursor=""
	local pages="$TMPDIR/pages.jsonl"
	: > "$pages"
	while :; do
		local req="$TMPDIR/catalog.req"
		local resp="$TMPDIR/catalog.resp"
		local params='{}'
		: > "$req"
		append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
		append_notification "$req" notifications/initialized '{}'
		if [ -n "$cursor" ]; then
			params=$(jq -cn --arg cursor "$cursor" '{cursor:$cursor}')
		fi
		append_request "$req" 2 tools/list "$params"
		run_session "$req" "$resp" "$@"
		local page
		page=$(jq -c 'select(.id == 2).result' "$resp")
		[ -n "$page" ] || fail "missing tools/list response"
		printf '%s\n' "$page" >> "$pages"
		cursor=$(printf '%s\n' "$page" | jq -r '.nextCursor // empty')
		[ -n "$cursor" ] || break
	done
	jq -s '[.[].tools[]]' "$pages" > "$out"
}

build_cases() {
	local catalog="$1"
	local out="$2"
	jq -cn \
		--slurpfile catalog "$catalog" \
		--arg file "$TEST_FILE" \
		--arg dir "$TEST_DIR" \
		--arg marker "$INJECT_MARKER" '
		def default_value($tool; $name; $prop):
			if $name == "file_path" then $file
			elif $name == "path" then $dir
			elif $name == "address" then "0"
			elif $name == "classname" then "main"
			elif $name == "prototype" then "int fuzz(void)"
			elif $name == "message" then "hello from tests"
			elif $name == "expression" then "1+1"
			elif $name == "query" then "main"
			elif $name == "type" and $tool == "search" then "string"
			elif $name == "name" and $tool == "use_decompiler" then "pdc"
			elif $name == "name" then "fuzz_name"
			elif $name == "new_name" then "fuzz_name_new"
			elif $name == "protection" then "r-x"
			elif $name == "url" then "http://127.0.0.1:1"
			elif $name == "cursor" then ""
			elif $name == "size" and (($prop.type // "") == "string") then "16"
			elif (($prop.type // "") == "boolean") then false
			elif (($prop.type // "") == "integer" or ($prop.type // "") == "number") then 1
			else "x"
			end;
		def wrong_value($type):
			if $type == "string" then 0
			elif ($type == "integer" or $type == "number") then "oops"
			elif $type == "boolean" then "oops"
			else empty
			end;
		def injection_value($name):
			if $name == "path" then "/tmp;f " + $marker + "=entry0"
			else "x;f " + $marker + "=entry0"
			end;
		def skip_smoke($tool):
			($tool == "open_session"
				or $tool == "close_file"
				or $tool == "run_command"
				or $tool == "run_javascript");
		def skip_string_fuzz($tool):
			($tool == "open_session"
				or $tool == "run_command"
				or $tool == "run_javascript");
		[
			$catalog[0][] as $tool
			| ($tool.inputSchema.properties // {}) as $props
			| ($tool.inputSchema.required // []) as $required
			| ($props | to_entries) as $entries
			| (reduce $entries[] as $entry ({}; .[$entry.key] = default_value($tool.name; $entry.key; $entry.value))) as $base
			| (
				if skip_smoke($tool.name) then
					empty
				else
					{kind:"smoke", tool:$tool.name, args:$base}
				end
			),
			(
				$required[]? as $param
				| {kind:"missing-required", tool:$tool.name, param:$param, args:($base | del(.[$param]))}
			),
			(
				$entries[]
				| (.value.type // "") as $type
				| select($type == "string" or $type == "integer" or $type == "number" or $type == "boolean")
				| {kind:"wrong-type", tool:$tool.name, param:.key, args:($base + {(.key): wrong_value($type)})}
			),
			(
				$entries[]
				| (.value.type // "") as $type
				| select($type == "string" and (skip_string_fuzz($tool.name) | not))
				| {kind:"empty-string", tool:$tool.name, param:.key, args:($base + {(.key): ""})}
			),
			(
				$entries[]
				| (.value.type // "") as $type
				| select($type == "string" and (skip_string_fuzz($tool.name) | not))
				| {kind:"injection", tool:$tool.name, param:.key, marker:$marker, args:($base + {(.key): injection_value(.key)})}
			),
			(
				$entries[]
				| (.value.type // "") as $type
				| select($type == "integer" or $type == "number")
				| {kind:"negative-number", tool:$tool.name, param:.key, args:($base + {(.key): -1})}
			)
		]' > "$out"
}

append_cases() {
	local cases="$1"
	local req="$2"
	local meta="$3"
	local _cases_expanded="$TMPDIR/_cases_expanded.jsonl"
	jq -c '.[]' "$cases" > "$_cases_expanded"
	while IFS= read -r case_json; do
		local id="$NEXT_ID"
		NEXT_ID=$((NEXT_ID + 1))
		local tool
		local args_json
		tool=$(printf '%s\n' "$case_json" | jq -r '.tool')
		args_json=$(printf '%s\n' "$case_json" | jq -c '.args')
		append_tool_call "$req" "$id" "$tool" "$args_json"
		printf '%s\n' "$case_json" | jq -c --argjson id "$id" '. + {id:$id}' >> "$meta"
	done < "$_cases_expanded"
}

assert_error_contains_param() {
	local response="$1"
	local param="$2"
	local context="$3"
	local code
	local message
	code=$(printf '%s\n' "$response" | jq -r '.error.code // empty')
	message=$(printf '%s\n' "$response" | jq -r '.error.message // empty')
	[ "$code" = "-32602" ] || fail "$context: expected -32602, got $response"
	case "$message" in
		*"$param"*) ;;
		*) fail "$context: expected message mentioning '$param', got '$message'" ;;
	esac
}

assert_marker_absent() {
	local response="$1"
	local marker="$2"
	local context="$3"
	if printf '%s\n' "$response" | grep -q "$marker"; then
		fail "$context: command injection marker leaked into response: $response"
	fi
}

run_dynamic_suite() {
	local catalog="$1"
	local suite_name="$2"
	local open_mode="$3"
	shift 3
	local cases="$TMPDIR/$suite_name.cases.json"
	local req="$TMPDIR/$suite_name.req"
	local resp="$TMPDIR/$suite_name.resp"
	local meta="$TMPDIR/$suite_name.meta.jsonl"

	build_cases "$catalog" "$cases"
	: > "$req"
	: > "$meta"
	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	if [ "$open_mode" = "with-open" ]; then
		append_tool_call "$req" 2 open_file "$(jq -cn --arg file "$TEST_FILE" '{file_path:$file}')"
	fi
	NEXT_ID=10
	append_cases "$cases" "$req" "$meta"
	if [ "$open_mode" = "with-open" ]; then
		append_tool_call "$req" "$NEXT_ID" list_symbols "$(jq -cn --arg marker "$INJECT_MARKER" '{filter:$marker}')"
		jq -cn --argjson id "$NEXT_ID" --arg kind injection-probe --arg marker "$INJECT_MARKER" \
			'{id:$id, kind:$kind, marker:$marker}' >> "$meta"
		NEXT_ID=$((NEXT_ID + 1))
	fi
	run_session "$req" "$resp" "$@"

	if [ "$open_mode" = "with-open" ]; then
		local open_file_response
		open_file_response=$(response_by_id "$resp" 2)
		[ -n "$open_file_response" ] || fail "$suite_name: missing open_file response"
	fi

	while IFS= read -r case_json; do
		local id
		local kind
		local tool
		local param
		local marker
		local response

		id=$(printf '%s\n' "$case_json" | jq -r '.id')
		kind=$(printf '%s\n' "$case_json" | jq -r '.kind')
		tool=$(printf '%s\n' "$case_json" | jq -r '.tool')
		param=$(printf '%s\n' "$case_json" | jq -r '.param // empty')
		marker=$(printf '%s\n' "$case_json" | jq -r '.marker // empty')
		response=$(response_by_id "$resp" "$id")
		[ -n "$response" ] || fail "$suite_name: missing response for $tool/$kind (#$id)"

		case "$kind" in
		missing-required|wrong-type)
			assert_error_contains_param "$response" "$param" "$suite_name:$tool:$kind"
			;;
		injection)
			:
			;;
		injection-probe)
			assert_marker_absent "$response" "$marker" "$suite_name:$kind"
			;;
		smoke|empty-string|negative-number)
			:
			;;
		*)
			fail "unknown test case kind: $kind"
			;;
		esac
	done < "$meta"

	echo "== $suite_name =="
	echo "cases: $(wc -l < "$meta" | tr -d ' ')"
}

run_close_file_regression() {
	local req="$TMPDIR/close.req"
	local resp="$TMPDIR/close.resp"
	: > "$req"
	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	append_tool_call "$req" 2 open_file "$(jq -cn --arg file "$TEST_FILE" '{file_path:$file}')"
	append_tool_call "$req" 3 close_file '{}'
	append_tool_call "$req" 4 get_current_address '{}'
	run_session "$req" "$resp"

	local close_response
	local after_close
	close_response=$(response_by_id "$resp" 3)
	after_close=$(response_by_id "$resp" 4)
	[ -n "$close_response" ] || fail "close_file: missing close response"
	[ -n "$after_close" ] || fail "close_file: missing post-close response"
	printf '%s\n' "$after_close" | jq -e '.error.code == -32611' >/dev/null 2>&1 || {
		fail "close_file: expected open_file requirement after close, got $after_close"
	}
}

run_open_file_regressions() {
	local req="$TMPDIR/open.req"
	local resp="$TMPDIR/open.resp"
	: > "$req"
	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	append_tool_call "$req" 2 open_file '{}'
	append_tool_call "$req" 3 open_file "$(jq -cn '{file_path:0}')"
	append_tool_call "$req" 4 open_file "$(jq -cn '{file_path:""}')"
	append_tool_call "$req" 5 open_file "$(jq -cn --arg path "/tmp;?e $INJECT_MARKER" '{file_path:$path}')"
	run_session "$req" "$resp"

	assert_error_contains_param "$(response_by_id "$resp" 2)" "file_path" "open_file:missing-required"
	assert_error_contains_param "$(response_by_id "$resp" 3)" "file_path" "open_file:wrong-type"
	printf '%s\n' "$(response_by_id "$resp" 4)" | jq -e '.result.content[0].text == "Failed to open file."' >/dev/null 2>&1 || {
		fail "open_file: empty string should fail cleanly"
	}
	assert_marker_absent "$(response_by_id "$resp" 5)" "$INJECT_MARKER" "open_file:injection"
}

run_open_session_regression() {
	local port="19392"
	local good_url="http://127.0.0.1:$port/cmd/"
	local req="$TMPDIR/open-session.req"
	local resp="$TMPDIR/open-session.resp"
	local server_log="$TMPDIR/open-session.server.log"
	local server_pid=""
	local ready="0"
	local i="0"

	r2 -q0 -e http.bind=127.0.0.1 -c "=h $port" /bin/ls > /dev/null 2>"$server_log" &
	server_pid=$!
	trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT INT TERM
	while [ "$i" -lt 20 ]; do
		if curl -fsS --data-raw i "$good_url" >/dev/null 2>&1; then
			ready="1"
			break
		fi
		i=$((i + 1))
		sleep 1
	done
	[ "$ready" = "1" ] || fail "open_session: failed to start local r2 http server"
	: > "$req"
	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	append_tool_call "$req" 2 open_session "$(jq -cn --arg url "$good_url" '{url:$url}')"
	append_tool_call "$req" 3 get_current_address '{}'
	append_tool_call "$req" 4 open_session "$(jq -cn '{url:"http://127.0.0.1:1"}')"
	append_tool_call "$req" 5 get_current_address '{}'
	append_tool_call "$req" 6 close_session '{}'
	run_session "$req" "$resp" -L -p

	printf '%s\n' "$(response_by_id "$resp" 2)" | jq -e '.result.content[0].text | contains("Successfully connected")' >/dev/null 2>&1 || {
		fail "open_session: initial connect should succeed, got $(response_by_id "$resp" 2)"
	}
	printf '%s\n' "$(response_by_id "$resp" 3)" | jq -e '.result.content[0].text | type == "string"' >/dev/null 2>&1 || {
		fail "open_session: expected active remote session before reconnect, got $(response_by_id "$resp" 3)"
	}
	printf '%s\n' "$(response_by_id "$resp" 4)" | jq -e '.error.code == -32603 and (.error.message | contains("Failed to connect"))' >/dev/null 2>&1 || {
		fail "open_session: failed reconnect should report an error, got $(response_by_id "$resp" 4)"
	}
	printf '%s\n' "$(response_by_id "$resp" 5)" | jq -e '.result.content[0].text | type == "string"' >/dev/null 2>&1 || {
		fail "open_session: existing remote session should survive failed reconnect, got $(response_by_id "$resp" 5)"
	}
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
	trap 'rm -rf "$TMPDIR"' EXIT INT TERM
}

run_sandbox_regressions() {
	local sb="$TMPDIR/sandbox"
	local req="$TMPDIR/sandbox.req"
	local resp="$TMPDIR/sandbox.resp"
	mkdir -p "$sb"
	cp /bin/ls "$sb/ls"
	ln -s /bin "$sb/escape"
	: > "$req"

	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	append_tool_call "$req" 2 open_file "$(jq -cn --arg file "$sb/ls" '{file_path:$file}')"
	append_tool_call "$req" 3 open_file "$(jq -cn --arg file "$sb/escape/ls" '{file_path:$file}')"
	append_tool_call "$req" 4 list_files "$(jq -cn --arg path "$sb/../" '{path:$path}')"
	append_tool_call "$req" 5 list_files "$(jq -cn --arg path "$sb/escape" '{path:$path}')"
	run_session "$req" "$resp" -s "$sb"

	local open_escape
	local traversal
	local list_escape
	open_escape=$(response_by_id "$resp" 3)
	traversal=$(response_by_id "$resp" 4)
	list_escape=$(response_by_id "$resp" 5)

	printf '%s\n' "$open_escape" | jq -e '.result.content[0].text == "Failed to open file."' >/dev/null 2>&1 || {
		fail "sandbox open_file symlink escape should fail, got $open_escape"
	}
	printf '%s\n' "$traversal" | jq -e '.error.code == -32603 and (.error.message | contains("Path traversal"))' >/dev/null 2>&1 || {
		fail "sandbox traversal should be rejected, got $traversal"
	}
	printf '%s\n' "$list_escape" | jq -e '.error.code == -32603 and (.error.message | contains("outside of the sandbox"))' >/dev/null 2>&1 || {
		fail "sandbox symlink escape should be rejected, got $list_escape"
	}
}

run_command_filter_regression() {
	local req="$TMPDIR/filter.req"
	local resp="$TMPDIR/filter.resp"
	local payload='x$(f __R2MCP_INJECTED__=entry0)'
	: > "$req"

	append_request "$req" 1 initialize '{"capabilities":{},"clientInfo":{"name":"testsuite","version":"1"}}'
	append_notification "$req" notifications/initialized '{}'
	append_tool_call "$req" 2 open_file "$(jq -cn --arg file "$TEST_FILE" '{file_path:$file}')"
	append_tool_call "$req" 3 run_command "$(jq -cn --arg command "$payload" '{command:$command}')"
	append_tool_call "$req" 4 list_symbols "$(jq -cn --arg marker "$INJECT_MARKER" '{filter:$marker}')"
	run_session "$req" "$resp" -r

	printf '%s\n' "$(response_by_id "$resp" 3)" | jq -e '.result.content[0].text | type == "string"' >/dev/null 2>&1 || {
		fail "command filter regression: expected run_command to return text, got $(response_by_id "$resp" 3)"
	}
	assert_marker_absent "$(response_by_id "$resp" 4)" "$INJECT_MARKER" "command filter regression"
}

need_cmd jq
need_cmd mktemp
need_cmd curl
need_cmd r2

echo "== Build =="
make -C src all > /dev/null

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM
TEST_DIR="$TMPDIR/work"
TEST_FILE="$TEST_DIR/ls.bin"
mkdir -p "$TEST_DIR"
cp /bin/ls "$TEST_FILE"

NORMAL_CATALOG="$TMPDIR/catalog.normal.json"
DANGEROUS_CATALOG="$TMPDIR/catalog.dangerous.json"
SESSION_CATALOG="$TMPDIR/catalog.sessions.json"
NORMAL_RUNTIME_CATALOG="$TMPDIR/catalog.normal.runtime.json"
DANGEROUS_ONLY="$TMPDIR/catalog.dangerous.only.json"

echo "== Catalog =="
fetch_catalog "$NORMAL_CATALOG"
fetch_catalog "$DANGEROUS_CATALOG" -r
fetch_catalog "$SESSION_CATALOG" -L
jq -e '
	length > 0
	and ((map(.name) | unique | length) == length)
	and all(.[]; (.inputSchema | type) == "object")
	and all(.[]; ((.inputSchema.properties // {}) | type) == "object")
	and all(.[]; ((.inputSchema.required // []) | type) == "array")
' "$NORMAL_CATALOG" >/dev/null
jq '[.[] | select(.name != "open_file" and .name != "list_sessions" and .name != "open_session" and .name != "close_session")]' \
	"$NORMAL_CATALOG" > "$NORMAL_RUNTIME_CATALOG"
jq --slurpfile normal "$NORMAL_CATALOG" '
	[.[] | select(.name as $name | ($normal[0] | map(.name) | index($name) | not))]
' "$DANGEROUS_CATALOG" > "$DANGEROUS_ONLY"
jq -e 'map(.name) | index("run_command") and index("run_javascript")' "$DANGEROUS_CATALOG" >/dev/null
echo "normal tools: $(jq 'length' "$NORMAL_RUNTIME_CATALOG")"
echo "dangerous-only tools: $(jq 'length' "$DANGEROUS_ONLY")"
echo "session tools: $(jq 'length' "$SESSION_CATALOG")"

run_dynamic_suite "$NORMAL_RUNTIME_CATALOG" "dynamic-normal" with-open
run_dynamic_suite "$DANGEROUS_ONLY" "dynamic-dangerous" with-open -r
run_dynamic_suite "$SESSION_CATALOG" "dynamic-sessions" no-open -L
run_open_file_regressions
run_close_file_regression
run_open_session_regression
run_sandbox_regressions
run_command_filter_regression

echo "== OK =="
