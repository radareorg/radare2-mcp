/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include <r_socket.h>
#include <r_cons.h>
#include <r_util/r_json.h>
#include <r_util/r_str.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
	bool yolo_mode;
	bool quit;
	bool single_request;
	int port;
	RCons *cons;
} R2McpSvcContext;

static bool parse_args(int argc, char **argv, R2McpSvcContext *ctx) {
	int i = 1;
	for (; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp (arg, "-y")) {
			ctx->yolo_mode = true;
		} else if (!strcmp (arg, "-q")) {
			ctx->single_request = true;
		} else if (r_str_startswith (arg, "-")) {
			R_LOG_INFO ("Unknown flag %s", arg);
		} else {
			break;
		}
	}
	if (i != argc - 1) {
		R_LOG_ERROR ("Usage: %s [-y] [-q] <port>", argv[0]);
		return false;
	}
	ctx->port = atoi (argv[i]);
	if (ctx->port <= 0) {
		R_LOG_ERROR ("Invalid port");
		return false;
	}
	return true;
}

static RSocket *setup_server(int port) {
	RSocket *server = r_socket_new (false);
	if (!server) {
		R_LOG_ERROR ("Cannot create socket");
		return NULL;
	}
	char port_str[16];
	sprintf (port_str, "%d", port);
	if (!r_socket_listen (server, port_str, NULL)) {
		R_LOG_ERROR ("Cannot listen on port %s", port_str);
		r_socket_free (server);
		return NULL;
	}
	R_LOG_INFO (Color_GREEN "🚀 R2MCP Supervisor waiting for requests on port %d" Color_RESET, port);
	return server;
}

static char *handle_modify(R2McpSvcContext *ctx, char *data) {
	r_cons_printf (ctx->cons, Color_MAGENTA "✏️"
					" Enter new tool name:" Color_RESET " ");
	r_cons_flush (ctx->cons);
	const char *line = r_line_readline (ctx->cons);
	if (!line) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	char *new_tool = strdup (line);
	char *escaped_new_tool = r_str_replace (strdup (new_tool), "\\", "\\\\", 1);
	escaped_new_tool = r_str_replace (escaped_new_tool, "\"", "\\\"", 1);
	char *tool_key = "\"tool\":\"";
	char *pos = strstr (data, tool_key);
	if (!pos) {
		free (escaped_new_tool);
		free (new_tool);
		return strdup ("{\"error\":\"no tool field\"}");
	}
	char *start = pos + strlen (tool_key);
	char *end = strchr (start, '"');
	if (!end) {
		free (escaped_new_tool);
		free (new_tool);
		return strdup ("{\"error\":\"invalid json\"}");
	}
	size_t prefix_len = start - data;
	char *response_body = r_str_newf ("%.*s%s%s", (int)prefix_len, data, escaped_new_tool, end);
	free (escaped_new_tool);
	free (new_tool);
	return response_body;
}

static char *handle_r2cmd(R2McpSvcContext *ctx) {
	r_cons_printf (ctx->cons, Color_CYAN "🖥️"
					" Enter r2 command:" Color_RESET " ");
	r_cons_flush (ctx->cons);
	const char *line = r_line_readline (ctx->cons);
	if (!line) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	char *r2cmd = strdup (line);
	char *escaped = r_str_replace (strdup (r2cmd), "\"", "\\\"", 1);
	char *response_body = r_str_newf ("{\"r2cmd\":\"%s\"}", escaped);
	free (escaped);
	free (r2cmd);
	return response_body;
}

static char *show_menu_and_get_response(char *data, const char *tool, R2McpSvcContext *ctx) {
	r_cons_printf (ctx->cons, "\n" Color_YELLOW "╔══════════════════════════════════════╗\n"
				"║ " Color_CYAN "🔧 Tool Call Request " Color_YELLOW "║\n"
				"╚══════════════════════════════════════╝\n" Color_GREEN "Tool: %s\n" Color_BLUE "Request: %s\n\n"
				"Available Actions:\n" Color_GREEN "1. ✅ Accept\n" Color_RED "2. ❌ Reject\n" Color_YELLOW "3. ⚡ Accept all (YOLO mode)\n" Color_MAGENTA "4. Modify tool\n" Color_CYAN "5. 🖥️ Run r2 command\n" Color_RED "6. Quit server\n\n" Color_RESET "❓ Your choice: ",
		tool? tool: "unknown",
		data);
	r_cons_flush (ctx->cons);

	const char *line = r_line_readline (ctx->cons);
	if (!line) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	char *input = strdup (line);
	int choice = atoi (input);
	free (input);
	switch (choice) {
	case 1: // Accept
		return strdup (data);
	case 2: // Reject
		return strdup ("{\"error\":\"rejected by user\"}");
	case 3: // YOLO
		ctx->yolo_mode = true;
		return strdup (data);
	case 4: // Modify
		return handle_modify (ctx, data);
	case 5: // Run r2 command
		return handle_r2cmd (ctx);
	case 6: // Quit
		ctx->quit = true;
		return strdup ("{\"error\":\"server quit\"}");
	default:
		return strdup ("{\"error\":\"invalid choice\"}");
	}
}

static void handle_request(RSocket *server, R2McpSvcContext *ctx) {
	RSocketHTTPOptions so = { 0 };
	so.timeout = 3;
	fflush (stderr);
	RSocketHTTPRequest *rs = r_socket_http_accept (server, &so);
	if (!rs) {
		return;
	}

	// Only accept POST requests
	if (strcmp (rs->method, "POST")) {
		char *response_body = r_str_newf ("{\"error\":\"Method not allowed\"}");
		r_socket_http_response (rs, 405, response_body, 0, "Content-Type: application/json\r\n");
		free (response_body);
		r_socket_http_free (rs);
		return;
	}

	if (!rs->data) {
		char *response_body = r_str_newf ("{\"error\":\"No data\"}");
		r_socket_http_response (rs, 400, response_body, 0, "Content-Type: application/json\r\n");
		free (response_body);
		r_socket_http_free (rs);
		return;
	}

	// Parse JSON
	char *body_copy = strdup ((char *)rs->data); // r_json_parse modifies the string
	RJson *j = r_json_parse (body_copy);
	if (!j) {
		free (body_copy);
		char *response_body = r_str_newf ("{\"error\":\"Invalid JSON\"}");
		r_socket_http_response (rs, 400, response_body, 0, "Content-Type: application/json\r\n");
		free (response_body);
		r_socket_http_free (rs);
		return;
	}

	const char *tool = r_json_get_str (j, "tool");
	char *response_body = NULL;

	if (ctx->yolo_mode) {
		// Auto accept
		r_cons_printf (ctx->cons, Color_YELLOW "⚡"
						" YOLO: Received message:" Color_RESET " %s\n",
			(char *)rs->data);
		r_cons_printf (ctx->cons, Color_YELLOW "⚡"
						" YOLO: Tool executed:" Color_RESET " %s\n",
			tool? tool: "unknown");
		r_cons_flush (ctx->cons);
		response_body = strdup ((char *)rs->data);
	} else {
		response_body = show_menu_and_get_response ((char *)rs->data, tool, ctx);
	}

	if (response_body) {
		r_socket_http_response (rs, 200, response_body, 0, "Content-Type: application/json\r\n");
		free (response_body);
	}

	r_json_free (j);
	free (body_copy);
	r_socket_http_free (rs);
	if (ctx->single_request) {
		ctx->quit = true;
	}
}

int main(int argc, char **argv) {
	R2McpSvcContext ctx = { 0 };
	ctx.cons = r_cons_new ();
	if (parse_args (argc, argv, &ctx)) {
		RSocket *server = setup_server (ctx.port);
		if (server) {
			while (!ctx.quit) {
				handle_request (server, &ctx);
			}
			r_socket_free (server);
		}
	}
	r_cons_free (ctx.cons);
	return 0;
}
