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
} R2McpSvcContext;

static int parse_args(int argc, char **argv, R2McpSvcContext *ctx) {
	int i = 1;
	for (; i < argc; i++) {
		if (!strcmp (argv[i], "-y")) {
			ctx->yolo_mode = true;
		} else if (!strcmp (argv[i], "-q")) {
			ctx->single_request = true;
		} else {
			break;
		}
	}
	if (i != argc - 1) {
		fprintf (stderr, "Usage: %s [-y] [-q] <port>\n", argv[0]);
		return 1;
	}
	ctx->port = atoi (argv[i]);
	if (ctx->port <= 0) {
		fprintf (stderr, "Invalid port\n");
		return 1;
	}
	return 0;
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
	R_LOG_INFO (Color_GREEN "🚀 R2 MCP-SBC listening on port %d" Color_RESET, port);
	return server;
}

static char *handle_modify(char *data) {
	printf (Color_MAGENTA "✏️"
			" Enter new tool name:" Color_RESET " ");
	fflush (stdout);
	char *new_tool = NULL;
	size_t new_tool_len = 0;
	if (getline (&new_tool, &new_tool_len, stdin) == -1) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	new_tool[strcspn (new_tool, "\n")] = 0;
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

static char *handle_r2cmd(void) {
	printf (Color_CYAN "🖥️"
			" Enter r2 command:" Color_RESET " ");
	fflush (stdout);
	char *r2cmd = NULL;
	size_t r2cmd_len = 0;
	if (getline (&r2cmd, &r2cmd_len, stdin) == -1) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	r2cmd[strcspn (r2cmd, "\n")] = 0;
	char *escaped = r_str_replace (strdup (r2cmd), "\"", "\\\"", 1);
	char *response_body = r_str_newf ("{\"r2cmd\":\"%s\"}", escaped);
	free (escaped);
	free (r2cmd);
	return response_body;
}

static char *show_menu_and_get_response(char *data, const char *tool, R2McpSvcContext *ctx) {
	printf ("\n" Color_YELLOW "╔══════════════════════════════════════╗\n" Color_RESET);
	printf (Color_YELLOW "║" Color_RESET " " Color_CYAN "🔧"
			" Tool Call Request" Color_RESET " " Color_YELLOW "║\n" Color_RESET);
	printf (Color_YELLOW "╚══════════════════════════════════════╝\n" Color_RESET);
	printf (Color_GREEN "Tool:" Color_RESET " %s\n", tool? tool: "unknown");
	printf (Color_BLUE "Request:" Color_RESET " %s\n", data);
	printf ("\n"
	"Available Actions:\n" Color_RESET);
	printf (Color_GREEN "1. "
			"✅"
			" Accept" Color_RESET "\n");
	printf (Color_RED "2. "
			"❌"
			" Reject" Color_RESET "\n");
	printf (Color_YELLOW "3. "
			"⚡"
			" Accept all (YOLO mode)" Color_RESET "\n");
	printf (Color_MAGENTA "4. "
			"✏️"
			" Modify tool" Color_RESET "\n");
	printf (Color_CYAN "5. "
			"🖥️"
			" Run r2 command" Color_RESET "\n");
	printf (Color_RED "6. Quit server" Color_RESET "\n");
	printf ("❓"
	" Your choice:" Color_RESET " ");
	fflush (stdout);

	char *input = NULL;
	size_t input_len = 0;
	if (getline (&input, &input_len, stdin) == -1) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	input[strcspn (input, "\n")] = 0;
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
		return handle_modify (data);
	case 5: // Run r2 command
		return handle_r2cmd ();
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
	eprintf (Color_CYAN "🛡️ [r2mcp-supervisor]> " Color_RESET);
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
		printf (Color_YELLOW "⚡"
				" YOLO: Received message:" Color_RESET " %s\n",
			(char *)rs->data);
		printf (Color_YELLOW "⚡"
				" YOLO: Tool executed:" Color_RESET " %s\n",
			tool? tool: "unknown");
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
	if (parse_args (argc, argv, &ctx)) {
		return 1;
	}
	RSocket *server = setup_server (ctx.port);
	if (!server) {
		return 1;
	}

	while (!ctx.quit) {
		handle_request (server, &ctx);
	}

	r_socket_free (server);
	return 0;
}
