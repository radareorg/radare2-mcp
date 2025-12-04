#include <r_socket.h>
#include <r_util/r_json.h>
#include <r_util/r_str.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// ANSI color codes
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_RESET "\033[0m"
#define COLOR_BOLD "\033[1m"

// Emojis
#define EMOJI_ROCKET "🚀"
#define EMOJI_WRENCH "🔧"
#define EMOJI_CHECK "✅"
#define EMOJI_CROSS "❌"
#define EMOJI_LIGHTNING "⚡"
#define EMOJI_PENCIL "✏️"
#define EMOJI_COMPUTER "🖥️"
#define EMOJI_QUESTION "❓"
#define EMOJI_WARNING "⚠️"

int parse_args(int argc, char **argv, bool *yolo_mode, int *port) {
	int port_index = 1;
	if (argc >= 2 && !strcmp (argv[1], "-y")) {
		*yolo_mode = true;
		port_index = 2;
	}
	if (argc != port_index + 1) {
		fprintf (stderr, "Usage: %s [-y] <port>\n", argv[0]);
		return 1;
	}
	*port = atoi (argv[port_index]);
	if (*port <= 0) {
		fprintf (stderr, "Invalid port\n");
		return 1;
	}
	return 0;
}

RSocket *setup_server(int port) {
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
	R_LOG_INFO (COLOR_GREEN EMOJI_ROCKET " R2 MCP-SBC listening on port %d" COLOR_RESET, port);
	return server;
}

char *handle_modify(char *data) {
	printf (COLOR_MAGENTA EMOJI_PENCIL " Enter new tool name:" COLOR_RESET " ");
	fflush (stdout);
	char *new_tool = NULL;
	size_t new_tool_len = 0;
	if (getline (&new_tool, &new_tool_len, stdin) == -1) {
		return strdup ("{\"error\":\"input failed\"}");
	}
	new_tool[strcspn (new_tool, "\n")] = 0;
	char *tool_key = "\"tool\":\"";
	char *pos = strstr (data, tool_key);
	if (!pos) {
		free (new_tool);
		return strdup ("{\"error\":\"no tool field\"}");
	}
	char *start = pos + strlen (tool_key);
	char *end = strchr (start, '"');
	if (!end) {
		free (new_tool);
		return strdup ("{\"error\":\"invalid json\"}");
	}
	size_t prefix_len = start - data;
	size_t suffix_len = strlen (end);
	char *response_body = malloc (prefix_len + strlen (new_tool) + suffix_len + 1);
	if (!response_body) {
		free (new_tool);
		return strdup ("{\"error\":\"alloc failed\"}");
	}
	memcpy (response_body, data, prefix_len);
	strcpy (response_body + prefix_len, new_tool);
	strcpy (response_body + prefix_len + strlen (new_tool), end);
	free (new_tool);
	return response_body;
}

char *handle_r2cmd(void) {
	printf (COLOR_CYAN EMOJI_COMPUTER " Enter r2 command:" COLOR_RESET " ");
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

char *show_menu_and_get_response(char *data, const char *tool, bool *yolo_mode) {
	printf ("\n" COLOR_BOLD COLOR_YELLOW "╔══════════════════════════════════════╗\n" COLOR_RESET);
	printf (COLOR_BOLD COLOR_YELLOW "║" COLOR_RESET " " COLOR_CYAN EMOJI_WRENCH " Tool Call Request" COLOR_RESET " " COLOR_BOLD COLOR_YELLOW "║\n" COLOR_RESET);
	printf (COLOR_BOLD COLOR_YELLOW "╚══════════════════════════════════════╝\n" COLOR_RESET);
	printf (COLOR_GREEN "Tool:" COLOR_RESET " %s\n", tool? tool: "unknown");
	printf (COLOR_BLUE "Request:" COLOR_RESET " %s\n", data);
	printf ("\n" COLOR_BOLD "Available Actions:\n" COLOR_RESET);
	printf (COLOR_GREEN "1. " EMOJI_CHECK " Accept" COLOR_RESET "\n");
	printf (COLOR_RED "2. " EMOJI_CROSS " Reject" COLOR_RESET "\n");
	printf (COLOR_YELLOW "3. " EMOJI_LIGHTNING " Accept all (YOLO mode)" COLOR_RESET "\n");
	printf (COLOR_MAGENTA "4. " EMOJI_PENCIL " Modify tool" COLOR_RESET "\n");
	printf (COLOR_CYAN "5. " EMOJI_COMPUTER " Run r2 command" COLOR_RESET "\n");
	printf (COLOR_BOLD EMOJI_QUESTION " Your choice:" COLOR_RESET " ");
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
		*yolo_mode = true;
		return strdup (data);
	case 4: // Modify
		return handle_modify (data);
	case 5: // Run r2 command
		return handle_r2cmd ();
	default:
		return strdup ("{\"error\":\"invalid choice\"}");
	}
}

void handle_request(RSocket *server, bool *yolo_mode) {
	RSocketHTTPOptions so = { 0 };
	so.timeout = 3;
	eprintf (COLOR_CYAN "🛡️ [r2mcp-supervisor]> " COLOR_RESET);
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

	if (*yolo_mode) {
		// Auto accept
		printf (COLOR_YELLOW EMOJI_LIGHTNING " YOLO: Received message:" COLOR_RESET " %s\n", (char *)rs->data);
		printf (COLOR_YELLOW EMOJI_LIGHTNING " YOLO: Tool executed:" COLOR_RESET " %s\n", tool? tool: "unknown");
		response_body = strdup ((char *)rs->data);
	} else {
		response_body = show_menu_and_get_response ((char *)rs->data, tool, yolo_mode);
	}

	if (response_body) {
		r_socket_http_response (rs, 200, response_body, 0, "Content-Type: application/json\r\n");
		free (response_body);
	}

	r_json_free (j);
	free (body_copy);
	r_socket_http_free (rs);
}

int main(int argc, char **argv) {
	bool yolo_mode = false;
	int port;
	if (parse_args (argc, argv, &yolo_mode, &port)) {
		return 1;
	}
	RSocket *server = setup_server (port);
	if (!server) {
		return 1;
	}

	while (true) {
		handle_request (server, &yolo_mode);
	}

	r_socket_free (server);
	return 0;
}
