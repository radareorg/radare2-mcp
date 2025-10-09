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

static bool yolo_mode = false;

int main(int argc, char **argv) {
	int port_index = 1;
	if (argc >= 2 && !strcmp (argv[1], "-y")) {
		yolo_mode = true;
		port_index = 2;
	}
	if (argc != port_index + 1) {
		fprintf (stderr, "Usage: %s [-y] <port>\n", argv[0]);
		return 1;
	}
	int port = atoi (argv[port_index]);
	if (port <= 0) {
		fprintf (stderr, "Invalid port\n");
		return 1;
	}

	RSocket *server = r_socket_new (false);
	if (!server) {
		R_LOG_ERROR ("Cannot create socket");
		return 1;
	}

	if (!r_socket_listen (server, argv[port_index], NULL)) {
		R_LOG_ERROR ("Cannot listen on port %s", argv[port_index]);
		r_socket_free (server);
		return 1;
	}

	R_LOG_INFO (COLOR_GREEN EMOJI_ROCKET " R2 MCP-SBC listening on port %s" COLOR_RESET, argv[port_index]);

	RSocketHTTPOptions so = { 0 };
	so.timeout = 3;

	while (true) {
		eprintf (COLOR_CYAN "🛡️ [r2mcp-supervisor]> " COLOR_RESET);
		fflush (stderr);
		RSocketHTTPRequest *rs = r_socket_http_accept (server, &so);
		if (!rs) {
			continue;
		}

		// Only accept POST requests
		if (strcmp (rs->method, "POST")) {
			r_socket_http_response (rs, 405, "Method not allowed", 0, NULL);
			r_socket_http_free (rs);
			continue;
		}

		if (!rs->data) {
			r_socket_http_response (rs, 400, "No data", 0, NULL);
			r_socket_http_free (rs);
			continue;
		}

		// Parse JSON
		char *body_copy = strdup ((char *)rs->data); // r_json_parse modifies the string
		RJson *j = r_json_parse (body_copy);
		if (!j) {
			free (body_copy);
			r_socket_http_response (rs, 400, "Invalid JSON", 0, NULL);
			r_socket_http_free (rs);
			continue;
		}

		const char *tool = r_json_get_str (j, "tool");

		char *response_body = NULL;

		if (yolo_mode) {
			// Auto accept
			printf (COLOR_YELLOW EMOJI_LIGHTNING " YOLO: Received message:" COLOR_RESET " %s\n", (char *)rs->data);
			printf (COLOR_YELLOW EMOJI_LIGHTNING " YOLO: Tool executed:" COLOR_RESET " %s\n", tool? tool: "unknown");
			response_body = strdup ((char *)rs->data);
		} else {
			printf ("\n" COLOR_BOLD COLOR_YELLOW "╔══════════════════════════════════════╗\n" COLOR_RESET);
			printf (COLOR_BOLD COLOR_YELLOW "║" COLOR_RESET " " COLOR_CYAN EMOJI_WRENCH " Tool Call Request" COLOR_RESET " " COLOR_BOLD COLOR_YELLOW "║\n" COLOR_RESET);
			printf (COLOR_BOLD COLOR_YELLOW "╚══════════════════════════════════════╝\n" COLOR_RESET);
			printf (COLOR_GREEN "Tool:" COLOR_RESET " %s\n", tool? tool: "unknown");
			printf (COLOR_BLUE "Request:" COLOR_RESET " %s\n", (char *)rs->data);
			printf ("\n" COLOR_BOLD "Available Actions:\n" COLOR_RESET);
			printf (COLOR_GREEN "1. " EMOJI_CHECK " Accept" COLOR_RESET "\n");
			printf (COLOR_RED "2. " EMOJI_CROSS " Reject" COLOR_RESET "\n");
			printf (COLOR_YELLOW "3. " EMOJI_LIGHTNING " Accept all (YOLO mode)" COLOR_RESET "\n");
			printf (COLOR_MAGENTA "4. " EMOJI_PENCIL " Modify tool" COLOR_RESET "\n");
			printf (COLOR_CYAN "5. " EMOJI_COMPUTER " Run r2 command" COLOR_RESET "\n");
			printf (COLOR_BOLD EMOJI_QUESTION " Your choice:" COLOR_RESET " ");
			fflush (stdout);

			char input[256];
			if (!fgets (input, sizeof (input), stdin)) {
				response_body = strdup ("{\"error\":\"input failed\"}");
			} else {
				int choice = atoi (input);
				switch (choice) {
				case 1: // Accept
					response_body = strdup ((char *)rs->data);
					break;
				case 2: // Reject
					response_body = strdup ("{\"error\":\"rejected by user\"}");
					break;
				case 3: // YOLO
					yolo_mode = true;
					response_body = strdup ((char *)rs->data);
					break;
				case 4: // Modify
					printf (COLOR_MAGENTA EMOJI_PENCIL " Enter new tool name:" COLOR_RESET " ");
					fflush (stdout);
					char new_tool[256];
					if (fgets (new_tool, sizeof (new_tool), stdin)) {
						new_tool[strcspn (new_tool, "\n")] = 0;
						char *tool_key = "\"tool\":\"";
						char *pos = strstr ((char *)rs->data, tool_key);
						if (pos) {
							char *start = pos + strlen (tool_key);
							char *end = strchr (start, '"');
							if (end) {
								size_t prefix_len = start - (char *)rs->data;
								size_t suffix_len = strlen (end);
								response_body = malloc (prefix_len + strlen (new_tool) + suffix_len + 1);
								if (response_body) {
									memcpy (response_body, rs->data, prefix_len);
									strcpy (response_body + prefix_len, new_tool);
									strcpy (response_body + prefix_len + strlen (new_tool), end);
								} else {
									response_body = strdup ("{\"error\":\"alloc failed\"}");
								}
							} else {
								response_body = strdup ("{\"error\":\"invalid json\"}");
							}
						} else {
							response_body = strdup ("{\"error\":\"no tool field\"}");
						}
					} else {
						response_body = strdup ("{\"error\":\"input failed\"}");
					}
					break;
				case 5: // Run r2 command
					printf (COLOR_CYAN EMOJI_COMPUTER " Enter r2 command:" COLOR_RESET " ");
					fflush (stdout);
					char r2cmd[1024];
					if (fgets (r2cmd, sizeof (r2cmd), stdin)) {
						r2cmd[strcspn (r2cmd, "\n")] = 0;
						// Simple JSON escape: replace " with \"
						char *escaped = r_str_replace (strdup (r2cmd), "\"", "\\\"", 1);
						response_body = r_str_newf ("{\"r2cmd\":\"%s\"}", escaped);
						free (escaped);
					} else {
						response_body = strdup ("{\"error\":\"input failed\"}");
					}
					break;
				default:
					response_body = strdup ("{\"error\":\"invalid choice\"}");
				}
			}
		}

		if (response_body) {
			r_socket_http_response (rs, 200, response_body, 0, "Content-Type: application/json\r\n");
			free (response_body);
		}

		r_json_free (j);
		free (body_copy);
		r_socket_http_free (rs);
	}

	r_socket_free (server);
	return 0;
}
