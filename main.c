#include "config.h"
#include "r2mcp.h"
#include "tools.h"

#include <signal.h>
#include <unistd.h>
#include <stdio.h>

/* Signal handling moved from r2mcp.c */
static void signal_handler(int signum) {
	const char msg[] = "\nInterrupt received, shutting down...\n";
	write (STDERR_FILENO, msg, sizeof (msg) - 1);
	r2mcp_running_set (0);
	signal (signum, SIG_DFL);
}

void setup_signals(void) {
	struct sigaction sa = {0};
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	sigemptyset (&sa.sa_mask);

	sigaction (SIGINT, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);
	sigaction (SIGHUP, &sa, NULL);
	signal (SIGPIPE, SIG_IGN);
}

/* Help and version moved from r2mcp.c */
void r2mcp_help(void) {
	const char help_text[] =
		"Usage: r2mcp [-flags]\n"
		" -c [cmd]   run those commands before entering the mcp loop\n"
		" -d [pdc]   select a different decompiler (pdc by default)\n"
		" -u [url]   use remote r2 webserver base URL (HTTP r2pipe client mode)\n"
		" -l [file]  append debug logs to this file\n"
		" -h         show this help\n"
		" -m         expose minimum amount of tools\n"
		" -p         permissive tools: allow calling non-listed tools\n"
		" -n         do not load any plugin or radare2rc\n"
		" -v         show version\n";
	printf ("%s", help_text);
}

void r2mcp_version(void) {
	printf ("%s\n", R2MCP_VERSION);
}

/* Program entry point wrapper */
int main(int argc, const char **argv) {
	return r2mcp_main (argc, argv);
}

/* Moved from r2mcp.c to isolate main concerns here */
int r2mcp_main(int argc, const char **argv) {
	bool minimode = false;
	RList *cmds = r_list_new ();
	bool loadplugins = true;
	const char *deco = NULL;
	bool http_mode = false;
	bool permissive = false;
	char *baseurl = NULL;
	char *logfile = NULL;
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "hmvpd:nc:u:l:");
	int c;
	while ( (c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'h':
			r2mcp_help ();
			return 0;
		case 'c':
			r_list_append (cmds, (char *)opt.arg);
			break;
		case 'v':
			r2mcp_version ();
			return 0;
		case 'd':
			deco = opt.arg;
			break;
		case 'u':
			http_mode = true;
			baseurl = strdup (opt.arg);
			eprintf ("[R2MCP] HTTP r2pipe client mode enabled, baseurl=%s\n", baseurl);
			break;
		case 'l':
			logfile = strdup (opt.arg);
			break;
		case 'n':
			loadplugins = true;
			break;
		case 'm':
			minimode = true;
			break;
		case 'p':
			permissive = true;
			break;
		default:
			eprintf ("Invalid flag -%c\n", c);
			return 1;
		}
	}

	ServerState ss = {
		.info = {
			.name = "Radare2 MCP Connector",
			.version = R2MCP_VERSION },
		.capabilities = { .logging = true, .tools = true },
		.instructions = "Use this server to analyze binaries with radare2",
		.initialized = false,
		.minimode = minimode,
		.permissive_tools = permissive,
		.http_mode = http_mode,
		.baseurl = baseurl,
		.logfile = logfile,
		.client_capabilities = NULL,
		.client_info = NULL
	};

	/* Enable logging */
	r2mcp_log_pub (&ss, "r2mcp starting");

	setup_signals ();

	/* Initialize tools registry */
	tools_registry_init (&ss);

	/* Initialize r2 (unless running in HTTP client mode) */
	if (!ss.http_mode) {
		if (!r2mcp_state_init (&ss)) {
			R_LOG_ERROR ("Failed to initialize radare2");
			r2mcp_log_pub (&ss, "Failed to initialize radare2");
			return 1;
		}
		if (loadplugins) {
			r_core_loadlibs (ss.rstate.core, R_CORE_LOADLIBS_ALL, NULL);
			r_core_parse_radare2rc (ss.rstate.core);
		}
		if (deco) {
			if (!strcmp (deco, "decai")) {
				deco = "decai -d";
			}
			char *pdc = r_str_newf ("e cmd.pdc=%s", deco);
			eprintf ("[R2MCP] Using Decompiler: %s\n", pdc);
			r2mcp_cmd (&ss, pdc);
			free (pdc);
		}
	} else {
		r2mcp_log_pub (&ss, "HTTP r2pipe client mode active - skipping local r2 initialization");
	}

	RListIter *iter;
	const char *cmd;
	r_list_foreach (cmds, iter, cmd) {
		r2mcp_cmd (&ss, cmd);
	}
	r_list_free (cmds);

	r2mcp_running_set (1);
	r2mcp_eventloop (&ss);
	tools_registry_fini (&ss);
	r2mcp_state_fini (&ss);
	/* Cleanup */
	free (ss.baseurl);
	free (ss.logfile);
	(void)0;
	return 0;
}
