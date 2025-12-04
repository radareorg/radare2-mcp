/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include "tools.h"
#include "prompts.h"

#if R2__UNIX__
/* Signal handling moved from r2mcp.c */
static void signal_handler(int signum) {
	const char msg[] = "\nInterrupt received, shutting down...\n";
	write (STDERR_FILENO, msg, sizeof (msg) - 1);
	r2mcp_running_set (0);
	signal (signum, SIG_DFL);
}
void setup_signals(void) {
	struct sigaction sa = { 0 };
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGINT, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);
	sigaction (SIGHUP, &sa, NULL);
	signal (SIGPIPE, SIG_IGN);
}

#endif
/* Help and version moved from r2mcp.c */
void r2mcp_help(void) {
	const char help_text[] =
		"Usage: r2mcp [-flags]\n"
		" -c [cmd]   run those commands before entering the mcp loop\n"
		" -d [pdc]   select a different decompiler (pdc by default)\n"
		" -u [url]   use remote r2 webserver base URL (HTTP r2pipe client mode)\n"
		" -l [file]  append debug logs to this file\n"
		" -s [dir]   enable sandbox mode; only allow files under [dir]\n"
		" -e [tool]  enable only the specified tool (repeatable)\n"
		" -h         show this help\n"
		" -r         enable the dangerous runCommand tool\n"
		" -R         enable read-only mode (expose only non-mutating tools)\n"
		" -m         expose minimum amount of tools\n"
		" -t         list available tools and exit\n"
		" -T [tests] run DSL tests and exit\n"
		" -p         permissive tools: allow calling non-listed tools\n"
		" -n         do not load any plugin or radare2rc\n"
		" -i         ignore analysis level specified in analyze calls\n"
		" -S [url]   enable supervisor control; connect to svc at [url]\n"
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
	bool enable_run_command_tool = false;
	bool readonly_mode = false;
	bool list_tools = false;
	RList *cmds = r_list_new ();
	/* Whitelist of enabled tool names (populated via repeated -e flags) */
	RList *enabled_tools = NULL;
	bool loadplugins = true;
	const char *deco = NULL;
	bool http_mode = false;
	bool permissive = false;
	char *baseurl = NULL;
	char *svc_baseurl = NULL;
	char *sandbox = NULL;
	char *logfile = NULL;
	bool ignore_analysis_level = false;
	const char *dsl_tests = NULL;
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "hmvpd:nc:u:l:s:rite:RT:S:");
	int c;
	while ((c = r_getopt_next (&opt)) != -1) {
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
		case 's':
			sandbox = strdup (opt.arg);
			break;
		case 'n':
			loadplugins = false;
			break;
		case 'm':
			minimode = true;
			break;
		case 'p':
			permissive = true;
			break;
		case 'r':
			enable_run_command_tool = true;
			break;
		case 'R':
			readonly_mode = true;
			break;
		case 'i':
			ignore_analysis_level = true;
			break;
		case 't':
			list_tools = true;
			break;
		case 'T':
			dsl_tests = opt.arg;
			break;
		case 'S':
			if (opt.arg) {
				if (strspn (opt.arg, "0123456789") == strlen (opt.arg)) {
					svc_baseurl = r_str_newf ("http://localhost:%s", opt.arg);
				} else {
					svc_baseurl = strdup (opt.arg);
				}
			}
			break;
		case 'e':
			if (opt.arg) {
				if (!enabled_tools) {
					enabled_tools = r_list_newf (free);
				}
				r_list_append (enabled_tools, strdup (opt.arg));
			}
			break;
		default:
			R_LOG_ERROR ("Invalid flag -%c", c);
			return 1;
		}
	}
	ServerState ss = {
		.info = {
			.name = "Radare2 MCP Connector",
			.version = R2MCP_VERSION },
		.capabilities = { .tools = true, .prompts = true, .resources = true },
		.instructions = "Use this server to analyze binaries with radare2",
		.initialized = false,
		.minimode = minimode,
		.readonly_mode = readonly_mode,
		.permissive_tools = permissive,
		.enable_run_command_tool = enable_run_command_tool,
		.http_mode = http_mode,
		.baseurl = baseurl,
		.svc_baseurl = svc_baseurl,
		.sandbox = sandbox,
		.logfile = logfile,
		.ignore_analysis_level = ignore_analysis_level,
		.client_capabilities = NULL,
		.client_info = NULL,
		.enabled_tools = enabled_tools,
	};
	/* Enable logging */
	r2mcp_log_pub (&ss, "r2mcp starting");
#if R2__UNIX__
	setup_signals ();
#endif
	/* Initialize registries */
	tools_registry_init (&ss);
	if (list_tools) {
		/* Print tools and exit early */
		tools_print_table (&ss);
		return 0;
	}
	prompts_registry_init (&ss);
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
	/* If -T was provided, run DSL tests and exit */
	if (dsl_tests) {
		int r = r2mcp_run_dsl_tests (&ss, dsl_tests, NULL);
		/* Cleanup and return */
		tools_registry_fini (&ss);
		prompts_registry_fini (&ss);
		r2mcp_state_fini (&ss);
		free (ss.baseurl);
		free (ss.svc_baseurl);
		free (ss.sandbox);
		free (ss.logfile);
		if (ss.enabled_tools) {
			r_list_free (ss.enabled_tools);
		}
		return r == 0? 0: 2;
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
	prompts_registry_fini (&ss);
	r2mcp_state_fini (&ss);
	/* Cleanup */
	free (ss.baseurl);
	free (ss.sandbox);
	free (ss.logfile);
	if (ss.enabled_tools) {
		r_list_free (ss.enabled_tools);
	}
	(void)0;
	return 0;
}
