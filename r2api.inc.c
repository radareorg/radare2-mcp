static void r2state_settings(RCore *core) {
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", false);
	r_config_set_b (core->config, "scr.interactive", false);
	r_config_set_b (core->config, "emu.str", true);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "anal.strings", true);
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "anal.hasnext", true); // TODO: optional
	r_config_set_b (core->config, "asm.lines.fcn", false);
	r_config_set_b (core->config, "asm.cmt.right", false);
	r_config_set_b (core->config, "scr.html", false);
	r_config_set_b (core->config, "scr.prompt", false);
	r_config_set_b (core->config, "scr.echo", false);
	r_config_set_b (core->config, "scr.flush", true);
	r_config_set_b (core->config, "scr.null", false);
	r_config_set_b (core->config, "scr.pipecolor", false);
	r_config_set_b (core->config, "scr.utf8", false);
	r_config_set_i (core->config, "scr.limit", 16768);
}

static bool logcb(void *user, int type, const char *origin, const char *msg) {
	if (type > R_LOG_LEVEL_WARN) {
		return false;
	}
	if (!msg || R_STR_ISEMPTY (origin)) {
		return true;
	}
	ServerState *ss = (ServerState *)user;
	if (ss->sb) {
		const char *typestr = r_log_level_tostring (type);
		// eprintf ("[%s] from=%s message=%s\n", typestr, origin, msg);
		r_strbuf_appendf (ss->sb, "[%s] %s\n", typestr, msg);
		// r_strbuf_appendf (ss->sb, "[%s] from=%s message=%s\n", typestr, origin, msg);
	}
	return true;
}

static void r2mcp_log_reset(ServerState *ss) {
	r_strbuf_free (ss->sb);
	ss->sb = r_strbuf_new ("");
}

static char *r2mcp_log_drain(ServerState *ss) {
	char *s = r_strbuf_drain (ss->sb);
	if (R_STR_ISNOTEMPTY (s)) {
		ss->sb = NULL;
		return s;
	}
	free (s);
	ss->sb = NULL;
	return NULL;
}

static bool r2state_init(ServerState *ss) {
	RCore *core = r_core_new ();
	if (!core) {
		R_LOG_ERROR ("Failed to initialize radare2 core");
		return false;
	}

	r2state_settings (core);
	ss->rstate.core = core;

	R_LOG_INFO ("Radare2 core initialized");
	r_log_add_callback (logcb, ss);
	return true;
}

static void r2state_fini(ServerState *ss) {
	RCore *core = ss->rstate.core;
	if (core) {
		r_core_free (core);
		r_strbuf_free (ss->sb);
		ss->sb = NULL;
		ss->rstate.core = NULL;
		ss->rstate.file_opened = false;
		ss->rstate.current_file = NULL;
	}
}

static inline void r2mcp_log(ServerState *ss, const char *x) {
	eprintf ("[R2MCP] %s\n", x);
#if R2MCP_DEBUG
	if (ss && ss->logfile && *ss->logfile) {
		r_file_dump (ss->logfile, (const ut8 *) (x), -1, true);
		r_file_dump (ss->logfile, (const ut8 *)"\n", -1, true);
	}
#endif
}

static char *r2_cmd_filter(const char *cmd, bool *changed) {
	char *res = r_str_trim_dup (cmd);
	char fchars[] = "|>`";
	*changed = false;
	if (*res == '!') {
		*changed = true;
		*res = 0;
	} else {
		char *ch = strstr (res, "$ (");
		if (ch) {
			*changed = true;
			*ch = 0;
		}
		for (ch = fchars; *ch; ch++) {
			char *p = strchr (res, *ch);
			if (p) {
				*changed = true;
				*p = 0;
			}
		}
	}
	return res;
}

#include "curl.inc.c"

static char *r2cmd_over_http(ServerState *ss, const char *cmd) {
	int rc = 0;
	char *res = curl_post_capture (ss->baseurl, cmd, &rc);
	if (rc != 0) {
		R_LOG_ERROR ("curl %d", rc);
		free (res);
		return NULL;
	}
	return res;
}

/* Forward declaration so helpers above can call r2_cmd */
static char *r2_cmd(ServerState *ss, const char *cmd);

/* Portable helper to format a string with a va_list. Uses vsnprintf. */
static char *vformat(const char *fmt, va_list ap) {
	va_list ap2;
	va_copy (ap2, ap);
	int needed = vsnprintf (NULL, 0, fmt, ap2);
	va_end (ap2);
	if (needed < 0) {
		return NULL;
	}
	char *buf = malloc ( (size_t)needed + 1);
	if (!buf) {
		return NULL;
	}
	vsnprintf (buf, (size_t)needed + 1, fmt, ap);
	return buf;
}

/* Run a command and discard the output. Useful for commands that don't
 * need their output but should be executed. */
static void r2_run_cmd(ServerState *ss, const char *cmd) {
	free (r2_cmd (ss, cmd));
}

static void r2_run_cmdf(ServerState *ss, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *cmd = vformat (fmt, ap);
	va_end (ap);
	if (cmd) {
		r2_run_cmd (ss, cmd);
		free (cmd);
	}
}

static char *r2_cmd(ServerState *ss, const char *cmd) {
	if (ss && ss->http_mode) {
		/* In HTTP mode we do not use any r2 C APIs. Delegate to the
		 * dummy function (user will implement HTTP requests later).
		 */
		return r2cmd_over_http (ss, cmd);
	}

	RCore *core = ss->rstate.core;
	if (!core || !ss->rstate.file_opened) {
		return strdup ("Use the openFile method before calling any other method");
	}
	bool changed = false;
	char *filteredCommand = r2_cmd_filter (cmd, &changed);
	if (changed) {
		r2mcp_log (ss, "command injection prevented");
	}
	r2mcp_log_reset (ss);
	char *res = r_core_cmd_str (core, filteredCommand);
	char *err = r2mcp_log_drain (ss);
	free (filteredCommand);
	r2state_settings (core);
	if (err) {
		char *newres = r_str_newf ("%s<log>\n%s\n</log>\n", res, err);
		free (res);
		res = newres;
	}
	return res;
}

static bool r2_open_file(ServerState *ss, const char *filepath) {
	R_LOG_INFO ("Attempting to open file: %s\n", filepath);
	/* In HTTP mode we do not touch the local r2 core. Just set the state
	 * so subsequent calls to r2_cmd will be allowed (they will be handled
	 * by the dummy function).
	 */
	if (ss && ss->http_mode) {
		free (ss->rstate.current_file);
		ss->rstate.current_file = strdup (filepath);
		ss->rstate.file_opened = true;
		return true;
	}

	RCore *core = ss->rstate.core;
	if (!core && !r2state_init (ss)) {
		R_LOG_ERROR ("Failed to initialize r2 core\n");
		return false;
	}

	if (ss->rstate.file_opened) {
		R_LOG_INFO ("Closing previously opened file: %s", ss->rstate.current_file);
		r_core_cmd0 (core, "o-*");
		ss->rstate.file_opened = false;
		ss->rstate.current_file = NULL;
	}

	r_core_cmd0 (core, "e bin.relocs.apply=true");
	r_core_cmd0 (core, "e bin.cache=true");

	char *cmd = r_str_newf ("'o %s", filepath);
	R_LOG_INFO ("Running r2 command: %s", cmd);
	char *result = r_core_cmd_str (core, cmd);
	free (cmd);
	bool success = (result && strlen (result) > 0);
	free (result);

	if (!success) {
		R_LOG_INFO ("Trying alternative method to open file");
		RIODesc *fd = r_core_file_open (core, filepath, R_PERM_R, 0);
		if (fd) {
			r_core_bin_load (core, filepath, 0);
			R_LOG_INFO ("File opened using r_core_file_open");
			success = true;
		} else {
			R_LOG_ERROR ("Failed to open file: %s", filepath);
			return false;
		}
	}

	R_LOG_INFO ("Loading binary information");
	r_core_cmd0 (core, "ob");

	free (ss->rstate.current_file);
	ss->rstate.current_file = strdup (filepath);
	ss->rstate.file_opened = true;
	R_LOG_INFO ("File opened successfully: %s", filepath);

	return true;
}

static char *r2_analyze(ServerState *ss, int level) {
	if (ss && ss->http_mode) {
		/* In HTTP mode we won't run local analysis; return empty string. */
		return strdup ("");
	}
	RCore *core = ss->rstate.core;
	if (!core || !ss->rstate.file_opened) {
		return false;
	}
	const char *cmd = "aa";
#if 1
	switch (level) {
	case 1: cmd = "aac"; break;
	case 2: cmd = "aaa"; break;
	case 3: cmd = "aaaa"; break;
	case 4: cmd = "aaaaa"; break;
	}
#endif
	r2mcp_log_reset (ss);
	r_core_cmd0 (core, cmd);
	return r2mcp_log_drain (ss);
}
