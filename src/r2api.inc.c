/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

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
		// R_LOG_INFO ("[%s] from=%s message=%s\n", typestr, origin, msg);
		fprintf (stderr, "[%s] %s\n", typestr, msg);
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

static inline void r2mcp_log(ServerState *ss, const char *x) {
	R_LOG_INFO ("[R2MCP] %s", x);
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

/* printf-like wrapper for r2mcp_cmd to avoid boilerplate */
char *r2mcp_cmdf(ServerState *ss, const char *fmt, ...) {
	if (!fmt) {
		return r2mcp_cmd (ss, "");
	}
	va_list ap;
	va_start (ap, fmt);
	va_list ap2;
	va_copy (ap2, ap);
	int n = vsnprintf (NULL, 0, fmt, ap2);
	va_end (ap2);
	if (n < 0) {
		va_end (ap);
		return NULL;
	}
	char *cmd = (char *)malloc ((size_t)n + 1);
	if (!cmd) {
		va_end (ap);
		return NULL;
	}
	vsnprintf (cmd, (size_t)n + 1, fmt, ap);
	va_end (ap);
	char *res = r2mcp_cmd (ss, cmd);
	free (cmd);
	return res;
}

static bool path_is_absolute(const char *p) {
	return p && p[0] == '/';
}

static bool path_contains_parent_ref(const char *p) {
	return p && strstr (p, "/../") != NULL;
}

static bool path_is_within_sandbox(const char *p, const char *sb) {
	if (!sb || !*sb) {
		return true;
	}
	size_t plen = strlen (p);
	size_t slen = strlen (sb);
	if (slen == 0 || slen > plen) {
		return false;
	}
	if (strncmp (p, sb, slen) != 0) {
		return false;
	}
	if (plen == slen) {
		return true; // exact match
	}
	// ensure boundary: next char must be '/'
	return p[slen] == '/';
}

R_IPI bool r2_open_file(ServerState *ss, const char *filepath) {
	R_LOG_INFO ("Attempting to open file: %s\n", filepath);

	// Security checks common to both local and HTTP modes
	if (R_STR_ISEMPTY (filepath)) {
		R_LOG_ERROR ("Empty file path is not allowed");
		return false;
	}
	bool is_uri = strstr (filepath, "://") != NULL;
	// Filesystem security checks only apply to local paths, not URI schemes
	if (!is_uri) {
		if (!path_is_absolute (filepath)) {
			R_LOG_ERROR ("Relative paths are not allowed. Use an absolute path");
			return false;
		}
		if (path_contains_parent_ref (filepath)) {
			R_LOG_ERROR ("Path traversal is not allowed (contains '/../')");
			return false;
		}
		if (ss->sandbox && *ss->sandbox) {
			if (!path_is_within_sandbox (filepath, ss->sandbox)) {
				R_LOG_ERROR ("Access denied: path is outside of the sandbox");
				return false;
			}
		}
	}

	/* In HTTP mode we do not touch the local r2 core. Just set the state
	 * so subsequent calls to r2mcp_cmd will be allowed (they will be handled
	 * by the HTTP helper).
	 */
	if (ss->http_mode) {
		free (ss->rstate.current_file);
		ss->rstate.current_file = strdup (filepath);
		ss->rstate.file_opened = true;
		return true;
	}

	RCore *core = ss->rstate.core;
	if (!core && !r2mcp_state_init (ss)) {
		R_LOG_ERROR ("Failed to initialize r2 core\n");
		return false;
	}

	if (ss->rstate.file_opened) {
		R_LOG_INFO ("Closing previously opened file: %s", ss->rstate.current_file);
		r_core_cmd0 (core, "o-*");
		ss->rstate.file_opened = false;
		free (ss->rstate.current_file);
		ss->rstate.current_file = NULL;
	}

	bool is_frida = strstr (filepath, "frida://") != NULL;
	if (is_frida) {
		ss->frida_mode = true;
	} else {
		r_core_cmd0 (core, "e bin.relocs.apply=true");
		r_core_cmd0 (core, "e bin.cache=true");
		R_LOG_INFO ("Loading binary information");
		r_core_cmd0 (core, "ob");
	}

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
	free (ss->rstate.current_file);
	ss->rstate.current_file = strdup (filepath);
	ss->rstate.file_opened = true;
	R_LOG_INFO ("File opened successfully: %s", filepath);

	return true;
}

R_IPI char *r2_analyze(ServerState *ss, int level) {
	if (ss && ss->http_mode) {
		/* In HTTP mode we won't run local analysis; return empty string. */
		return strdup ("");
	}
	RCore *core = ss->rstate.core;
	if (!core || !ss->rstate.file_opened) {
		return NULL;
	}
	const char *cmd = "aa";
	if (!ss->ignore_analysis_level) {
		switch (level) {
		case 1: cmd = "aac"; break;
		case 2: cmd = "aaa"; break;
		case 3: cmd = "aaaa"; break;
		case 4: cmd = "aaaaa"; break;
		}
	}
	r2mcp_log_reset (ss);
	r_core_cmd0 (core, cmd);
	return r2mcp_log_drain (ss);
}
