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
static bool r2state_init(ServerState *ss) {
	RCore *core = r_core_new ();
	if (!core) {
		R_LOG_ERROR ("Failed to initialize radare2 core");
		return false;
	}

	r2state_settings (core);
	ss->rstate.core = core;

	R_LOG_INFO ("Radare2 core initialized");
	return true;
}

static void r2state_fini(ServerState *ss) {
	RCore *core = ss->rstate.core;
	if (core) {
		r_core_free (core);
		ss->rstate.core = NULL;
		ss->rstate.file_opened = false;
		ss->rstate.current_file = NULL;
	}
}

static inline void r2mcp_log(const char *x) {
	eprintf ("RESULT %s\n", x);
#if R2MCP_DEBUG
	r_file_dump (R2MCP_LOGFILE, (const ut8 *)(x), -1, true);
	r_file_dump (R2MCP_LOGFILE, (const ut8 *)"\n", -1, true);
#else
	// do nothing
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
		char *ch = strstr (res, "$(");
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

static char *r2_cmd(ServerState *ss, const char *cmd) {
	RCore *core = ss->rstate.core;
	if (!core || !ss->rstate.file_opened) {
		return strdup ("Use the openFile method before calling any other method");
	}
	bool changed = false;
	char *filteredCommand = r2_cmd_filter (cmd, &changed);
	if (changed) {
		r2mcp_log ("command injection prevented");
	}
	char *res = r_core_cmd_str (core, filteredCommand);
	free (filteredCommand);
	r2state_settings (core);
	return res;
}

static bool r2_open_file(ServerState *ss, const char *filepath) {
	R_LOG_INFO ("Attempting to open file: %s\n", filepath);
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

static bool r2_analyze(ServerState *ss, int level) {
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
	r_core_cmd0 (core, cmd);
	return true;
}

