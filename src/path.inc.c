/* r2mcp - MIT - Copyright 2026 - pancake */

// TODO: move this code into r2's util api for portability reasons

static bool r2mcp_path_contains_parent_ref(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, false);
	const char *p = path;
	while ((p = strstr (p, ".."))) {
		bool at_start = (p == path || p[-1] == '/' || p[-1] == '\\');
		bool at_end = (!p[2] || p[2] == '/' || p[2] == '\\');
		if (at_start && at_end) {
			return true;
		}
		p += 2;
	}
	return false;
}

static bool r2mcp_path_is_within_sandbox(const char *path, const char *sandbox) {
	if (R_STR_ISEMPTY (sandbox)) {
		return true;
	}
	R_RETURN_VAL_IF_FAIL (path, false);
	char *rp = r_file_abspath (path);
	char *rs = r_file_abspath (sandbox);
	bool ret = false;
	if (rp && rs) {
		size_t sl = strlen (rs);
		if (r_str_startswith (rp, rs)) {
			char c = rp[sl];
			ret = (c == '\0' || c == '/' || c == '\\' || rs[sl - 1] == '/' || rs[sl - 1] == '\\');
		}
	} else {
		R_LOG_ERROR ("Access denied: unable to resolve path");
	}
	free (rp);
	free (rs);
	return ret;
}

static const char *r2mcp_sandbox_check(ServerState *ss, const char *path) {
	if (!r_file_is_abspath (path)) {
		return "Relative paths are not allowed. Use an absolute path";
	}
	if (r2mcp_path_contains_parent_ref (path)) {
		return "Path traversal is not allowed (contains '..' path segments)";
	}
	if (ss->sandbox && *ss->sandbox && !r2mcp_path_is_within_sandbox (path, ss->sandbox)) {
		return "Access denied: path is outside of the sandbox";
	}
	return NULL;
}
