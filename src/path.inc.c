/* r2mcp - MIT - Copyright 2026 - pancake */

// TODO: move this code into r2's util api for portability reasons

#if R2__WINDOWS__
#include <windows.h>
#endif

static bool r2mcp_path_contains_parent_ref(const char *path) {
	if (!path) {
		return false;
	}
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

#if R2__WINDOWS__
static char *r2mcp_path_realpath(const char *path) {
	if (!path) {
		return NULL;
	}
	HANDLE h = CreateFileA (path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD n = GetFinalPathNameByHandleA (h, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (!n) {
		CloseHandle (h);
		return NULL;
	}
	char *buf = malloc ((size_t)n + 1);
	if (!buf) {
		CloseHandle (h);
		return NULL;
	}
	DWORD got = GetFinalPathNameByHandleA (h, buf, n, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	CloseHandle (h);
	if (!got) {
		free (buf);
		return NULL;
	}
	buf[got] = '\0';
	if (r_str_startswith (buf, "\\\\?\\UNC\\")) {
		char *ret = r_str_newf ("\\\\%s", buf + 8);
		free (buf);
		return ret;
	}
	if (r_str_startswith (buf, "\\\\?\\")) {
		char *ret = strdup (buf + 4);
		free (buf);
		return ret;
	}
	return buf;
}
#else
static char *r2mcp_path_realpath(const char *path) {
	if (!path) {
		return NULL;
	}
	return realpath (path, NULL);
}
#endif

static bool r2mcp_path_is_within_sandbox(const char *path, const char *sandbox) {
	if (R_STR_ISEMPTY (sandbox)) {
		return true;
	}
	if (!path) {
		return false;
	}
	char *rp = r2mcp_path_realpath (path);
	if (!rp) {
		R_LOG_ERROR ("Access denied: unable to resolve path");
		return false;
	}
	char *rs = r2mcp_path_realpath (sandbox);
	if (!rs) {
		R_LOG_ERROR ("Access denied: unable to resolve sandbox path");
		free (rp);
		return false;
	}
	bool ret = false;
	size_t sl = strlen (rs);
	if (r_str_startswith (rp, rs)) {
		char c = rp[sl];
		ret = (c == '\0' || c == '/' || c == '\\' || rs[sl - 1] == '/' || rs[sl - 1] == '\\');
	}
	free (rp);
	free (rs);
	return ret;
}

static const char *r2mcp_sandbox_check(ServerState *ss, const char *path) {
	if (R_STR_ISEMPTY (path)) {
		return "Empty file path is not allowed";
	}
	if (strstr (path, "://")) {
		return "URI paths are not allowed here";
	}
	if ((path[0] == '/' || path[0] == '\\') && (path[1] == '/' || path[1] == '\\')) {
		return "Network and device paths are not allowed";
	}
#if R2__WINDOWS__
	if (!isalpha ((unsigned char)path[0]) || path[1] != ':' || (path[2] != '/' && path[2] != '\\')) {
		return "Use an absolute path on a local drive";
	}
	char root[] = { path[0], ':', '\\', 0 };
	UINT drive_type = GetDriveTypeA (root);
	if (drive_type == DRIVE_REMOTE || drive_type == DRIVE_UNKNOWN || drive_type == DRIVE_NO_ROOT_DIR) {
		return "Network and unavailable drives are not allowed";
	}
#endif
	if (!r_file_is_abspath (path)) {
		return "Relative paths are not allowed. Use an absolute path";
	}
	if (r2mcp_path_contains_parent_ref (path)) {
		return "Path traversal is not allowed (contains '..' path segments)";
	}
	if (*path == '.' || strstr (path, "/.") || strstr (path, "\\.")) {
		return "Access denied: hidden paths are not allowed";
	}
	if (ss->sandbox && *ss->sandbox && !r2mcp_path_is_within_sandbox (path, ss->sandbox)) {
		return "Access denied: path is outside of the sandbox";
	}
	return NULL;
}

static const char *r2mcp_open_path_check(ServerState *ss, const char *path) {
	if (R_STR_ISEMPTY (path)) {
		return "Empty file path is not allowed";
	}
	int grain = 0;
	if (!r_sandbox_grain_parse (r2mcp_effective_sandbox_grain (ss), &grain)) {
		return "Invalid sandbox grain";
	}
	if (strstr (path, "://")) {
		if (R_STR_ISNOTEMPTY (ss->sandbox)) {
			return "URI paths are not allowed with a filesystem sandbox";
		}
		// Frida uses its own process/network APIs rather than r2's sandbox wrappers.
		if (r_str_startswith (path, "frida://") &&
			(! (grain & R_SANDBOX_GRAIN_EXEC) || ! (grain & R_SANDBOX_GRAIN_NETWORK) ||
				!r_sandbox_check (R_SANDBOX_GRAIN_EXEC) || !r_sandbox_check (R_SANDBOX_GRAIN_NETWORK))) {
			return "Frida requires exec and network sandbox permissions";
		}
		return NULL;
	}
	const char *err = r2mcp_sandbox_check (ss, path);
	if (err) {
		return err;
	}
	if (!r_file_is_regular (path)) {
		return "Only existing regular files can be opened";
	}
	if (ss->rstate->core) {
		RIOPlugin *plugin = r_io_plugin_resolve (ss->rstate->core->io, path, false);
		if (!plugin || strcmp (plugin->meta.name, "default")) {
			return "Local paths must use the default file plugin";
		}
	}
	return NULL;
}
