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
