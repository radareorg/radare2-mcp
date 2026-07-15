/* r2mcp - MIT - Copyright 2026 - pancake */

typedef struct {
	const char *address;
	const char *port;
	char *address_copy;
	bool local_only;
} R2McpBind;

static bool r2mcp_bind_parse(const char *address_port, const char *default_port, R2McpBind *bind) {
	const char *separator;
	R_RETURN_VAL_IF_FAIL (bind, false);
	memset (bind, 0, sizeof (*bind));
	bind->address = "127.0.0.1";
	bind->local_only = true;
	if (R_STR_ISEMPTY (address_port)) {
		if (R_STR_ISEMPTY (default_port)) {
			return false;
		}
		bind->port = default_port;
		return true;
	}
	separator = strchr (address_port, ':');
	if (separator) {
		if (separator == address_port || R_STR_ISEMPTY (separator + 1)) {
			return false;
		}
		bind->address_copy = r_str_ndup (address_port, separator - address_port);
		bind->address = bind->address_copy;
		bind->port = separator + 1;
	} else {
		bind->port = address_port;
	}
	if (strcmp (bind->address, "127.0.0.1") && strcmp (bind->address, "localhost") && strcmp (bind->address, "0.0.0.0")) {
		free (bind->address_copy);
		bind->address_copy = NULL;
		return false;
	}
	bind->local_only = strcmp (bind->address, "0.0.0.0") != 0;
	return true;
}

static void r2mcp_bind_fini(R2McpBind *bind) {
	if (bind) {
		free (bind->address_copy);
		bind->address_copy = NULL;
	}
}
