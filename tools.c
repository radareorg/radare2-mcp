#include <r_core.h>
#include "r2mcp.h"
#include "tools.h"

static inline ToolMode current_mode(const ServerState *ss) {
	if (ss->http_mode) {
		return TOOL_MODE_HTTP;
	}
	if (ss->minimode) {
		return TOOL_MODE_MINI;
	}
	return TOOL_MODE_NORMAL;
}

static ToolSpec *tool(const char *name, const char *desc, const char *schema, int modes) {
	ToolSpec *t = R_NEW0 (ToolSpec);
	if (!t) {
		return NULL;
	}
	t->name = name;
	t->description = desc;
	t->schema_json = schema;
	t->modes = modes;
	return t;
}

void tools_registry_init(ServerState *ss) {
	if (ss->tools) {
		return; // already initialized
	}
	ss->tools = r_list_newf (free);
	if (!ss->tools) {
		return;
	}

	// Modes convenience
	const int M_MINI = TOOL_MODE_MINI;
	const int M_HTTP = TOOL_MODE_HTTP;
	// const int M_ALL  = TOOL_MODE_NORMAL; // normal only

	// Normal mode: full set
	r_list_append ( (RList *)ss->tools, tool ("openFile",
				"Opens a binary file with radare2 for analysis <think>Call this tool before any other one from r2mcp. Use an absolute filePath</think>",
				"{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"filePath\"]}",
				TOOL_MODE_NORMAL | M_MINI));

	r_list_append ( (RList *)ss->tools, tool ("closeFile",
				"Close the currently open file",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listFunctions",
				"Lists all functions discovered during analysis",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listLibraries",
				"Lists all shared libraries linked to the binary",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listImports",
				"Lists imported symbols (note: use listSymbols for addresses with sym.imp. prefix)",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listSections",
				"Displays memory sections and segments from the binary",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("showFunctionDetails",
				"Displays detailed information about the current function",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("getCurrentAddress",
				"Shows the current position and function name",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("showHeaders",
				"Displays binary headers and file information",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listSymbols",
				"Shows all symbols (functions, variables, imports) with addresses",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listEntrypoints",
				"Displays program entrypoints, constructors and main function",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listMethods",
				"Lists all methods belonging to the specified class",
				"{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list methods for\"}},\"required\":[\"classname\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listClasses",
				"Lists class names from various languages (C++, ObjC, Swift, Java, Dalvik)",
				"{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("listDecompilers",
				"Shows all available decompiler backends",
				"{\"type\":\"object\",\"properties\":{}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("renameFunction",
				"Renames the function at the specified address",
				"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"New function name\"},\"address\":{\"type\":\"string\",\"description\":\"Address of the function to rename\"}},\"required\":[\"name\",\"address\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("useDecompiler",
				"Selects which decompiler backend to use (default: pdc)",
				"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("getFunctionPrototype",
				"Retrieves the function signature at the specified address",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"}},\"required\":[\"address\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("setFunctionPrototype",
				"Sets the function signature (return type, name, arguments)",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function\"},\"prototype\":{\"type\":\"string\",\"description\":\"Function signature in C-like syntax\"}},\"required\":[\"address\",\"prototype\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("setComment",
				"Adds a comment at the specified address",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to put the comment in\"},\"message\":{\"type\":\"string\",\"description\":\"Comment text to use\"}},\"required\":[\"address\",\"message\"]}",
				TOOL_MODE_NORMAL | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listStrings",
				"Lists strings from data sections with optional regex filter",
				"{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("listAllStrings",
				"Scans the entire binary for strings with optional regex filter",
				"{\"type\":\"object\",\"properties\":{\"filter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("analyze",
				"Runs binary analysis with optional depth level",
				"{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0-4, higher is more thorough)\"}},\"required\":[]}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("xrefsTo",
				"Finds all code references to the specified address",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to check for cross-references\"}},\"required\":[\"address\"]}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("decompileFunction",
				"Show C-like pseudocode of the function in the given address. <think>Use this to inspect the code in a function, do not run multiple times in the same offset</think>",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"}},\"required\":[\"address\"]}",
				TOOL_MODE_NORMAL | M_MINI | M_HTTP));

	r_list_append ( (RList *)ss->tools, tool ("disassembleFunction",
				"Shows assembly listing of the function at the specified address",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"}},\"required\":[\"address\"]}",
				TOOL_MODE_NORMAL));

	r_list_append ( (RList *)ss->tools, tool ("disassemble",
				"Disassembles a specific number of instructions from an address <think>Use this tool to inspect a portion of memory as code without depending on function analysis boundaries. Use this tool when functions are large and you are only interested on few instructions</think>",
				"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"numInstructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble (default: 10)\"}},\"required\":[\"address\"]}",
				TOOL_MODE_NORMAL));
}

void tools_registry_fini(ServerState *ss) {
	if (ss && ss->tools) {
		r_list_free ( (RList *)ss->tools);
		ss->tools = NULL;
	}
}

static bool tool_matches_mode(const ToolSpec *t, ToolMode mode) {
	return (t->modes & mode) != 0;
}

static RList *tools_filtered_for_mode(const ServerState *ss) {
	ToolMode mode = current_mode (ss);
	RList *out = r_list_new ();
	if (!out) {
		return NULL;
	}
	RListIter *it;
	ToolSpec *t;
	r_list_foreach ( ( (RList *)ss->tools), it, t) {
		if (tool_matches_mode (t, mode)) {
			r_list_append (out, t); // reference only
		}
	}
	return out;
}

bool tools_is_tool_allowed(const ServerState *ss, const char *name) {
	if (ss->permissive_tools) {
		return true;
	}
	if (!ss->tools || !name) {
		return false;
	}
	ToolMode mode = current_mode (ss);
	RListIter *it;
	ToolSpec *t;
	r_list_foreach ( ( (RList *)ss->tools), it, t) {
		if (!strcmp (t->name, name)) {
			return tool_matches_mode (t, mode);
		}
	}
	return false;
}

char *tools_build_catalog_json(const ServerState *ss, const char *cursor, int page_size) {
	if (!ss->tools) {
		return strdup ("{\"tools\":[]}");
	}

	int start_index = 0;
	if (cursor) {
		start_index = atoi (cursor);
		if (start_index < 0) start_index = 0;
	}

	RList *list = tools_filtered_for_mode (ss);
	if (!list) {
		return strdup ("{\"tools\":[]}");
	}
	int total_tools = r_list_length (list);
	int end_index = start_index + page_size;
	if (end_index > total_tools) end_index = total_tools;

	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "{\"tools\":[");

	int idx = 0;
	int out_count = 0;
	RListIter *it;
	ToolSpec *t;
	r_list_foreach (list, it, t) {
		if (idx >= start_index && idx < end_index) {
			if (out_count > 0) {
				r_strbuf_append (sb, ",");
			}
			r_strbuf_appendf (sb,
					"{\"name\":\"%s\",\"description\":\"%s\",\"inputSchema\":%s}",
					t->name, t->description, t->schema_json);
			out_count++;
		}
		idx++;
		if (idx >= end_index) {
			// keep looping for correctness of idx but we could break
		}
	}

	r_strbuf_append (sb, "]");
	if (end_index < total_tools) {
		r_strbuf_appendf (sb, ",\"nextCursor\":\"%d\"", end_index);
	}
	r_strbuf_append (sb, "}");

	r_list_free (list);
	return r_strbuf_drain (sb);
}
