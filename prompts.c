#include "r2mcp.h"
#include "prompts.h"

static char *json_text_msg(const char *role, const char *text) {
	PJ *pj = pj_new();
	pj_o(pj);
	pj_ks(pj, "role", role);
	pj_k(pj, "content");
	pj_a(pj);
	pj_o(pj);
	pj_ks(pj, "type", "text");
	pj_ks(pj, "text", text);
	pj_end(pj);
	pj_end(pj);
	pj_end(pj);
	return pj_drain(pj);
}

static char *json_messages_obj2(char *m1, char *m2) {
	RStrBuf *sb = r_strbuf_new("{");
	r_strbuf_append(sb, "\"messages\":[");
	if (m1) {
		r_strbuf_append(sb, m1);
		if (m2) r_strbuf_append(sb, ",");
	}
	if (m2) {
		r_strbuf_append(sb, m2);
	}
	r_strbuf_append(sb, "]}");
	free(m1);
	free(m2);
	return r_strbuf_drain(sb);
}


// Utility to fetch string argument value
static const char *arg_str(RJson *arguments, const char *key, const char *dflt) {
	const char *s = r_json_get_str(arguments, key);
	return s ? s : dflt;
}

// ---------- Prompt renderers ----------

// crackme solver
static char *render_crackme(const PromptSpec *spec, RJson *arguments) {
	(void)spec;
	const char *filePath = r_json_get_str(arguments, "filePath");
	const char *goal = arg_str(arguments, "goal", "Recover the correct input or bypass check");

	const char *sys =
		"You are an expert reverse engineer using radare2 via r2mcp.\n"
		"Goal: plan first, then execute minimal tool calls.\n"
		"General steps:\n"
		"1) Open the target binary and run lightweight analysis (analyze level 2).\n"
		"2) Identify main/entrypoints and functions referring to strcmp, strncmp, memcmp, crypto, or suspicious branches.\n"
		"3) Read/Decompile only the most relevant functions (avoid dumping huge outputs).\n"
		"4) Derive the key/logic and propose inputs or patches.\n"
		"5) Summarize findings and next actions.\n"
		"Prefer afl listing with addresses, selective pdc/pdf on key functions, and xrefsTo for checks.\n";

	RStrBuf *user = r_strbuf_new("");
	r_strbuf_appendf(user, "Task: %s.\n", goal);
	if (filePath && *filePath) {
		r_strbuf_appendf(user, "Open file: %s (use tools/call openFile).\n", filePath);
	} else {
		r_strbuf_append(user, "Ask for or confirm file path if unknown.\n");
	}
	r_strbuf_append(user,
			"Plan your steps, then call: analyze(level=2), listEntrypoints, listFunctions, listImports, listStrings(filter optional).\n"
			"Use decompileFunction or disassembleFunction on candidate functions only.\n");

	char *m1 = json_text_msg("system", sys);
	char *m2 = json_text_msg("user", r_strbuf_get(user));
	char *out = json_messages_obj2(m1, m2);
	r_strbuf_free(user);
	return out;
}

// find cryptographic material
static char *render_crypto(const PromptSpec *spec, RJson *arguments) {
	(void)spec;
	const char *hint = arg_str(arguments, "hint", "Look for keys, IVs, S-boxes, constants, PRNG seeds");
	const char *sys =
		"You are tasked with locating cryptographic material in a binary.\n"
		"Strategy:\n"
		"- List imports and strings to find crypto APIs/signatures.\n"
		"- Search for constants (AES S-box, SHA tables), base64 sets, or long random-looking blobs.\n"
		"- Inspect xrefs to functions handling buffers just before encryption/decryption.\n"
		"- Use selective decompilation and avoid dumping entire files.\n";

	RStrBuf *user = r_strbuf_new("");
	r_strbuf_appendf(user, "Focus: %s.\n", hint);
	r_strbuf_append(user,
			"Use: listImports, listStrings(filter to crypto keywords), listFunctions (scan for suspicious names), and xrefsTo(address).\n"
			"If needed, disassemble/decompile only tight regions where material is assigned.\n");

	char *m1 = json_text_msg("system", sys);
	char *m2 = json_text_msg("user", r_strbuf_get(user));
	char *out = json_messages_obj2(m1, m2);
	r_strbuf_free(user);
	return out;
}

// document assembly code for a function
static char *render_document_function(const PromptSpec *spec, RJson *arguments) {
	(void)spec;
	const char *address = r_json_get_str(arguments, "address");
	const char *depth = arg_str(arguments, "detail", "concise");

	const char *sys =
		"Produce a clear, structured explanation of a function’s behavior.\n"
		"Guidelines:\n"
		"- Summarize purpose, inputs/outputs, side effects.\n"
		"- Highlight algorithms, notable constants, error paths.\n"
		"- Provide a brief high-level pseudocode if helpful.\n";

	RStrBuf *user = r_strbuf_new("");
	if (address && *address) {
		r_strbuf_appendf(user, "Target function address: %s.\n", address);
	} else {
		r_strbuf_append(user, "Ask for an address to document.\n");
	}
	r_strbuf_appendf(user,
			"Detail level: %s.\nUse: getCurrentAddress (to verify), disassembleFunction(address), decompileFunction(address), getFunctionPrototype(address).\n",
			depth);

	char *m1 = json_text_msg("system", sys);
	char *m2 = json_text_msg("user", r_strbuf_get(user));
	char *out = json_messages_obj2(m1, m2);
	r_strbuf_free(user);
	return out;
}

// find control-flow path between two addresses (for exploit dev or reachability)
static char *render_cfg_path(const PromptSpec *spec, RJson *arguments) {
	(void)spec;
	const char *src = r_json_get_str(arguments, "sourceAddress");
	const char *dst = r_json_get_str(arguments, "targetAddress");
	const char *sys =
		"Find and explain a feasible control-flow path between two addresses.\n"
		"Approach:\n"
		"- Identify function boundaries for source/target.\n"
		"- Use xrefsTo and selective disassembly to traverse edges.\n"
		"- Summarize the path as a sequence of blocks with conditions.\n";

	RStrBuf *user = r_strbuf_new("");
	r_strbuf_append(user, "Compute a path with minimal output.\n");
	if (src) r_strbuf_appendf(user, "Source: %s. ", src);
	if (dst) r_strbuf_appendf(user, "Target: %s. ", dst);
	r_strbuf_append(user, "Use: getCurrentAddress, disassembleFunction, disassemble, xrefsTo.\n");

	char *m1 = json_text_msg("system", sys);
	char *m2 = json_text_msg("user", r_strbuf_get(user));
	char *out = json_messages_obj2(m1, m2);
	r_strbuf_free(user);
	return out;
}

// ---------- Registry ----------


static PromptArg ARGS_CRACKME[] = {
	{"filePath", "Absolute path to target binary", false},
	{"goal", "What success looks like (e.g., recover password)", false},
};

static PromptArg ARGS_DOCUMENT_FUNCTION[] = {
	{"address", "Function start address to document", true},
	{"detail", "Level of detail: concise|full", false},
};

static PromptArg ARGS_CFG_PATH[] = {
	{"sourceAddress", "Source address or block", true},
	{"targetAddress", "Target address or block", true},
};

static PromptArg ARGS_CRYPTO[] = {
	{"hint", "Extra context (e.g., suspected algorithm)", false},
};

static PromptSpec builtin_prompts[] = {
	{
		.name = "crackme_solver",
		.description = "Plan and solve a crackme using radare2 with minimal, targeted steps",
		.args = ARGS_CRACKME,
		.nargs = (int)(sizeof(ARGS_CRACKME)/sizeof(ARGS_CRACKME[0])),
		.render = render_crackme,
	},
	{
		.name = "find_crypto_material",
		.description = "Locate keys, IVs, S-boxes, and crypto constants",
		.args = ARGS_CRYPTO,
		.nargs = (int)(sizeof(ARGS_CRYPTO)/sizeof(ARGS_CRYPTO[0])),
		.render = render_crypto,
	},
	{
		.name = "document_function",
		.description = "Explain a function’s purpose, behavior, and pseudocode",
		.args = ARGS_DOCUMENT_FUNCTION,
		.nargs = (int)(sizeof(ARGS_DOCUMENT_FUNCTION)/sizeof(ARGS_DOCUMENT_FUNCTION[0])),
		.render = render_document_function,
	},
	{
		.name = "find_control_flow_path",
		.description = "Find a control-flow path between two addresses for reachability or exploit planning",
		.args = ARGS_CFG_PATH,
		.nargs = (int)(sizeof(ARGS_CFG_PATH)/sizeof(ARGS_CFG_PATH[0])),
		.render = render_cfg_path,
	},
};

typedef struct {
	RList *list; // of PromptSpec* (borrowed pointers to builtin entries)
} PromptRegistry;

void prompts_registry_init(ServerState *ss) {
	if (ss->prompts) return;
	PromptRegistry *reg = R_NEW0(PromptRegistry);
	if (!reg) return;
	reg->list = r_list_new();
	if (!reg->list) {
		free(reg);
		return;
	}
	// Append pointers to builtin prompts
	size_t n = sizeof(builtin_prompts)/sizeof(builtin_prompts[0]);
	for (size_t i = 0; i < n; i++) {
		r_list_append(reg->list, &builtin_prompts[i]);
	}
	ss->prompts = reg;
}

void prompts_registry_fini(ServerState *ss) {
	if (!ss || !ss->prompts) return;
	PromptRegistry *reg = (PromptRegistry*)ss->prompts;
	r_list_free(reg->list);
	free(reg);
	ss->prompts = NULL;
}

static PromptSpec *prompts_find(const ServerState *ss, const char *name) {
	if (!ss || !ss->prompts || !name) return NULL;
	PromptRegistry *reg = (PromptRegistry*)ss->prompts;
	RListIter *it; PromptSpec *p;
	r_list_foreach(reg->list, it, p) {
		if (!strcmp(p->name, name)) return p;
	}
	return NULL;
}

char *prompts_build_list_json(const ServerState *ss, const char *cursor, int page_size) {
	if (!ss || !ss->prompts) {
		PJ *pj = pj_new();
		pj_o(pj);
		pj_k(pj, "prompts");
		pj_a(pj);
		pj_end(pj); // end array
		pj_end(pj); // end object
		return pj_drain(pj);
	}

	PromptRegistry *reg = (PromptRegistry*)ss->prompts;

	int start_index = 0;
	if (cursor) {
		start_index = atoi(cursor);
		if (start_index < 0) start_index = 0;
	}
	int total = r_list_length(reg->list);
	int end_index = start_index + page_size;
	if (end_index > total) end_index = total;

	PJ *pj = pj_new();
	pj_o(pj);
	pj_k(pj, "prompts");
	pj_a(pj);

	RListIter *it; PromptSpec *p; int idx = 0;
	r_list_foreach(reg->list, it, p) {
		if (idx >= start_index && idx < end_index) {
			pj_o(pj);
			pj_ks(pj, "name", p->name);
			pj_ks(pj, "description", p->description ? p->description : "");
			pj_k(pj, "arguments");
			pj_a(pj);
			for (int i = 0; i < p->nargs; i++) {
				pj_o(pj);
				pj_ks(pj, "name", p->args[i].name);
				pj_ks(pj, "description", p->args[i].description ? p->args[i].description : "");
				pj_kb(pj, "required", p->args[i].required);
				pj_end(pj);
			}
			pj_end(pj); // end arguments array
			pj_end(pj); // end prompt object
		}
		idx++;
	}

	pj_end(pj); // end prompts array
	if (end_index < total) {
		char buf[32];
		snprintf(buf, sizeof(buf), "%d", end_index);
		pj_ks(pj, "nextCursor", buf);
	}
	pj_end(pj); // end root object
	return pj_drain(pj);
}

char *prompts_get_json(const ServerState *ss, const char *name, RJson *arguments) {
	PromptSpec *spec = prompts_find(ss, name);
	if (!spec) {
		return NULL;
	}
	return spec->render(spec, arguments);
}
