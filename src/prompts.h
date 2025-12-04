#pragma once

#include <stdbool.h>
#include "r2mcp.h"

typedef struct {
	const char *name;
	const char *description;
	bool required;
} PromptArg;

typedef struct PromptSpec {
	const char *name;
	const char *description;
	PromptArg *args;
	int nargs;
	// Render returns a JSON object string with { messages: [...] }
	char *(*render)(const struct PromptSpec *spec, RJson *arguments);
	void *render_data;
} PromptSpec;

// Initialize and shutdown the prompts registry stored in ServerState
void prompts_registry_init(ServerState *ss);
void prompts_registry_fini(ServerState *ss);

// Build list JSON for prompts with optional pagination
char *prompts_build_list_json(const ServerState *ss, const char *cursor, int page_size);

// Resolve a prompt by name and arguments, returning a JSON object string
char *prompts_get_json(const ServerState *ss, const char *name, RJson *arguments);

