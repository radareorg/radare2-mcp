#pragma once

#include <stdbool.h>

typedef struct {
	const char *name;
	const char *description;
	bool required;
} PromptArg;

typedef struct PromptSpec {
	const char *name;
	const char *description;
	const PromptArg *args;
	int nargs;
	// Render returns a JSON object string with { messages: [...] }
	char *(*render)(const struct PromptSpec *spec, RJson *arguments);
} PromptSpec;

#include "r2mcp.h"

// Initialize and shutdown the prompts registry stored in ServerState
void prompts_registry_init(ServerState *ss);
void prompts_registry_fini(ServerState *ss);

// Build list JSON for prompts with optional pagination
char *prompts_build_list_json(const ServerState *ss, const char *cursor, int page_size);

// Resolve a prompt by name and arguments, returning a JSON object string
char *prompts_get_json(const ServerState *ss, const char *name, RJson *arguments);

