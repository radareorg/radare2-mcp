/* r2mcp - MIT - Copyright 2025-2026 - pancake, dnakov */

#include "r2mcp.h"
#include "prompts.h"

typedef struct {
	char *name;
	char *description;
	char *required;
} ParsedArg;

typedef struct {
	char *name;
	char *description;
	char *content;
	char *user_template;
	RList *args;
} ParsedPrompt;

static char *json_text_msg(const char *role, const char *text) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "role", role);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", text);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static char *json_messages_obj2(char *m1, char *m2) {
	RStrBuf *sb = r_strbuf_new ("{");
	r_strbuf_append (sb, "\"messages\":[");
	if (m1) {
		r_strbuf_append (sb, m1);
		if (m2) {
			r_strbuf_append (sb, ",");
		}
	}
	if (m2) {
		r_strbuf_append (sb, m2);
	}
	r_strbuf_append (sb, "]}");
	free (m1);
	free (m2);
	return r_strbuf_drain (sb);
}

static char *expand_template(const char *template, RJson *arguments) {
	RStrBuf *sb = r_strbuf_new ("");
	const char *p = template;
	while (*p) {
		if (*p == '{') {
			if (r_str_startswith (p, "{if ")) {
				p += 4;
				const char *arg_start = p;
				char *end = strchr (p, '}');
				if (end) {
					char *arg = r_str_ndup (arg_start, end - arg_start);
					const char *val = r_json_get_str (arguments, arg);
					p = end + 1;
					const char *if_content = p;
					const char *else_pos = strstr (p, "{else}");
					const char *endif_pos = strstr (p, "{/if}");
					if (val && *val) {
						const char *end_content = else_pos? else_pos: endif_pos;
						if (end_content) {
							r_strbuf_append_n (sb, if_content, end_content - if_content);
							p = end_content + (else_pos? 6: 5);
						}
					} else {
						if (else_pos) {
							const char *else_content = else_pos + 6;
							const char *end_content = endif_pos;
							if (end_content) {
								r_strbuf_append_n (sb, else_content, end_content - else_content);
								p = end_content + 5;
							}
						} else {
							if (endif_pos) {
								p = endif_pos + 5;
							}
						}
					}
					free (arg);
				}
			} else {
				char *end = strchr (p, '}');
				if (end) {
					char *arg = r_str_ndup (p + 1, end - p - 1);
					const char *val = r_json_get_str (arguments, arg);
					if (val) {
						r_strbuf_append (sb, val);
					}
					p = end + 1;
					free (arg);
				} else {
					r_strbuf_appendf (sb, "%c", *p);
					p++;
				}
			}
		} else {
			r_strbuf_appendf (sb, "%c", *p);
			p++;
		}
	}
	return r_strbuf_drain (sb);
}

static char *render_loaded(const PromptSpec *spec, RJson *arguments) {
	ParsedPrompt *pp = (ParsedPrompt *)spec->render_data;
	char *user = NULL;
	if (pp->user_template) {
		user = expand_template (pp->user_template, arguments);
	}
	char *m1 = json_text_msg ("system", pp->content);
	char *m2 = user? json_text_msg ("user", user): NULL;
	char *out = json_messages_obj2 (m1, m2);
	free (user);
	return out;
}

static ParsedPrompt *parse_r2ai_md(const char *path) {
	size_t size;
	char *data = r_file_slurp (path, &size);
	if (!data) {
		return NULL;
	}
	ParsedPrompt *pp = R_NEW0 (ParsedPrompt);
	const char *basename = r_file_basename (path);
	char *name_dup = strdup (basename);
	char *dot = strstr (name_dup, ".r2ai.md");
	if (dot) {
		*dot = 0;
	}
	pp->name = name_dup;
	char *p = data;
	if (size < 4 || strncmp (p, "---\n", 4)) {
		goto fail;
	}
	p += 4;
	char *end = strstr (p, "\n---\n");
	if (!end) {
		goto fail;
	}
	*end = 0;
	char *front = p;
	p = end + 5;
	pp->content = r_str_trim_dup (p);
	char *front_copy = strdup (front);
	char *line = strtok (front_copy, "\n");
	int in_args = 0;
	RList *args = NULL;
	while (line) {
		char *trimmed_line = r_str_trim_dup (line);
		if (!*trimmed_line) {
			free (trimmed_line);
			line = strtok (NULL, "\n");
			continue;
		}
		if (!strcmp (trimmed_line, "args:")) {
			in_args = 1;
			args = r_list_newf (free);
			free (trimmed_line);
			line = strtok (NULL, "\n");
			continue;
		}
		if (in_args) {
			if (trimmed_line[0] == '-') {
				char *arg_line = trimmed_line + 1;
				char *trimmed_arg = r_str_trim_dup (arg_line);
				ParsedArg *arg = R_NEW0 (ParsedArg);
				char *colon = strchr (trimmed_arg, ':');
				if (colon) {
					*colon = 0;
					char *key = r_str_trim_dup (trimmed_arg);
					char *value = r_str_trim_dup (colon + 1);
					if (!strcmp (key, "name")) {
						arg->name = value;
					} else if (!strcmp (key, "description")) {
						arg->description = value;
					} else if (!strcmp (key, "required")) {
						arg->required = value;
					} else {
						free (value);
					}
					free (key);
				}
				free (trimmed_arg);
				if (arg->name) {
					r_list_append (args, arg);
				} else {
					free (arg);
				}
			} else {
				in_args = 0;
			}
		}
		if (!in_args) {
			char *colon = strchr (trimmed_line, ':');
			if (colon) {
				*colon = 0;
				char *key = r_str_trim_dup (trimmed_line);
				char *value = r_str_trim_dup (colon + 1);
				if (!strcmp (key, "description")) {
					pp->description = value;
				} else if (!strcmp (key, "user_template")) {
					if (value[0] == '|') {
						RStrBuf *sb = r_strbuf_new ("");
						free (value);
						line = strtok (NULL, "\n");
						while (line) {
							char *trimmed = r_str_trim_dup (line);
							if (!*trimmed) {
								free (trimmed);
								line = strtok (NULL, "\n");
								continue;
							}
							r_strbuf_append (sb, trimmed);
							r_strbuf_append (sb, "\n");
							free (trimmed);
							line = strtok (NULL, "\n");
						}
						pp->user_template = r_strbuf_drain (sb);
					} else {
						free (value);
					}
				} else {
					free (value);
				}
				free (key);
			}
		}
		free (trimmed_line);
		line = strtok (NULL, "\n");
	}
	pp->args = args;
	free (front_copy);
	free (data);
	return pp;
fail:
	free (pp->name);
	free (pp->description);
	free (pp->content);
	free (pp->user_template);
	r_list_free (pp->args);
	free (pp);
	free (data);
	return NULL;
}

// ---------- Registry ----------

typedef struct {
	RList *list; // of PromptSpec*(borrowed pointers to builtin entries)
} PromptRegistry;

void prompts_registry_init(ServerState *ss) {
	if (ss->prompts) {
		return;
	}
	PromptRegistry *reg = R_NEW0 (PromptRegistry);
	reg->list = r_list_new ();
	if (!reg->list) {
		free (reg);
		return;
	}
	// Load prompts from directories
	// Support colon-separated paths like r2ai
	RList *dirs_list = r_list_newf (free);

	if (ss->prompts_dir) {
		// Parse colon-separated custom directories using r_str_split_duplist
		RList *path_parts = r_str_split_duplist (ss->prompts_dir, ":", true);
		if (path_parts) {
			RListIter *it;
			char *path_part;
			r_list_foreach (path_parts, it, path_part) {
				if (path_part && *path_part) {
					char *expanded = r_file_home (path_part);
					if (expanded) {
						r_list_append (dirs_list, expanded);
					} else {
						// If r_file_home fails, try direct path
						r_list_append (dirs_list, strdup (path_part));
					}
				}
			}
			r_list_free (path_parts);
		}
	} else {
		// Default directories when no custom path specified
		const char *default_paths[] = { "prompts", "~/.config/r2ai/prompts", "~/.config/r2mcp/prompts", NULL };
		for (int i = 0; default_paths[i]; i++) {
			char *expanded = r_file_home (default_paths[i]);
			if (expanded) {
				r_list_append (dirs_list, expanded);
			}
		}
	}

	// Iterate through all directories in the list
	RListIter *dir_it;
	char *path;
	r_list_foreach (dirs_list, dir_it, path) {
		RList *files = r_sys_dir (path);
		if (files) {
			RListIter *it;
			char *file;
			r_list_foreach (files, it, file) {
				if (!strcmp (file, ".") || !strcmp (file, "..")) {
					continue;
				}
				if (*file != '.' && r_str_endswith (file, ".r2ai.md")) {
					char *full_path = r_str_newf ("%s/%s", path, file);
					ParsedPrompt *pp = parse_r2ai_md (full_path);
					if (pp) {
						PromptSpec *spec = R_NEW (PromptSpec);
						spec->name = pp->name;
						spec->description = pp->description;
						spec->nargs = pp->args ? r_list_length (pp->args) : 0;
						spec->args = calloc (spec->nargs + 1, sizeof (PromptArg));
						int i = 0;
						RListIter *ait;
						ParsedArg *pa;
						r_list_foreach (pp->args, ait, pa) {
							spec->args[i].name = pa->name;
							spec->args[i].description = pa->description;
							spec->args[i].required = pa->required && !strcmp (pa->required, "true");
							i++;
						}
						spec->render = render_loaded;
						spec->render_data = pp;
						r_list_append (reg->list, spec);
					}
					free (full_path);
				}
			}
			r_list_free (files);
		}
	}
	r_list_free (dirs_list);
	ss->prompts = reg;
}

void prompts_registry_fini(ServerState *ss) {
	if (!ss || !ss->prompts) {
		return;
	}
	PromptRegistry *reg = (PromptRegistry *)ss->prompts;
	r_list_free (reg->list);
	free (reg);
	ss->prompts = NULL;
}

static PromptSpec *prompts_find(const ServerState *ss, const char *name) {
	if (!ss || !ss->prompts || !name) {
		return NULL;
	}
	PromptRegistry *reg = (PromptRegistry *)ss->prompts;
	RListIter *it;
	PromptSpec *p;
	r_list_foreach (reg->list, it, p) {
		if (!strcmp (p->name, name)) {
			return p;
		}
	}
	return NULL;
}

char *prompts_build_list_json(const ServerState *ss, const char *cursor, int page_size) {
	if (!ss || !ss->prompts) {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_k (pj, "prompts");
		pj_a (pj);
		pj_end (pj); // end array
		pj_end (pj); // end object
		return pj_drain (pj);
	}

	PromptRegistry *reg = (PromptRegistry *)ss->prompts;

	int start_index = 0;
	if (cursor) {
		start_index = atoi (cursor);
		if (start_index < 0) {
			start_index = 0;
		}
	}
	int total = r_list_length (reg->list);
	int end_index = start_index + page_size;
	if (end_index > total) {
		end_index = total;
	}

	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "prompts");
	pj_a (pj);

	RListIter *it;
	PromptSpec *p;
	int idx = 0;
	r_list_foreach (reg->list, it, p) {
		if (idx >= start_index && idx < end_index) {
			pj_o (pj);
			pj_ks (pj, "name", p->name);
			pj_ks (pj, "description", p->description? p->description: "");
			pj_k (pj, "arguments");
			pj_a (pj);
			for (int i = 0; i < p->nargs; i++) {
				pj_o (pj);
				pj_ks (pj, "name", p->args[i].name);
				pj_ks (pj, "description", p->args[i].description? p->args[i].description: "");
				pj_kb (pj, "required", p->args[i].required);
				pj_end (pj);
			}
			pj_end (pj); // end arguments array
			pj_end (pj); // end prompt object
		}
		idx++;
	}

	pj_end (pj); // end prompts array
	if (end_index < total) {
		char buf[32];
		snprintf (buf, sizeof (buf), "%d", end_index);
		pj_ks (pj, "nextCursor", buf);
	}
	pj_end (pj); // end root object
	return pj_drain (pj);
}

char *prompts_get_json(const ServerState *ss, const char *name, RJson *arguments) {
	PromptSpec *spec = prompts_find (ss, name);
	if (!spec) {
		return NULL;
	}
	return spec->render (spec, arguments);
}
