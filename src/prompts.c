/* r2mcp - MIT - Copyright 2025-2026 - pancake, dnakov */

#include "r2mcp.h"
#include "prompts.h"
#include "utils.inc.c"

typedef struct {
	char *name;
	char *desc;
	char *req;
} ParsedArg;

typedef struct {
	char *name;
	char *desc;
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
					if (R_STR_ISNOTEMPTY (val)) {
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

static char *render_loaded(const PromptSpec *spec, RJson *args) {
	ParsedPrompt *pp = (ParsedPrompt *)spec->render_data;
	char *user = NULL;
	if (pp->user_template) {
		user = expand_template (pp->user_template, args);
	}
	char *m1 = json_text_msg ("system", pp->content);
	char *m2 = user? json_text_msg ("user", user): NULL;
	RStrBuf *sb = r_strbuf_new ("{");
	r_strbuf_append (sb, "\"messages\":[");
	if (m1) {
		r_strbuf_append (sb, m1);
	}
	if (m2) {
		const char *comma = m1? ",": "";
		r_strbuf_appendf (sb, "%s%s", comma, m2);
	}
	r_strbuf_append (sb, "]}");
	free (m1);
	free (m2);
	free (user);
	return r_strbuf_drain (sb);
}

static PromptSpec *spec_from_prompt(ParsedPrompt *pp) {
	PromptSpec *spec = R_NEW (PromptSpec);
	spec->name = pp->name;
	spec->description = pp->desc;
	spec->nargs = pp->args? r_list_length (pp->args): 0;
	spec->args = calloc (spec->nargs + 1, sizeof (PromptArg));
	int i = 0;
	RListIter *it;
	ParsedArg *pa;
	r_list_foreach (pp->args, it, pa) {
		spec->args[i].name = pa->name;
		spec->args[i].description = pa->desc;
		spec->args[i].required = pa->req && !strcmp (pa->req, "true");
		i++;
	}
	spec->render = render_loaded;
	spec->render_data = pp;
	return spec;
}

static char *parse_args_block(char *line_ptr, ParsedPrompt *pp) {
	RList *args = r_list_newf (free);
	while (*line_ptr) {
		char *nl = strchr (line_ptr, '\n');
		if (!nl) {
			break;
		}
		*nl = '\0';
		r_str_trim (line_ptr);
		if (line_ptr[0] != '-') {
			pp->args = args;
			return line_ptr;
		}
		char *colon = strchr (line_ptr + 1, ':');
		if (colon) {
			*colon = 0;
			ParsedArg *arg = R_NEW0 (ParsedArg);
			char *key = r_str_trim_dup (line_ptr + 1);
			char *val = r_str_trim_dup (colon + 1);
			if (!strcmp (key, "name")) {
				arg->name = val;
			} else if (!strcmp (key, "description")) {
				arg->desc = val;
			} else if (!strcmp (key, "required")) {
				arg->req = val;
			} else {
				free (val);
			}
			free (key);
			if (arg->name) {
				r_list_append (args, arg);
			} else {
				free (arg);
			}
		}
		line_ptr = nl + 1;
	}
	pp->args = args;
	return line_ptr;
}

static char *parse_frontmatter_field(char *nl, char *line, ParsedPrompt *pp) {
	char *colon = strchr (line, ':');
	if (colon) {
		size_t keylen = colon - line;
		char *val = colon + 1;
		if (keylen == strlen ("description") && r_str_startswith (line, "description")) {
			pp->desc = strdup (val);
		} else if (keylen == strlen ("user_template") && r_str_startswith (line, "user_template")) {
			RStrBuf *sb = r_strbuf_new ("");
			char *p = nl + 1;
			while (*p) {
				char *next_nl = strchr (p, '\n');
				if (next_nl) {
					r_strbuf_append_n (sb, p, next_nl - p);
					r_strbuf_append (sb, "\n");
					p = next_nl + 1;
				} else {
					r_strbuf_append (sb, p);
					p += strlen (p);
				}
			}
			pp->user_template = r_strbuf_drain (sb);
			nl = p - 1;
		}
	}
	return nl + 1;
}

static ParsedPrompt *parse_r2ai_md(const char *path) {
	size_t sz;
	char *data = r_file_slurp (path, &sz);
	if (!data || sz < 4 || !r_str_startswith (data, "---\n")) {
		free (data);
		return NULL;
	}
	char *end = strstr (data + 4, "\n---\n");
	if (!end) {
		free (data);
		return NULL;
	}
	ParsedPrompt *pp = R_NEW0 (ParsedPrompt);
	pp->name = strdup (r_file_basename (path));
	char *dot = strstr (pp->name, ".r2ai.md");
	if (dot) {
		*dot = 0;
	}
	*end = 0;
	pp->content = r_str_trim_dup (end + 5);
	char *p = data + 4;
	while (*p) {
		char *nl = strchr (p, '\n');
		if (!nl) {
			break;
		}
		*nl = '\0';
		r_str_trim (p);
		if (!strcmp (p, "args:")) {
			p = parse_args_block (nl + 1, pp);
		} else {
			p = parse_frontmatter_field (nl, p, pp);
		}
	}
	free (data);
	return pp;
}

typedef struct {
	RList /*<PromptSpec*>*/ *lst;
} PromptRegistry;

void prompts_registry_init(ServerState *ss) {
	if (ss->prompts) {
		return;
	}
	PromptRegistry *reg = R_NEW0 (PromptRegistry);
	reg->lst = r_list_new ();
	if (!reg->lst) {
		free (reg);
		return;
	}
	RList *paths = r_list_newf (free);
	if (ss->prompts_dir) {
		RList *entries = r_str_split_duplist (ss->prompts_dir, ":", true);
		if (entries) {
			RListIter *it;
			char *e;
			r_list_foreach (entries, it, e) {
				char *exp = r_file_home (e);
				if (exp) {
					r_list_append (paths, exp);
				} else {
					r_list_append (paths, strdup (e));
				}
			}
			r_list_free (entries);
		}
	} else {
		r_list_append (paths, strdup ("prompts"));
		r_list_append (paths, r_file_home ("~/.config/r2ai/prompts"));
		r_list_append (paths, r_file_home ("~/.config/r2mcp/prompts"));
	}

	// Iterate through all directories and load prompt files
	char *path;
	RListIter *it;
	r_list_foreach (paths, it, path) {
		RList *files = r_sys_dir (path);
		if (files) {
			RListIter *fit;
			char *file;
			r_list_foreach (files, fit, file) {
				if (*file == '.' || !r_str_endswith (file, ".r2ai.md")) {
					continue;
				}
				char *full_path = r_str_newf ("%s/%s", path, file);
				ParsedPrompt *pp = parse_r2ai_md (full_path);
				if (pp) {
					PromptSpec *spec = spec_from_prompt (pp);
					r_list_append (reg->lst, spec);
				}
				free (full_path);
			}
			r_list_free (files);
		}
	}
	r_list_free (paths);
	ss->prompts = reg;
}

void prompts_registry_fini(ServerState *ss) {
	if (!ss || !ss->prompts) {
		return;
	}
	PromptRegistry *reg = (PromptRegistry *)ss->prompts;
	r_list_free (reg->lst);
	free (reg);
	ss->prompts = NULL;
}

static PromptSpec *prompts_find(const ServerState *ss, const char *nm) {
	if (!ss || !ss->prompts || !nm) {
		return NULL;
	}
	PromptRegistry *reg = (PromptRegistry *)ss->prompts;
	RListIter *it;
	PromptSpec *p;
	r_list_foreach (reg->lst, it, p) {
		if (!strcmp (p->name, nm)) {
			return p;
		}
	}
	return NULL;
}

char *prompts_build_list_json(const ServerState *ss, const char *cursor, int pagesz) {
	PromptRegistry *reg = (ss && ss->prompts)? (PromptRegistry *)ss->prompts: NULL;
	int total = 0;
	int eidx = 0;
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "prompts");
	pj_a (pj);
	if (reg) {
		int idx = 0;
		int total = r_list_length (reg->lst);
		int sidx = 0;
		if (cursor) {
			sidx = atoi (cursor);
			if (sidx < 0) {
				sidx = 0;
			}
		}
		eidx = sidx + pagesz;
		if (eidx > total) {
			eidx = total;
		}
		RListIter *it;
		PromptSpec *p;
		r_list_foreach (reg->lst, it, p) {
			if (idx >= sidx && idx < eidx) {
				pj_o (pj);
				pj_ks (pj, "name", p->name);
				pj_ks (pj, "description", p->description? p->description: "");
				pj_k (pj, "arguments");
				pj_a (pj);
				int i;
				for (i = 0; i < p->nargs; i++) {
					pj_o (pj);
					pj_ks (pj, "name", p->args[i].name);
					pj_ks (pj, "description", p->args[i].description? p->args[i].description: "");
					pj_kb (pj, "required", p->args[i].required);
					pj_end (pj);
				}
				pj_end (pj);
				pj_end (pj);
			}
			idx++;
		}
	}

	pj_end (pj); // end prompts array
	if (eidx < total) {
		char buf[32];
		snprintf (buf, sizeof (buf), "%d", eidx);
		pj_ks (pj, "nextCursor", buf);
	}
	pj_end (pj); // end root object
	return pj_drain (pj);
}

char *prompts_get_json(const ServerState *ss, const char *nm, RJson *args) {
	PromptSpec *spec = prompts_find (ss, nm);
	return spec? spec->render (spec, args): NULL;
}
