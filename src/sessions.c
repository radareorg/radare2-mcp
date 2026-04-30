/* r2mcp - MIT - Copyright 2026 - pancake */

#include "sessions.h"
#include <r_util.h>

static void session_free(void *p) {
	R2McpSession *sess = (R2McpSession *)p;
	if (!sess) {
		return;
	}
	r2mcp_rstate_fini (&sess->rstate);
	free (sess->id);
	free (sess);
}

R2McpSessions *r2mcp_sessions_new(int max, int idle_timeout) {
	R2McpSessions *s = R_NEW0 (R2McpSessions);
	if (!s) {
		return NULL;
	}
	s->list = r_list_newf (session_free);
	s->max = R_MAX (0, max);
	s->idle_timeout = R_MAX (0, idle_timeout);
	return s;
}

void r2mcp_sessions_free(R2McpSessions *s) {
	if (!s) {
		return;
	}
	r_list_free (s->list);
	free (s);
}

static R2McpSession *find(R2McpSessions *s, const char *id) {
	RListIter *it;
	R2McpSession *sess;
	r_list_foreach (s->list, it, sess) {
		if (!strcmp (sess->id, id)) {
			return sess;
		}
	}
	return NULL;
}

void r2mcp_sessions_sweep(R2McpSessions *s) {
	if (!s || s->idle_timeout <= 0) {
		return;
	}
	const ut64 now = r_time_now_mono ();
	const ut64 max_age_us = (ut64)s->idle_timeout * 1000000ULL;
	RListIter *it, *tmp;
	R2McpSession *sess;
	r_list_foreach_safe (s->list, it, tmp, sess) {
		if (now - sess->last_used > max_age_us) {
			R_LOG_INFO ("r2mcp: evicting idle session '%s'", sess->id);
			r_list_delete (s->list, it);
		}
	}
}

R2McpSession *r2mcp_sessions_acquire(R2McpSessions *s, const char *id) {
	if (!s || !id) {
		return NULL;
	}
	R2McpSession *sess = find (s, id);
	if (sess) {
		/* Move to head (MRU). r_list_delete_data would invoke the list's
		 * free callback and destroy the session, so detach the callback
		 * across the splice. */
		RListFree fr = s->list->free;
		s->list->free = NULL;
		r_list_delete_data (s->list, sess);
		s->list->free = fr;
		r_list_prepend (s->list, sess);
		sess->last_used = r_time_now_mono ();
		return sess;
	}
	/* Evict LRU if at cap */
	if (s->max > 0 && r_list_length (s->list) >= s->max) {
		RListIter *tail = r_list_tail (s->list);
		if (tail) {
			R2McpSession *victim = (R2McpSession *)tail->data;
			R_LOG_INFO ("r2mcp: evicting LRU session '%s' (cap=%d)", victim->id, s->max);
			r_list_delete (s->list, tail);
		}
	}
	sess = R_NEW0 (R2McpSession);
	if (!sess) {
		return NULL;
	}
	sess->id = strdup (id);
	sess->rstate.analyze_level = -1;
	if (!r2mcp_rstate_init (&sess->rstate)) {
		free (sess->id);
		free (sess);
		return NULL;
	}
	sess->last_used = r_time_now_mono ();
	r_list_prepend (s->list, sess);
	R_LOG_INFO ("r2mcp: created session '%s'", id);
	return sess;
}
