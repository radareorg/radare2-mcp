#pragma once

#include "r2mcp.h"

/* A single client session — one independent RadareState identified by an
 * opaque X-Session-ID string. */
typedef struct r2mcp_session_t {
	char *id;
	RadareState rstate;
	ut64 last_used; /* r_time_now_mono() value */
} R2McpSession;

/* Bounded LRU registry of sessions. Single-threaded use only. */
struct r2mcp_sessions_t {
	RList *list;      /* R2McpSession*, head = most recently used */
	int max;          /* hard cap; oldest evicted on overflow. 0 = unbounded */
	int idle_timeout; /* seconds; 0 = never expire */
};

typedef struct r2mcp_sessions_t R2McpSessions;

/* Lifecycle */
R2McpSessions *r2mcp_sessions_new(int max, int idle_timeout);
void r2mcp_sessions_free(R2McpSessions *s);

/* Find an existing session by id or create a new one. On overflow the
 * least-recently-used session is evicted. Touches last_used and moves the
 * entry to head. Returns NULL on allocation failure. */
R2McpSession *r2mcp_sessions_acquire(R2McpSessions *s, const char *id);

/* Drop sessions whose last_used is older than idle_timeout. */
void r2mcp_sessions_sweep(R2McpSessions *s);
