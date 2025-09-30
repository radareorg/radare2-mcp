#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * Execute: curl -sS -d "<msg>" <url>
 * Capture stdout (HTTP response body) and return it as a malloc'd NUL-terminated string.
 *
 * @param url  Target URL (non-NULL)
 * @param msg  Message for -d (non-NULL), e.g. "key=value" or JSON string
 * @param exit_code_out Optional: receives curl's exit code (0 on success). Pass NULL if not needed.
 *
 * @return malloc'd buffer with the response (caller must free), or NULL on error.
 *         On error, *exit_code_out (if provided) is set to a negative number when possible.
 */
char *curl_post_capture(const char *url, const char *msg, int *exit_code_out) {
	if (exit_code_out) *exit_code_out = -1;
	if (!url || !msg) { errno = EINVAL; return NULL; }

	int pipefd[2];
	if (pipe (pipefd) == -1) {
		return NULL;
	}

	pid_t pid = fork ();
	if (pid == -1) {
		int e = errno;
		close (pipefd[0]);
		close (pipefd[1]);
		errno = e;
		return NULL;
	}

	if (pid == 0) {
		// Child: stdout -> pipe write end
		// stderr unchanged (so errors still show on parent stderr because of -sS)
		if (dup2 (pipefd[1], STDOUT_FILENO) == -1) {
			_exit (127);
		}

		close (pipefd[0]);
		close (pipefd[1]);

		// Build argv; no shell is involved (safe for spaces/quotes in msg/url).
		// Note: if msg starts with '@', curl treats it as a file. If that's unwanted,
		// use "--data-raw" instead of "-d".
		char *const argv[] = {
			"curl",
			"-sS",
			"-d", (char *)msg,
			(char *)url,
			NULL
		};

		execvp ("curl", argv);
		// If exec fails:
		_exit (127);
	}

	// Parent
	close (pipefd[1]); // we read from pipefd[0]

	// Read child's stdout fully into a dynamic buffer
	size_t cap = 8192, len = 0;
	char *buf = malloc (cap);
	if (!buf) {
		close (pipefd[0]);
		// Reap child to avoid a zombie
		int st;
		waitpid (pid, &st, 0);
		return NULL;
	}

	for (;;) {
		if (len + 4096 + 1 > cap) {
			size_t ncap = cap * 2;
			char *tmp = realloc (buf, ncap);
			if (!tmp) {
				free (buf);
				buf = NULL;
				break;
			}
			buf = tmp; cap = ncap;
		}
		ssize_t n = read (pipefd[0], buf + len, 4096);
		if (n > 0) {
			len += (size_t)n;
		} else if (n == 0) {
			break; // EOF
		} else if (errno != EINTR) {
			free (buf); buf = NULL; // read error
			break;
		}
	}

	close (pipefd[0]);

	// Reap curl
	int status = 0, rc = -1;
	if (waitpid (pid, &status, 0) != -1) {
		if (WIFEXITED (status)) {
			rc = WEXITSTATUS (status);
		} else if (WIFSIGNALED (status)) {
			rc = 128 + WTERMSIG (status);
		}
	}

	if (exit_code_out) {
		*exit_code_out = rc;
	}

	if (!buf) {
		return NULL;
	}

	// NUL-terminate (even if empty)
	buf[len] = '\0';
	return buf;
}
