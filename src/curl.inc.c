/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(R2__WINDOWS__)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#elif defined(R2__UNIX__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#else
#error please define R2__WINDOWS__ or R2__UNIX__ for platform detection
#endif

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
	if (exit_code_out) {
		*exit_code_out = -1;
	}
	if (!url || !msg) {
		errno = EINVAL;
		return NULL;
	}
	char *buf = NULL;
	size_t len = 0;
	int exit_code = -1;
#if R2__WINDOWS__
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof (SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	HANDLE read_h = NULL, write_h = NULL;
	if (!CreatePipe (&read_h, &write_h, &sa, 0)) {
		return NULL;
	}
	// Ensure the read handle is not inherited
	SetHandleInformation (read_h, HANDLE_FLAG_INHERIT, 0);

	char *escaped_msg = r_str_escape_sh (msg);
	char *escaped_url = r_str_escape_sh (url);
	char *cmd = r_str_newf ("curl -sS -d \"%s\" \"%s\"", escaped_msg, escaped_url);
	free (escaped_msg);
	free (escaped_url);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory (&si, sizeof (si));
	si.cb = sizeof (si);
	si.hStdOutput = write_h;
	si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;

	ZeroMemory (&pi, sizeof (pi));

	// Create process
	BOOL ok = CreateProcessA (NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	free (cmd);
	// Close the write handle in parent after creating the child
	CloseHandle (write_h);

	if (!ok) {
		CloseHandle (read_h);
		return NULL;
	}

	// Read child's stdout
	size_t cap = 8192;
	buf = malloc (cap);
	if (!buf) {
		CloseHandle (read_h);
		CloseHandle (pi.hProcess);
		CloseHandle (pi.hThread);
		WaitForSingleObject (pi.hProcess, INFINITE);
		return NULL;
	}

	for (;;) {
		if (len + 4096 + 1 > cap) {
			size_t ncap = cap * 2;
			char *tmp = realloc (buf, ncap);
			if (!tmp) {
				R_FREE (buf);
				break;
			}
			buf = tmp;
			cap = ncap;
		}
		DWORD nread = 0;
		BOOL r = ReadFile (read_h, buf + len, 4096, &nread, NULL);
		if (r && nread > 0) {
			len += (size_t)nread;
			continue;
		}
		if (!r) {
			DWORD err = GetLastError ();
			if (err == ERROR_BROKEN_PIPE) {
				break; // EOF
			}
			R_FREE (buf);
			break;
		}
		// r == TRUE but nread == 0 -> EOF
		break;
	}

	CloseHandle (read_h);

	// Wait for process and get exit code
	WaitForSingleObject (pi.hProcess, INFINITE);
	DWORD exitcode = 0;
	if (!GetExitCodeProcess (pi.hProcess, &exitcode)) {
		exitcode = (DWORD)-1;
	}
	exit_code = (int)exitcode;
	CloseHandle (pi.hProcess);
	CloseHandle (pi.hThread);
#elif R2__UNIX__
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
	size_t cap = 8192;
	buf = malloc (cap);
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
				R_FREE (buf);
				break;
			}
			buf = tmp;
			cap = ncap;
		}
		ssize_t n = read (pipefd[0], buf + len, 4096);
		if (n > 0) {
			len += (size_t)n;
		} else if (n == 0) {
			break; // EOF
		} else if (errno != EINTR) {
			free (buf);
			buf = NULL; // read error
			break;
		}
	}
	close (pipefd[0]);
	// Reap curl
	int status = 0;
	if (waitpid (pid, &status, 0) != -1) {
		if (WIFEXITED (status)) {
			exit_code = WEXITSTATUS (status);
		} else if (WIFSIGNALED (status)) {
			exit_code = 128 + WTERMSIG (status);
		}
	}
#else
#error unsupported platform for curl_post_capture
#endif
	if (exit_code_out) {
		*exit_code_out = exit_code;
	}
	if (!buf) {
		return NULL;
	}
	// NUL-terminate (even if empty)
	buf[len] = '\0';
	return buf;
}
