/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include <r_types.h>
#include "readbuffer.h"

ReadBuffer *read_buffer_new(void) {
	ReadBuffer *buf = R_NEW (ReadBuffer);
	buf->data = malloc (BUFFER_SIZE);
	buf->size = 0;
	buf->capacity = BUFFER_SIZE;
	return buf;
}

void read_buffer_free(ReadBuffer *buf) {
	if (buf) {
		free (buf->data);
		free (buf);
	}
}

void read_buffer_append(ReadBuffer *buf, const char *data, size_t len) {
	if (buf->size + len > buf->capacity) {
		size_t new_capacity = buf->capacity * 2;
		if (new_capacity < buf->size + len) {
			new_capacity = buf->size + len;
		}
		char *new_data = realloc (buf->data, new_capacity);
		if (!new_data) {
			// R_LOG_ERROR ("Failed to resize buffer");
			return;
		}
		buf->data = new_data;
		buf->capacity = new_capacity;
	}
	memcpy (buf->data + buf->size, data, len);
	buf->size += len;
}

// Extract a complete JSON message from the buffer, respecting string quoting.
// Returns a heap-allocated message string or NULL if no complete message is available.
char *read_buffer_get_message(ReadBuffer *buf) {
	if (buf->size == 0) {
		return NULL;
	}

	// Ensure the buffer is null-terminated for safety
	if (buf->capacity <= buf->size + 1) {
		buf->capacity = buf->size + 2;
		buf->data = realloc (buf->data, buf->capacity);
	}
	buf->data[buf->size] = '\0';

	int brace_count = 0;
	int start_pos = -1;
	bool in_string = false;
	bool escape_next = false;
	size_t i;

	for (i = 0; i < buf->size; i++) {
		const char c = buf->data[i];

		// Handle escape sequences inside strings
		if (escape_next) {
			escape_next = false;
			continue;
		}

		if (in_string) {
			if (c == '\\') {
				escape_next = true;
			} else if (c == '"') {
				in_string = false;
			}
			continue;
		}

		// Outside of a string
		if (c == '"') {
			in_string = true;
			continue;
		}

		if (start_pos == -1) {
			if (c == '{') {
				start_pos = i;
				brace_count = 1;
			}
			continue;
		}

		if (c == '{') {
			brace_count++;
		} else if (c == '}') {
			brace_count--;
			if (brace_count == 0) {
				// Complete message from start_pos to i (inclusive)
				size_t msg_len = i - start_pos + 1;
				char *msg = malloc (msg_len + 1);
				memcpy (msg, buf->data + start_pos, msg_len);
				msg[msg_len] = '\0';

				// Shift remaining data to the front
				size_t remaining = buf->size - (i + 1);
				if (remaining > 0) {
					memmove (buf->data, buf->data + i + 1, remaining);
				}
				buf->size = remaining;
				return msg;
			}
		}
	}

	return NULL;
}
