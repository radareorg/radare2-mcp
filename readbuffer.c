// --- readbuffer ---
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

// Modified read_buffer functions to handle partial reads better
char *read_buffer_get_message(ReadBuffer *buf) {
	// Search for a complete JSON-RPC message
	// We need to find a properly balanced set of braces {}
	if (buf->size == 0) {
		return NULL;
	}

	// Ensure the buffer is null-terminated for string operations
	if (buf->size < buf->capacity) {
		buf->data[buf->size] = '\0';
	} else {
		// Expand capacity if needed
		buf->capacity += 1;
		buf->data = realloc (buf->data, buf->capacity);
		buf->data[buf->size] = '\0';
	}

	// Look for a complete JSON message by counting braces
	int brace_count = 0;
	int start_pos = -1;
	size_t i;

	for (i = 0; i < buf->size; i++) {
		const char c = buf->data[i];

		// Find the first opening brace if we haven't already
		if (start_pos == -1 && c == '{') {
			start_pos = i;
			brace_count = 1;
			continue;
		}

		// Count braces within a JSON object
		if (start_pos != -1) {
			if (c == '{') {
				brace_count++;
			} else if (c == '}') {
				brace_count--;

				// If we've found a complete JSON object
				if (brace_count == 0) {
					// We have a complete message from start_pos to i (inclusive)
					size_t msg_len = i - start_pos + 1;
					char *msg = malloc (msg_len + 1);
					memcpy (msg, buf->data + start_pos, msg_len);
					msg[msg_len] = '\0';

					// Move any remaining data to the beginning of the buffer
					size_t remaining = buf->size - (i + 1);
					if (remaining > 0) {
						memmove (buf->data, buf->data + i + 1, remaining);
					}
					buf->size = remaining;

					// r2mcp_log ("Extracted complete JSON message");
					return msg;
				}
			}
		}
	}

	// If we get here, we don't have a complete message yet
	return NULL;
}

