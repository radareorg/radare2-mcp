#ifndef R2MCP_READBUFFER_H
#define R2MCP_READBUFFER_H 1

#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE     65536
typedef struct {
	char *data;
	size_t size;
	size_t capacity;
} ReadBuffer;

ReadBuffer *read_buffer_new(void);
void read_buffer_free(ReadBuffer *buf);
void read_buffer_append(ReadBuffer *buf, const char *data, size_t len);

#endif
