#include "readbuffer.h"

typedef struct {
	const char *name;
	const char *version;
} ServerInfo;

typedef struct {
	bool logging;
	bool tools;
} ServerCapabilities;

typedef struct {
	RCore *core;
	bool file_opened;
	char *current_file;
} RadareState;

typedef struct {
	ServerInfo info;
	ServerCapabilities capabilities;
	const char *instructions;
	bool initialized;
	const RJson *client_capabilities;
	const RJson *client_info;
	RadareState rstate;
	RStrBuf *sb;
} ServerState;
