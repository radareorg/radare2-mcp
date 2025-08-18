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
	bool minimode;
	/* When true, operate in HTTP r2pipe client mode and do NOT use r2 C APIs */
	bool http_mode;
	/* Base URL of the remote r2 webserver (if http_mode is true) */
	char *baseurl;
	const RJson *client_capabilities;
	const RJson *client_info;
	RadareState rstate;
	RStrBuf *sb;
} ServerState;
