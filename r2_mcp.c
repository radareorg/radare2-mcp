#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_print.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>

static const char *r_json_get_str(const RJson *json, const char *key) {
    if (!json || !key) {
        return NULL;
    }
    
    const RJson *field = r_json_get(json, key);
    if (!field || field->type != R_JSON_STRING) {
        return NULL;
    }
    
    return field->str_value;
}

#define PORT 3000
#define BUFFER_SIZE 65536
#define READ_CHUNK_SIZE 4096

#define LATEST_PROTOCOL_VERSION "2024-11-05"

typedef struct {
    const char *name;
    const char *version;
} ServerInfo;

typedef struct {
    bool logging;
    bool resources;
    bool tools;
} ServerCapabilities;

typedef struct {
    ServerInfo info;
    ServerCapabilities capabilities;
    const char *instructions;
    bool initialized;
    RJson *client_capabilities;
    RJson *client_info;
} ServerState;

static RCore *r_core = NULL;
static bool file_opened = false;
static char current_file[1024] = {0};
static volatile sig_atomic_t running = 1;
static bool is_direct_mode = false;
static ServerState server_state = {
    .info = {
        .name = "Radare2 MCP Connector",
        .version = "1.0.0"
    },
    .capabilities = {
        .logging = true,
        .resources = true,
        .tools = true
    },
    .instructions = "Use this server to analyze binaries with radare2",
    .initialized = false,
    .client_capabilities = NULL,
    .client_info = NULL
};

// Forward declarations
static void process_mcp_message(const char *msg);
static void direct_mode_loop(void);

#define JSON_RPC_VERSION "2.0"
#define MCP_VERSION "2024-11-05"

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} ReadBuffer;

ReadBuffer* read_buffer_new() {
    ReadBuffer *buf = malloc(sizeof(ReadBuffer));
    buf->data = malloc(BUFFER_SIZE);
    buf->size = 0;
    buf->capacity = BUFFER_SIZE;
    return buf;
}

void read_buffer_append(ReadBuffer *buf, const char *data, size_t len) {
    if (buf->size + len > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            fprintf(stderr, "Failed to resize buffer\n");
            return;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
}

char* read_buffer_get_message(ReadBuffer *buf) {
    char *newline = memchr(buf->data, '\n', buf->size);
    if (!newline) return NULL;
    
    size_t msg_len = newline - buf->data;
    char *msg = malloc(msg_len + 1);
    memcpy(msg, buf->data, msg_len);
    msg[msg_len] = '\0';
    
    size_t remaining = buf->size - (msg_len + 1);
    if (remaining > 0) {
        memmove(buf->data, newline + 1, remaining);
    }
    buf->size = remaining;
    
    return msg;
}

void read_buffer_free(ReadBuffer *buf) {
    free(buf->data);
    free(buf);
}

static char *get_capabilities();
static char *handle_initialize(RJson *params);
static char *handle_list_resources(RJson *params);
static char *handle_list_resource_templates(RJson *params);
static char *handle_list_tools(RJson *params);
static char *handle_get_resource(RJson *params);
static char *handle_call_tool(RJson *params);
static char *format_string(const char *format, ...);
static char *format_string(const char *format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    return strdup(buffer);
}

static bool init_r2(void) {
    r_core = r_core_new();
    if (!r_core) {
        fprintf(stderr, "Failed to initialize radare2 core\n");
        return false;
    }
    
    r_config_set_i(r_core->config, "scr.color", 0);
    
    printf("Radare2 core initialized\n");
    return true;
}

void cleanup_r2() {
    if (r_core) {
        r_core_free(r_core);
        r_core = NULL;
        file_opened = false;
        memset(current_file, 0, sizeof(current_file));
    }
}

bool r2_open_file(const char *filepath) {
    fprintf(stderr, "Attempting to open file: %s\n", filepath);
    
    if (!r_core && !init_r2()) {
        fprintf(stderr, "Failed to initialize r2 core\n");
        return false;
    }
    
    if (file_opened) {
        fprintf(stderr, "Closing previously opened file: %s\n", current_file);
        r_core_cmd0(r_core, "o-*");
        file_opened = false;
        memset(current_file, 0, sizeof(current_file));
    }
    
    r_core_cmd0(r_core, "e bin.relocs.apply=true");
    r_core_cmd0(r_core, "e bin.cache=true");
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "o %s", filepath);
    fprintf(stderr, "Running r2 command: %s\n", cmd);
    
    char *result = r_core_cmd_str(r_core, cmd);
    bool success = (result && strlen(result) > 0);
    free(result);
    
    if (!success) {
        fprintf(stderr, "Trying alternative method to open file...\n");
        RIODesc *fd = r_core_file_open(r_core, filepath, R_PERM_R, 0);
        if (fd) {
            r_core_bin_load(r_core, filepath, 0);
            fprintf(stderr, "File opened using r_core_file_open\n");
            success = true;
        } else {
            fprintf(stderr, "Failed to open file: %s\n", filepath);
            return false;
        }
    }
    
    fprintf(stderr, "Loading binary information\n");
    r_core_cmd0(r_core, "ob");
    
    strncpy(current_file, filepath, sizeof(current_file) - 1);
    file_opened = true;
    fprintf(stderr, "File opened successfully: %s\n", filepath);
    
    return true;
}

char *r2_cmd(const char *cmd) {
    if (!r_core || !file_opened) {
        return strdup("Error: No file is open");
    }
    return r_core_cmd_str(r_core, cmd);
}

bool r2_analyze(const char *level) {
    if (!r_core || !file_opened) return false;
    
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "%s", level);
    r_core_cmd0(r_core, cmd);
    return true;
}

static void signal_handler(int signum) {
    const char msg[] = "\nInterrupt received, shutting down...\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    
    running = 0;
    
    signal(signum, SIG_DFL);
}

static bool check_client_capability(const char *capability) {
    if (!server_state.client_capabilities) return false;
    RJson *cap = (RJson *)r_json_get(server_state.client_capabilities, capability);
    return cap != NULL;
}

static bool check_server_capability(const char *capability) {
    if (!strcmp(capability, "logging")) return server_state.capabilities.logging;
    if (!strcmp(capability, "resources")) return server_state.capabilities.resources;
    if (!strcmp(capability, "tools")) return server_state.capabilities.tools;
    return false;
}

static bool assert_capability_for_method(const char *method, char **error) {
    if (!strcmp(method, "sampling/createMessage")) {
        if (!check_client_capability("sampling")) {
            *error = strdup("Client does not support sampling");
            return false;
        }
    } else if (!strcmp(method, "roots/list")) {
        if (!check_client_capability("roots")) {
            *error = strdup("Client does not support listing roots");
            return false;
        }
    }
    return true;
}

static bool assert_request_handler_capability(const char *method, char **error) {
    if (!strcmp(method, "sampling/createMessage")) {
        if (!check_server_capability("sampling")) {
            *error = strdup("Server does not support sampling");
            return false;
        }
    } else if (!strcmp(method, "logging/setLevel")) {
        if (!check_server_capability("logging")) {
            *error = strdup("Server does not support logging");
            return false;
        }
    } else if (!strncmp(method, "prompts/", 8)) {
        if (!check_server_capability("prompts")) {
            *error = strdup("Server does not support prompts");
            return false;
        }
    } else if (!strncmp(method, "resources/", 10)) {
        if (!check_server_capability("resources")) {
            *error = strdup("Server does not support resources");
            return false;
        }
    } else if (!strncmp(method, "tools/", 6)) {
        if (!check_server_capability("tools")) {
            *error = strdup("Server does not support tools");
            return false;
        }
    }
    return true;
}

static char *handle_mcp_request(const char *method, RJson *params, const char *id) {
    char *error = NULL;
    char *result = NULL;

    if (!assert_capability_for_method(method, &error) || !assert_request_handler_capability(method, &error)) {
        PJ *pj = pj_new();
        pj_o(pj);
        pj_ks(pj, "jsonrpc", "2.0");
        if (id) pj_ks(pj, "id", id);
        pj_k(pj, "error");
        pj_o(pj);
        pj_ki(pj, "code", -32601);
        pj_ks(pj, "message", error);
        pj_end(pj);
        pj_end(pj);
        free(error);
        return pj_drain(pj);
    }

    if (!strcmp(method, "initialize")) {
        result = handle_initialize(params);
    } else if (!strcmp(method, "ping")) {
        result = strdup("{}");
    } else if (!strcmp(method, "resources/templates/list")) {
        result = handle_list_resource_templates(params);
    } else if (!strcmp(method, "resources/list")) {
        result = handle_list_resources(params);
    } else if (!strcmp(method, "resources/read")) {
        result = handle_get_resource(params);
    } else if (!strcmp(method, "resources/subscribe")) {
        PJ *pj = pj_new();
        pj_o(pj);
        pj_ki(pj, "code", -32601);
        pj_ks(pj, "message", "Method not implemented: subscriptions are not supported");
        pj_end(pj);
        error = pj_drain(pj);
    } else if (!strcmp(method, "tools/list")) {
        result = handle_list_tools(params);
    } else if (!strcmp(method, "tools/call")) {
        result = handle_call_tool(params);
    } else {
        error = strdup("Unknown method");
    }

    PJ *pj = pj_new();
    pj_o(pj);
    pj_ks(pj, "jsonrpc", "2.0");
    if (id) pj_ks(pj, "id", id);

    if (error) {
        pj_k(pj, "error");
        pj_o(pj);
        pj_ki(pj, "code", -32601);
        pj_ks(pj, "message", error);
        pj_end(pj);
        free(error);
    } else {
        pj_k(pj, "result");
        if (result) {
            pj_raw(pj, result);
            free(result);
        } else {
            pj_null(pj);
        }
    }

    pj_end(pj);
    return pj_drain(pj);
}

static char *handle_initialize(RJson *params) {
    if (server_state.client_capabilities) r_json_free(server_state.client_capabilities);
    if (server_state.client_info) r_json_free(server_state.client_info);
    
    server_state.client_capabilities = (RJson *)r_json_get(params, "capabilities");
    server_state.client_info = (RJson *)r_json_get(params, "clientInfo");
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_ks(pj, "protocolVersion", LATEST_PROTOCOL_VERSION);
    pj_k(pj, "serverInfo");
    pj_o(pj);
    pj_ks(pj, "name", server_state.info.name);
    pj_ks(pj, "version", server_state.info.version);
    pj_end(pj);
    pj_k(pj, "capabilities");
    pj_raw(pj, get_capabilities());
    if (server_state.instructions) {
        pj_ks(pj, "instructions", server_state.instructions);
    }
    pj_end(pj);
    
    server_state.initialized = true;
    return pj_drain(pj);
}

static char *get_capabilities() {
    PJ *pj = pj_new();
    pj_o(pj);
    
    pj_k(pj, "resources");
    pj_o(pj);
    pj_kb(pj, "subscribe", true);
    pj_end(pj);
    
    pj_k(pj, "tools");
    pj_o(pj);
    pj_kb(pj, "listChanged", true);
    pj_end(pj);
    
    pj_end(pj);
    return pj_drain(pj);
}

static char *handle_list_resources(RJson *params) {
    // Add pagination support
    const char *cursor = r_json_get_str(params, "cursor");
    int page_size = 10; // Default page size
    int start_index = 0;
    
    // Parse cursor if provided
    if (cursor) {
        start_index = atoi(cursor);
        if (start_index < 0) start_index = 0;
    }
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_k(pj, "resources");
    pj_a(pj);
    
    // Define our resources
    const char *resources[][4] = {
        {"r2://currentFile", "Current File Info", "Get information about the currently open file", "application/json"},
        {"r2://functions", "Functions", "List functions in the binary", "application/json"},
        {"r2://imports", "Imports", "List imports in the binary", "application/json"},
        {"r2://exports", "Exports", "List exports in the binary", "application/json"},
        {"r2://strings", "Strings", "Get strings from the binary", "application/json"},
        // Add more resources here
    };
    
    int total_resources = sizeof(resources) / sizeof(resources[0]);
    int end_index = start_index + page_size;
    if (end_index > total_resources) end_index = total_resources;
    
    // Add resources for this page
    for (int i = start_index; i < end_index; i++) {
        pj_o(pj);
        pj_ks(pj, "uri", resources[i][0]);
        pj_ks(pj, "name", resources[i][1]);
        pj_ks(pj, "description", resources[i][2]);
        pj_ks(pj, "mimeType", resources[i][3]);
        pj_end(pj);
    }
    
    pj_end(pj); // End resources array
    
    // Add nextCursor if there are more resources
    if (end_index < total_resources) {
        char next_cursor[16];
        snprintf(next_cursor, sizeof(next_cursor), "%d", end_index);
        pj_ks(pj, "nextCursor", next_cursor);
    }
    
    pj_end(pj);
    return pj_drain(pj);
}

static char *handle_list_tools(RJson *params) {
    // Add pagination support
    const char *cursor = r_json_get_str(params, "cursor");
    int page_size = 10; // Default page size
    int start_index = 0;
    
    // Parse cursor if provided
    if (cursor) {
        start_index = atoi(cursor);
        if (start_index < 0) start_index = 0;
    }
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_k(pj, "tools");
    pj_a(pj);
    
    // Define our tools with their descriptions and schemas
    // Format: {name, description, schema_definition}
    const char *tools[][3] = {
        {
            "openFile", 
            "Open a file for analysis", 
            "{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"filePath\"]}"
        },
        {
            "closeFile", 
            "Close the currently open file", 
            "{\"type\":\"object\",\"properties\":{}}"
        },
        {
            "runCommand", 
            "Run a radare2 command and get the output", 
            "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"Command to execute\"}},\"required\":[\"command\"]}"
        },
        {
            "analyze", 
            "Run analysis on the current file", 
            "{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"string\",\"description\":\"Analysis level (a, aa, aaa, aaaa)\"}},\"required\":[]}"
        },
        {
            "disassemble", 
            "Disassemble instructions at a given address", 
            "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"numInstructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble\"}},\"required\":[\"address\"]}"
        }
    };
    
    int total_tools = sizeof(tools) / sizeof(tools[0]);
    int end_index = start_index + page_size;
    if (end_index > total_tools) end_index = total_tools;
    
    // Add tools for this page
    for (int i = start_index; i < end_index; i++) {
        pj_o(pj);
        pj_ks(pj, "name", tools[i][0]);
        pj_ks(pj, "description", tools[i][1]);
        pj_k(pj, "inputSchema");
        pj_raw(pj, tools[i][2]);
        pj_end(pj);
    }
    
    pj_end(pj); // End tools array
    
    // Add nextCursor if there are more tools
    if (end_index < total_tools) {
        char next_cursor[16];
        snprintf(next_cursor, sizeof(next_cursor), "%d", end_index);
        pj_ks(pj, "nextCursor", next_cursor);
    }
    
    pj_end(pj);
    return pj_drain(pj);
}

static char *handle_get_resource(RJson *params) {
    const char *uri = r_json_get_str(params, "uri");
    
    if (!uri) {
        PJ *pj = pj_new();
        pj_o(pj);
        pj_ki(pj, "code", -32602);
        pj_ks(pj, "message", "Missing required parameter: uri");
        pj_k(pj, "data");
        pj_o(pj);
        pj_k(pj, "uri");
        pj_null(pj);
        pj_end(pj);
        pj_end(pj);
        return pj_drain(pj);
    }
    
    if (!file_opened && strcmp(uri, "r2://currentFile")) {
        PJ *pj = pj_new();
        pj_o(pj);
        pj_ki(pj, "code", -32002);
        pj_ks(pj, "message", "No file is currently open");
        pj_k(pj, "data");
        pj_o(pj);
        pj_ks(pj, "uri", uri);
        pj_end(pj);
        pj_end(pj);
        return pj_drain(pj);
    }
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_k(pj, "contents");
    pj_a(pj);
    pj_o(pj);
    pj_ks(pj, "uri", uri);
    pj_ks(pj, "mimeType", "application/json");
    
    if (!strncmp(uri, "r2://", 5)) {
        const char *resource = uri + 5;
        
        if (!strcmp(resource, "currentFile")) {
            PJ *file_pj = pj_new();
            pj_o(file_pj);
            if (!file_opened) {
                pj_kb(file_pj, "opened", false);
                pj_ks(file_pj, "message", "No file is currently open");
            } else {
                pj_kb(file_pj, "opened", true);
                pj_ks(file_pj, "filePath", current_file);
                char *info_str = r2_cmd("ij");
                if (info_str) {
                    pj_k(file_pj, "info");
                    pj_raw(file_pj, info_str);
                    free(info_str);
                }
            }
            pj_end(file_pj);
            char *file_json = pj_drain(file_pj);
            pj_ks(pj, "text", file_json);
            free(file_json);
        } else if (!strcmp(resource, "functions")) {
            char *func_str = r2_cmd("aflj");
            pj_ks(pj, "text", func_str ? func_str : "[]");
            free(func_str);
        } else if (!strcmp(resource, "imports")) {
            char *imports_str = r2_cmd("iij");
            pj_ks(pj, "text", imports_str ? imports_str : "[]");
            free(imports_str);
        } else if (!strcmp(resource, "exports")) {
            char *exports_str = r2_cmd("iEj");
            pj_ks(pj, "text", exports_str ? exports_str : "[]");
            free(exports_str);
        } else if (!strcmp(resource, "strings")) {
            char *strings_str = r2_cmd("izj");
            pj_ks(pj, "text", strings_str ? strings_str : "[]");
            free(strings_str);
        } else {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32002);
            pj_ks(err_pj, "message", "Resource not found");
            pj_k(err_pj, "data");
            pj_o(err_pj);
            pj_ks(err_pj, "uri", uri);
            pj_end(err_pj);
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
    } else if (!strncmp(uri, "file:///", 8)) {
        const char *filepath = uri + 7;
        FILE *file = fopen(filepath, "rb");
        if (!file) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32002);
            pj_ks(err_pj, "message", "Resource not found");
            pj_k(err_pj, "data");
            pj_o(err_pj);
            pj_ks(err_pj, "uri", uri);
            pj_end(err_pj);
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        char *buffer = malloc(size + 1);
        if (!buffer) {
            fclose(file);
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32603);
            pj_ks(err_pj, "message", "Internal server error");
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        size_t read_size = fread(buffer, 1, size, file);
        fclose(file);
        buffer[read_size] = '\0';
        
        pj_ks(pj, "text", buffer);
        const char *ext = strrchr(filepath, '.');
        if (ext) {
            if (!strcmp(ext, ".rs")) {
                pj_ks(pj, "mimeType", "text/x-rust");
            } else if (!strcmp(ext, ".c") || !strcmp(ext, ".h")) {
                pj_ks(pj, "mimeType", "text/x-c");
            } else if (!strcmp(ext, ".cpp") || !strcmp(ext, ".hpp")) {
                pj_ks(pj, "mimeType", "text/x-c++");
            } else {
                pj_ks(pj, "mimeType", "text/plain");
            }
        } else {
            pj_ks(pj, "mimeType", "text/plain");
        }
        
        free(buffer);
    } else {
        pj_end(pj);
        pj_end(pj);
        pj_end(pj);
        free(pj);
        
        PJ *err_pj = pj_new();
        pj_o(err_pj);
        pj_ki(err_pj, "code", -32002);
        pj_ks(err_pj, "message", "Unknown URI scheme");
        pj_k(err_pj, "data");
        pj_o(err_pj);
        pj_ks(err_pj, "uri", uri);
        pj_end(err_pj);
        pj_end(err_pj);
        return pj_drain(err_pj);
    }
    
    pj_end(pj);
    pj_end(pj);
    pj_end(pj);
    return pj_drain(pj);
}

static char *handle_call_tool(RJson *params) {
    const char *tool_name = r_json_get_str(params, "name");
    
    if (!tool_name) {
        PJ *pj = pj_new();
        pj_o(pj);
        pj_ki(pj, "code", -32602);
        pj_ks(pj, "message", "Missing required parameter: name");
        pj_end(pj);
        return pj_drain(pj);
    }
    
    RJson *tool_args = (RJson *)r_json_get(params, "arguments");
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_k(pj, "content");
    pj_a(pj);
    pj_o(pj);
    pj_ks(pj, "type", "text");
    
    if (!strcmp(tool_name, "openFile")) {
        const char *filepath = r_json_get_str(tool_args, "filePath");
        if (!filepath) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32602);
            pj_ks(err_pj, "message", "Missing required parameter: filePath");
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        bool success = r2_open_file(filepath);
        pj_ks(pj, "text", success ? "File opened successfully." : "Failed to open file.");
        pj_end(pj);
        pj_end(pj);
        if (!success) pj_kb(pj, "isError", true);
        pj_end(pj);
        return pj_drain(pj);
    }
    
    if (!strcmp(tool_name, "closeFile")) {
        if (!file_opened) {
            pj_ks(pj, "text", "No file was open.");
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            return pj_drain(pj);
        }
        
        char filepath_copy[1024];
        strncpy(filepath_copy, current_file, sizeof(filepath_copy) - 1);
        if (r_core) {
            r_core_cmd0(r_core, "o-*");
            file_opened = false;
            memset(current_file, 0, sizeof(current_file));
        }
        
        pj_ks(pj, "text", "File closed successfully.");
        pj_end(pj);
        pj_end(pj);
        pj_end(pj);
        return pj_drain(pj);
    }
    
    if (!strcmp(tool_name, "runCommand")) {
        if (!file_opened) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_k(err_pj, "content");
            pj_a(err_pj);
            pj_o(err_pj);
            pj_ks(err_pj, "type", "text");
            pj_ks(err_pj, "text", "No file is currently open. Please open a file first.");
            pj_end(err_pj);
            pj_end(err_pj);
            pj_kb(err_pj, "isError", true);
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        const char *command = r_json_get_str(tool_args, "command");
        if (!command) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32602);
            pj_ks(err_pj, "message", "Missing required parameter: command");
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        char *result = r2_cmd(command);
        pj_ks(pj, "text", result);
        pj_end(pj);
        pj_end(pj);
        pj_end(pj);
        free(result);
        return pj_drain(pj);
    }
    
    if (!strcmp(tool_name, "analyze")) {
        if (!file_opened) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_k(err_pj, "content");
            pj_a(err_pj);
            pj_o(err_pj);
            pj_ks(err_pj, "type", "text");
            pj_ks(err_pj, "text", "No file is currently open. Please open a file first.");
            pj_end(err_pj);
            pj_end(err_pj);
            pj_kb(err_pj, "isError", true);
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        const char *level = r_json_get_str(tool_args, "level");
        if (!level) level = "aaa";
        
        r2_analyze(level);
        char *result = r2_cmd("afl");
        char *text = format_string("Analysis completed with level %s.\n\n%s", level, result);
        pj_ks(pj, "text", text);
        pj_end(pj);
        pj_end(pj);
        pj_end(pj);
        free(result);
        free(text);
        return pj_drain(pj);
    }
    
    if (!strcmp(tool_name, "disassemble")) {
        if (!file_opened) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_k(err_pj, "content");
            pj_a(err_pj);
            pj_o(err_pj);
            pj_ks(err_pj, "type", "text");
            pj_ks(err_pj, "text", "No file is currently open. Please open a file first.");
            pj_end(err_pj);
            pj_end(err_pj);
            pj_kb(err_pj, "isError", true);
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        const char *address = r_json_get_str(tool_args, "address");
        if (!address) {
            pj_end(pj);
            pj_end(pj);
            pj_end(pj);
            free(pj);
            
            PJ *err_pj = pj_new();
            pj_o(err_pj);
            pj_ki(err_pj, "code", -32602);
            pj_ks(err_pj, "message", "Missing required parameter: address");
            pj_end(err_pj);
            return pj_drain(err_pj);
        }
        
        // Use const_cast pattern
        RJson *num_instr_json = (RJson *)r_json_get(tool_args, "numInstructions");
        int num_instructions = 10;
        if (num_instr_json && num_instr_json->type == R_JSON_INTEGER) {
            num_instructions = (int)num_instr_json->num.u_value;
        }
        
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "pd %d @ %s", num_instructions, address);
        char *disasm = r2_cmd(cmd);
        pj_ks(pj, "text", disasm);
        pj_end(pj);
        pj_end(pj);
        pj_end(pj);
        free(disasm);
        return pj_drain(pj);
    }
    
    pj_end(pj);
    pj_end(pj);
    pj_end(pj);
    free(pj);
    
    PJ *err_pj = pj_new();
    pj_o(err_pj);
    pj_ki(err_pj, "code", -32602);
    pj_ks(err_pj, "message", format_string("Unknown tool: %s", tool_name));
    pj_end(err_pj);
    char *err_str = pj_drain(err_pj);
    free((char *)err_str); // Free the formatted string
    return err_str;
}

static char *handle_list_resource_templates(RJson *params) {
    (void)params;
    
    PJ *pj = pj_new();
    pj_o(pj);
    pj_k(pj, "resourceTemplates");
    pj_a(pj);
    
    pj_o(pj);
    pj_ks(pj, "uriTemplate", "file:///{path}");
    pj_ks(pj, "name", "File Access");
    pj_ks(pj, "description", "Access file contents");
    pj_ks(pj, "mimeType", "application/octet-stream");
    pj_end(pj);
    
    pj_end(pj);
    pj_end(pj);
    return pj_drain(pj);
}

// Added back the direct_mode_loop implementation
static void process_mcp_message(const char *msg) {
    RJson *request = r_json_parse((char *)msg);
    if (!request) {
        fprintf(stderr, "Invalid JSON\n");
        return;
    }
    
    const char *method = r_json_get_str(request, "method");
    RJson *params = (RJson *)r_json_get(request, "params");
    RJson *id_json = (RJson *)r_json_get(request, "id");
    
    if (!method) {
        fprintf(stderr, "Invalid JSON-RPC message: missing method\n");
        r_json_free(request);
        return;
    }
    
    if (id_json) {
        const char *id = NULL;
        char id_buf[32] = {0};
        if (id_json->type == R_JSON_STRING) {
            id = id_json->str_value;
        } else if (id_json->type == R_JSON_INTEGER) {
            snprintf(id_buf, sizeof(id_buf), "%lld", (long long)id_json->num.u_value);
            id = id_buf;
        }
        
        char *response = handle_mcp_request(method, params, id);
        printf("%s\n", response);
        fflush(stdout);
        free(response);
    } else {
        // We don't handle notifications anymore
        fprintf(stderr, "Ignoring notification: %s\n", method);
    }
    
    r_json_free(request);
}

static void direct_mode_loop(void) {
    fprintf(stderr, "Running in MCP direct mode (stdin/stdout)\n");
    
    ReadBuffer *buffer = read_buffer_new();
    char chunk[READ_CHUNK_SIZE];
    
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    struct timeval tv;
    fd_set readfds;
    
    while (running) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "Select error: %s\n", strerror(errno));
                break;
            }
            continue;
        }
        
        if (ret == 0) {
            if (write(STDOUT_FILENO, "", 0) < 0) {
                fprintf(stderr, "Client disconnected (stdout closed)\n");
                break;
            }
            continue;
        }
        
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            ssize_t bytes_read = read(STDIN_FILENO, chunk, READ_CHUNK_SIZE);
            
            if (bytes_read > 0) {
                read_buffer_append(buffer, chunk, bytes_read);
                char *msg;
                while ((msg = read_buffer_get_message(buffer)) != NULL) {
                    process_mcp_message(msg);
                    free(msg);
                }
            } else if (bytes_read == 0) {
                fprintf(stderr, "End of input stream\n");
                break;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    fprintf(stderr, "Error reading from stdin: %s\n", strerror(errno));
                    break;
                }
            }
        }
    }
    
    read_buffer_free(buffer);
    fprintf(stderr, "Direct mode loop terminated\n");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    
    signal(SIGPIPE, SIG_IGN);

    
    if (!init_r2()) {
        fprintf(stderr, "Failed to initialize radare2\n");
        return 1;
    }
    
    if (!isatty(STDIN_FILENO)) {
        is_direct_mode = true;
        direct_mode_loop();
        cleanup_r2();
        fprintf(stderr, "MCP direct mode terminated gracefully\n");
        return 0;
    }
    
    cleanup_r2();
    return 0;
}