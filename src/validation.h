/* r2mcp - MIT - Copyright 2025-2026 - pancake */
#ifndef VALIDATION_H
#define VALIDATION_H

#include <r_core.h>
#include "r2mcp.h"

/* Validation result - caller must free error_message if not NULL */
typedef struct {
	bool valid;
	char *error_message;
} ValidationResult;

ValidationResult validate_arguments(RJson *args, const char *schema_json);

/* Helper: Check if a required string parameter exists and is a string */
ValidationResult validate_required_string(RJson *args, const char *param_name);

/* Helper: Check if a required numeric parameter exists and is numeric */
ValidationResult validate_required_number(RJson *args, const char *param_name);

/* Helper: Check if a required boolean parameter exists and is a boolean */
ValidationResult validate_required_boolean(RJson *args, const char *param_name);

#endif
