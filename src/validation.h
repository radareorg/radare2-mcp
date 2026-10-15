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

/* Evaluate numeric input with r2 semantics; callers serialize the result. */
bool parse_math_expression(RNum *num, const char *expression, ut64 *out_value);
ValidationResult validate_arguments(RJson *args, const char *schema_json, RNum *num);

#endif
