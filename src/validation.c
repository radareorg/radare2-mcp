/* r2mcp - MIT - Copyright 2025-2026 - pancake */

#include "validation.h"
#include "jsonrpc.h"

/* Check if a parameter exists and is a string */
ValidationResult validate_required_string(RJson *args, const char *param_name) {
	const RJson *field = r_json_get (args, param_name);
	if (!field || field->type != R_JSON_STRING) {
		char *msg = r_str_newf ("Missing required parameter '%s' (expected string)", param_name);
		return (ValidationResult){ false, msg };
	}
	return (ValidationResult){ true, NULL };
}

/* Check if a parameter exists and is numeric (integer or double) */
ValidationResult validate_required_number(RJson *args, const char *param_name) {
	const RJson *field = r_json_get (args, param_name);
	if (!field || (field->type != R_JSON_INTEGER && field->type != R_JSON_DOUBLE)) {
		char *msg = r_str_newf ("Missing required parameter '%s' (expected number)", param_name);
		return (ValidationResult){ false, msg };
	}
	return (ValidationResult){ true, NULL };
}

/* Check if a parameter exists and is a boolean */
ValidationResult validate_required_boolean(RJson *args, const char *param_name) {
	const RJson *field = r_json_get (args, param_name);
	if (!field || field->type != R_JSON_BOOLEAN) {
		char *msg = r_str_newf ("Missing required parameter '%s' (expected boolean)", param_name);
		return (ValidationResult){ false, msg };
	}
	return (ValidationResult){ true, NULL };
}

/* Check if a parameter exists with any valid type */
ValidationResult validate_required_param(RJson *args, const char *param_name) {
	const RJson *field = r_json_get (args, param_name);
	if (!field) {
		char *msg = r_str_newf ("Missing required parameter '%s'", param_name);
		return (ValidationResult){ false, msg };
	}
	return (ValidationResult){ true, NULL };
}

/* Parse JSON Schema to extract required properties */
static RList *parse_required_properties(const char *schema_json) {
	if (!schema_json || !*schema_json) {
		return NULL;
	}
	
	/* We need a non-modifiable copy for parsing */
	char *schema_copy = strdup (schema_json);
	if (!schema_copy) {
		return NULL;
	}
	
	RJson *schema = r_json_parse (schema_copy);
	if (!schema || schema->type != R_JSON_OBJECT) {
		free (schema_copy);
		return NULL;
	}
	
	RList *required = NULL;
	const RJson *required_json = r_json_get (schema, "required");
	if (required_json && required_json->type == R_JSON_ARRAY) {
		required = r_list_newf (free);
		const RJson *item = required_json->children.first;
		while (item) {
			if (item->type == R_JSON_STRING && item->str_value) {
				r_list_append (required, strdup (item->str_value));
			}
			item = item->next;
		}
	}
	
	r_json_free (schema);
	free (schema_copy);
	return required;
}

/* Validate arguments against JSON Schema */
ValidationResult validate_arguments(RJson *args, const char *schema_json) {
	if (!schema_json || !*schema_json) {
		/* No schema defined - allow all arguments */
		return (ValidationResult){ true, NULL };
	}
	
	/* Parse schema to get required properties */
	RList *required = parse_required_properties (schema_json);
	if (!required) {
		/* Schema couldn't be parsed - allow all arguments */
		return (ValidationResult){ true, NULL };
	}
	
	/* Check each required parameter exists */
	RListIter *it;
	const char *param;
	r_list_foreach (required, it, param) {
		const RJson *field = r_json_get (args, param);
		if (!field) {
			char *msg = r_str_newf ("Missing required parameter '%s'", param);
			r_list_free (required);
			return (ValidationResult){ false, msg };
		}
	}
	
	r_list_free (required);
	return (ValidationResult){ true, NULL };
}
