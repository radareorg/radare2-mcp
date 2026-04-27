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

static const char *json_type_name(RJsonType type) {
	switch (type) {
	case R_JSON_NULL:
		return "null";
	case R_JSON_BOOLEAN:
		return "boolean";
	case R_JSON_INTEGER:
		return "integer";
	case R_JSON_DOUBLE:
		return "number";
	case R_JSON_STRING:
		return "string";
	case R_JSON_ARRAY:
		return "array";
	case R_JSON_OBJECT:
		return "object";
	default:
		return "unknown";
	}
}

static bool is_numeric_string(const RJson *field, bool integer_only) {
	if (!field || field->type != R_JSON_STRING || R_STR_ISEMPTY (field->str_value)) {
		return false;
	}
	const char *s = field->str_value;
	while (IS_WHITESPACE (*s)) {
		s++;
	}
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	char *end = NULL;
	if (integer_only) {
		(void)strtoll (s, &end, 0);
	} else {
		(void)strtod (s, &end);
	}
	if (end == s) {
		return false;
	}
	while (IS_WHITESPACE (*end)) {
		end++;
	}
	return !*end;
}

static bool json_matches_schema_type(const RJson *field, const char *expected_type) {
	if (!field || !expected_type) {
		return false;
	}
	if (!strcmp (expected_type, "string")) {
		return field->type == R_JSON_STRING;
	}
	if (!strcmp (expected_type, "boolean")) {
		return field->type == R_JSON_BOOLEAN;
	}
	if (!strcmp (expected_type, "integer")) {
		return field->type == R_JSON_INTEGER || is_numeric_string (field, true);
	}
	if (!strcmp (expected_type, "number")) {
		return field->type == R_JSON_INTEGER || field->type == R_JSON_DOUBLE || is_numeric_string (field, false);
	}
	if (!strcmp (expected_type, "object")) {
		return field->type == R_JSON_OBJECT;
	}
	if (!strcmp (expected_type, "array")) {
		return field->type == R_JSON_ARRAY;
	}
	if (!strcmp (expected_type, "null")) {
		return field->type == R_JSON_NULL;
	}
	return true;
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
		r_json_free (schema);
		free (schema_copy);
		return NULL;
	}

	RList *required = r_list_newf (free);
	const RJson *required_json = r_json_get (schema, "required");
	if (required_json && required_json->type == R_JSON_ARRAY) {
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

	/* Parse the schema once so we can validate required fields and types */
	char *schema_copy = strdup (schema_json);
	if (!schema_copy) {
		return (ValidationResult){ true, NULL };
	}
	RJson *schema = r_json_parse (schema_copy);
	if (!schema || schema->type != R_JSON_OBJECT) {
		r_json_free (schema);
		free (schema_copy);
		return (ValidationResult){ true, NULL };
	}

	/* Parse schema to get required properties */
	RList *required = parse_required_properties (schema_json);
	if (!required) {
		r_json_free (schema);
		free (schema_copy);
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
			r_json_free (schema);
			free (schema_copy);
			return (ValidationResult){ false, msg };
		}
	}

	const RJson *properties = r_json_get (schema, "properties");
	if (properties && properties->type == R_JSON_OBJECT && args && args->type == R_JSON_OBJECT) {
		const RJson *field = args->children.first;
		while (field) {
			const RJson *prop_schema = field->key? r_json_get (properties, field->key): NULL;
			const char *expected_type = prop_schema? r_json_get_str (prop_schema, "type"): NULL;
			if (expected_type && !json_matches_schema_type (field, expected_type)) {
				char *msg = r_str_newf ("Invalid parameter '%s': expected %s, got %s",
					field->key,
					expected_type,
					json_type_name (field->type));
				r_list_free (required);
				r_json_free (schema);
				free (schema_copy);
				return (ValidationResult){ false, msg };
			}
			field = field->next;
		}
	}

	r_list_free (required);
	r_json_free (schema);
	free (schema_copy);
	return (ValidationResult){ true, NULL };
}
