/* r2mcp - MIT - Copyright 2025-2026 - pancake */

#include "validation.h"
#include "jsonrpc.h"

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

/* Older r2 releases accept empty or partially parsed 0x literals. */
static bool validate_hex_literals(const char *expression) {
	const char *p = expression;
	while (*p) {
		const char *token = p;
		const char *extra = isdigit ((ut8)*p)? "_:.": "_.$?:\\";
		while (*p && (isalnum ((ut8)*p) || strchr (extra, *p))) {
			p++;
		}
		if (p - token >= 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
			const char *digit = token + 2;
			/* Leave r2's relative 0xf.. / 0xff.. notation to its parser. */
			if (!r_str_startswith (token, "0xf..") && !r_str_startswith (token, "0xF..") &&
				!r_str_startswith (token, "0xff..") && !r_str_startswith (token, "0xFF..")) {
				if (!isxdigit ((ut8)*digit)) {
					return false;
				}
				while (digit < p && (isxdigit ((ut8)*digit) || *digit == '_')) {
					digit++;
				}
				if (digit < p && (*digit == 'u' || *digit == 'U')) {
					digit++;
				}
				if (digit != p) {
					return false;
				}
			}
		}
		if (p == token) {
			p++;
		}
	}
	return true;
}

bool parse_math_expression(RNum *num, const char *expression, ut64 *out_value) {
	if (!expression || R_STR_ISEMPTY (r_str_trim_head_ro (expression))) {
		return false;
	}
	if (!validate_hex_literals (expression)) {
		return false;
	}
	RNum local_num = {0};
	if (!num) {
		num = &local_num;
	}
	const char *error = NULL;
	ut64 value = r_num_math_err (num, expression, &error);
	if (error || r_num_failed (num) || num->dbz) {
		return false;
	}
	*out_value = value;
	return true;
}

static bool is_numeric_string(RNum *num, const RJson *field) {
	if (!field || field->type != R_JSON_STRING) {
		return false;
	}
	ut64 value;
	return parse_math_expression (num, field->str_value, &value);
}

static bool is_boolean_string(const RJson *field) {
	if (!field || field->type != R_JSON_STRING || R_STR_ISEMPTY (field->str_value)) {
		return false;
	}
	return r_str_is_bool (field->str_value);
}

static bool json_matches_schema_type(RNum *num, const RJson *field, const char *expected_type) {
	if (!field || !expected_type) {
		return false;
	}
	if (!strcmp (expected_type, "string")) {
		return field->type == R_JSON_STRING;
	}
	if (!strcmp (expected_type, "boolean")) {
		if (field->type == R_JSON_BOOLEAN || is_boolean_string (field)) {
			return true;
		}
		if (field->type == R_JSON_INTEGER && (field->num.s_value == 0 || field->num.s_value == 1)) {
			return true;
		}
		return false;
	}
	if (!strcmp (expected_type, "integer")) {
		return field->type == R_JSON_INTEGER || is_numeric_string (num, field);
	}
	if (!strcmp (expected_type, "number")) {
		return field->type == R_JSON_INTEGER || field->type == R_JSON_DOUBLE || is_numeric_string (num, field);
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

/* Validate arguments against JSON Schema */
ValidationResult validate_arguments(RJson *args, const char *schema_json, RNum *num) {
	if (R_STR_ISEMPTY (schema_json)) {
		/* No schema defined - allow all arguments */
		return (ValidationResult){ true, NULL };
	}

	RJson *schema = r_json_parsedup (schema_json);
	if (!schema || schema->type != R_JSON_OBJECT) {
		r_json_free (schema);
		return (ValidationResult){ true, NULL };
	}

	const RJson *required = r_json_get (schema, "required");
	if (required && required->type == R_JSON_ARRAY) {
		const RJson *item;
		for (item = required->children.first; item; item = item->next) {
			if (item->type == R_JSON_STRING && item->str_value && !r_json_get (args, item->str_value)) {
				char *msg = r_str_newf ("Missing required parameter '%s'", item->str_value);
				r_json_free (schema);
				return (ValidationResult){ false, msg };
			}
		}
	}

	const RJson *properties = r_json_get (schema, "properties");
	if (properties && properties->type == R_JSON_OBJECT && args && args->type == R_JSON_OBJECT) {
		const RJson *field = args->children.first;
		while (field) {
			const RJson *prop_schema = field->key? r_json_get (properties, field->key): NULL;
			const char *expected_type = prop_schema? r_json_get_str (prop_schema, "type"): NULL;
			if (expected_type && !json_matches_schema_type (num, field, expected_type)) {
				char *msg = r_str_newf ("Invalid parameter '%s': expected %s, got %s",
					field->key,
					expected_type,
					json_type_name (field->type));
				r_json_free (schema);
				return (ValidationResult){ false, msg };
			}
			field = field->next;
		}
	}

	r_json_free (schema);
	return (ValidationResult){ true, NULL };
}
