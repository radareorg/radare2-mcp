/* r2mcp - MIT - Copyright 2025 - pancake */

#if R2_VERSION_NUMBER < 50909
#include <r_core.h>
#include <r_util/r_json.h>

st64 r_json_get_num(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, 0);
	const RJson *field = r_json_get (json, key);
	if (field) {
		switch (field->type) {
		case R_JSON_STRING:
			return r_num_get (NULL, field->str_value);
		case R_JSON_INTEGER:
			return field->num.s_value;
		case R_JSON_BOOLEAN:
			return field->num.u_value;
		case R_JSON_DOUBLE:
			return (int)field->num.dbl_value;
		default:
			break;
		}
	}
	return 0;
}

const char *r_json_get_str(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, NULL);
	const RJson *field = r_json_get (json, key);
	if (!field || field->type != R_JSON_STRING) {
		return NULL;
	}
	return field->str_value;
}
#endif
