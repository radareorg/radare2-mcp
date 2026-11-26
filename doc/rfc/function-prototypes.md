# RFC: Reuse function prototype tools

Status: Existing tools retained; integration work proposed.
See the [RFC index](README.md).

## Interfaces

```text
get_function_prototype(address)
set_function_prototype(address, prototype)
```

Keep these names and their function-signature responsibility. The existing
implementation uses the native `afs` operations. A prototype covers the
return type, function name and arguments; variable-specific annotations use
[set_type](set-type.md).

```text
define_types(code="struct Header { unsigned int length; unsigned short flags; };")
set_function_prototype(address="sym.parse", prototype="int parse(struct Header *header)")
get_function_prototype(address="sym.parse")
show_function_details(address="sym.parse", include_variables=true)
```

These are proposed workflow examples, not additional CLI or DSL syntax.

## Integration work

Use types registered through [define_types](define-types.md) and validate
declarations through native parsing where supported. Defining a function
type in the type database does not automatically apply it to an analyzed
function; applying a prototype remains an explicit action.

Resolve the target function before mutation. Preserve native signature
semantics and diagnose parser or application failures. Read back the applied
signature instead of treating an empty setter response as proof of success.
Avoid creating a parallel function-type registry in r2mcp.

Function details and variable type editing should reflect native signature
updates where argument recovery supports them. Local-slot type changes
must not accidentally replace an entire function prototype. Do not promise
identical type propagation from every decompiler backend.

Keep the getter in read-only mode and exclude the setter. Preserve existing
response compatibility while adding structured result information where
needed by the editing workflow.

## Acceptance cases

- Round-trip return types and arguments, including newly defined compound
  and pointer types.
- Native-supported function-pointer and variadic signatures.
- Invalid declarations and missing functions without unintended mutation.
- Consistency with function details and variable annotations, unchanged
  seek, content modes and read-only dispatch.
