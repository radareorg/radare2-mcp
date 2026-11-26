# RFC: Define types

Status: Proposed. First milestone. See the [RFC index](README.md).

## Purpose

Add `define_types` so agents can introduce related C declarations without
enabling raw commands. Structures, unions, enums, typedefs and function
declarations feed r2's existing type database and the c2 -> `pf` workflow.

This operation defines types. [set_type](set-type.md) separately applies an
annotation, and [write_memory](write-memory.md) separately changes bytes.

## Interface

```text
define_types(code)
```

`code` is required C declaration text and may contain multiple declarations.
Use the current session's target configuration rather than the host ABI.

```text
define_types(code="typedef unsigned int Word; struct Header { Word length; unsigned short flags; };")
```

Return the declared or updated type names and parser diagnostics, respecting
the existing content modes. Preserve native redefinition semantics and
report which definitions changed; do not maintain a second type registry.

## Implementation

Use `r_anal_cparse` and the current native parser path, which supplies c2
parsing by default, then save the parsed declarations through native type
storage. Keep semicolons, braces and declaration text out of command-string
interpolation when a local parser API is available.

Parse and validate before importing results. A failed batch must not leave
the successful prefix registered. Preserve line/type diagnostics and
distinguish failure from a successful empty result. Verify native parser
behavior before relying on this property.

Support only declarations the native parser can represent. Forward
declarations and function pointers should follow its capabilities. Diagnose
unsupported constructs, including bitfields where unavailable, rather than
inventing a layout. Verify alignment, packing and pointer sizes through the
same native machinery used for memory reads.

Defining a function type does not automatically apply it to an analyzed
function. Keep [set_function_prototype](function-prototypes.md) for that
operation. Definitions live in the current session; persistence follows
existing project/session facilities.

Exclude this mutating action from read-only mode. Advertise remote support
only when the remote parser and diagnostic path are tested. Preserve the
supported-header build policy instead of adding a parser dependency.

## Acceptance cases

- Multiple related declarations, typedef chains, enums, unions and nesting.
- Native-supported forward declarations, function pointers and redefinitions.
- Malformed and unsupported declarations with useful diagnostics and no
  partial import.
- Layout discovery through [list_types](list-types.md), followed by typed
  memory reading; include padded layouts and both pointer widths.
- Session isolation, content modes and read-only dispatch rejection.
