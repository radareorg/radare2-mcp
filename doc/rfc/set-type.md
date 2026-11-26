# RFC: Set a type

Status: Proposed. Second milestone. See the [RFC index](README.md).

## Purpose

Use one `set_type` action for address-linked data and function variables.
This follows r2's type-link and variable concepts without separate local
and global type tools.

## Interface

```text
set_type(address, type, variable?)
```

`address` and `type` are required. With no `variable`, link the type to data
at that IO address. With `variable`, the address selects the containing
function and the name selects one of its existing arguments or locals.

```text
set_type(address="obj.header", type="Header")
set_type(address="sym.parse", variable="header", type="Header *")
```

The operation changes analysis metadata, not memory bytes. An explicit
`type` on `read_memory` or `write_memory` remains a temporary interpretation
and does not create this annotation.

## Implementation

Validate type names or expressions through native type machinery, including
pointer expressions and supported typedefs. Unknown or invalid types are
errors; creating definitions belongs to [define_types](define-types.md).

For address annotations, reuse native type links (`tl`/type-link APIs).
For variables, resolve the function and existing variable first, then use
native variable type operations (`afvt` or the corresponding API).

Do not create a missing function or variable, select a nearest flag as a
substitute, or report success without verifying the resulting metadata.
Return the resolved address/function, selected variable where applicable,
and previous and resulting type information.

Preserve seek, memory contents and unrelated annotations. Exclude the action
from read-only mode. Type propagation into decompiled output depends on the
backend; verify the native annotation and do not promise identical output
from every decompiler. Function return/argument prototypes continue to use
the existing [prototype tools](function-prototypes.md).

## Acceptance cases

- Address links to primitive and compound types, replacing an existing link.
- Argument/local types, pointers and typedefs discovered through function
  details.
- Missing functions/variables and invalid types rejected without mutation.
- Read-back through native metadata and typed memory reads.
- Unchanged bytes, seek and unrelated annotations; read-only rejection and
  all supported content modes.
