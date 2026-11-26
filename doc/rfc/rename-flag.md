# RFC: Clarify flag renaming

Status: Proposed correction to an existing tool. Second milestone.
See the [RFC index](README.md).

## Purpose

Keep `rename_flag` as the action for existing flags, including labels on
global data. Correct the description that currently claims local-variable
support. Recovered arguments and locals use
[rename_variable](rename-variable.md).

## Existing interface

```text
rename_flag(address, name, new_name)
```

Preserve the existing required parameters for compatibility. `name` selects
the flag to rename; the current `fr` implementation does not make `address`
a function-local namespace. Document that distinction explicitly.

```text
rename_flag(address="obj.header", name="obj.header", new_name="packet_header")
```

## Implementation

Retain native flag and flagspace semantics. Resolve the exact flag, validate
the new name, perform the rename and verify its result. Report missing flags
and collisions accurately instead of returning an unconditional `ok` after
an empty command response.

Preserve the flag's address, size and other metadata. Other aliases at the
same address remain separate flags. Renaming a flag does not rename a
function variable or rewrite a binary's symbol table. Keep `rename_function`
for analysis function names and its associated native behavior.

Exclude mutation in read-only mode. Keep content modes and current seek
consistent with the rest of the proposed editing tools.

## Acceptance cases

- Rename a global data flag and resolve its new name at the same address.
- Preserve size, flagspace, aliases and unrelated variable/function names.
- Missing flags, invalid names and native collision behavior.
- Result read-back, unchanged seek and read-only rejection.
