# RFC: Function details and variable discovery

Status: Proposed extension. Second milestone. See the [RFC index](README.md).

## Purpose

Extend `show_function_details` to expose the variables an agent can rename
or annotate. Reuse this existing discovery tool instead of adding separate
function-by-name, function-by-address and variable-list tools.

The existing tool accepts an address expression, selects the containing
function and defaults to the current seek when the address is omitted. It
already supports structured function details with native JSON fallbacks.

## Interface

```text
show_function_details(address?, include_variables?)
```

`include_variables` defaults to false so existing calls retain their current
cost and response scope. When true, include the native arguments and local
variables within the selected function's details.

```text
show_function_details(address="sym.parse", include_variables=true)
show_function_details(address="sym.parse + 4", include_variables=true)
show_function_details(include_variables=true)
```

For each variable, expose the native name, type, argument/local role and
storage identity: a register, base-pointer slot or stack-pointer slot with
its offset. Include size, parameter position and register-home relationships
when provided by the native context. Preserve distinctions between variables
and storage slots instead of guessing that similarly named entries are the
same variable.

These are analysis descriptions. They do not imply that the variable has a
currently readable runtime address or value.

## Implementation

Retain the existing `functions` response envelope, named attributes and
address/current-seek behavior. Add variable details within the relevant
function entry using the native function context when available, with
`afvj` or equivalent supported APIs as a fallback.

Do not require a new ABI for existing builds merely to retain the basic
function-details tool. Clearly distinguish unavailable variable information
from a function with no recovered variables. Keep native diagnostics
separate from the structured result.

The returned names and identities must be usable by
[rename_variable](rename-variable.md) and [set_type](set-type.md). Reading
details does not run analysis, recover missing variables implicitly or
change the current seek. A missing function follows the existing empty-result
behavior without fabricating a function from a nearby flag.

Keep the action available in read-only mode and preserve all existing
content modes. Text and structured views must describe the same function.

## Acceptance cases

- Lookup by function name, start address, interior address and current seek.
- Register arguments and stack/BP locals, including types and slot offsets.
- Native context and older fallback output, including missing information.
- Renaming and typing a discovered variable followed by refreshed details.
- Existing named attributes and response shape preserved when the new
  option is omitted; content-mode and seek-preservation regressions.
