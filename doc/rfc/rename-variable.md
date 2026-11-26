# RFC: Rename a function variable

Status: Proposed. Second milestone. See the [RFC index](README.md).

## Purpose

Add `rename_variable` for function arguments and locals. Keep
`rename_function` for functions and [rename_flag](rename-flag.md) for flags,
including global data labels.

The current `rename_flag` executes `fr`. It does not rename recovered
function variables despite its current description. Function variables need
the native `afvn` operation or corresponding API.

## Interface

```text
rename_variable(address, name, new_name)
```

All arguments are required. `address` is an expression selecting the
containing function. `name` is the exact native name obtained from
[show_function_details](function-details.md), and `new_name` is its new name.

```text
show_function_details(address="sym.parse", include_variables=true)
rename_variable(address="sym.parse", name="var_10h", new_name="header")
set_type(address="sym.parse", variable="header", type="Header *")
```

The same action covers arguments and locals; it does not accept a global
scope or guess between flags and function variables.

## Implementation

Resolve the function and variable before mutation. Validate the proposed
name using native constraints and detect collisions or ambiguity. Missing
functions, missing variables and conflicting names are errors with no rename.

Use `afvn` or the corresponding native variable API. If calling a command,
respect its native new-name/old-name ordering and prevent argument text
from becoming a second operation.

Verify the resulting variable identity and return the function address,
previous and new names, type and storage information. Preserve its type,
location, access metadata, other functions' variables and current seek.
Do not infer success solely from an empty command response.

Exclude from read-only mode. Decompiler presentation can vary; the required
result is the verified native rename, visible in refreshed function details.

## Acceptance cases

- Rename discovered register arguments and stack/BP locals.
- Select the function through a name, start address or interior address.
- Same variable name in different functions remains function-scoped.
- Invalid names, missing variables, collisions and ambiguous selection.
- Type/storage preservation, result read-back, content modes and read-only
  rejection.
