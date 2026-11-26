# RFC: Targeted function analysis

Status: Proposed extension; later milestone. See the [RFC index](README.md).

## Purpose

Extend `analyze` to create or recover a function at a selected address.
This supports functions missed in stripped binaries and firmware while
reusing the existing analysis action.

## Interface

```text
analyze(level?, timeout_seconds?, address?)
```

Omitting `address` retains current whole-file analysis behavior and its
level/cache semantics. Supplying an address selects targeted function
analysis using native analysis facilities. Native analysis determines the
function boundaries; the initial proposal adds no manual range editor.

```text
analyze(address="0x401200")
show_function_details(address="0x401200", include_variables=true)
```

## Implementation

Validate the address and honor the existing per-call timeout behavior.
Bypass the whole-file already-analyzed shortcut for targeted requests.
A targeted operation must not mark the entire file analyzed at a new level
or reset unrelated functions and annotations.

Return the resulting function address and analysis outcome, including
diagnostics or an explicit failure to create/recover a function. Preserve
the current seek and retain the existing read-only exclusion.

Specify and test how the existing `level` affects a targeted request before
exposing it; do not silently run whole-file passes for an address-scoped call.

## Function removal

Removing a mistaken function was also discussed. Keep it deferred as a
separate explicit action, provisionally `remove_function(address)`, if a
concrete correction workflow warrants it. Do not overload `analyze` with a
delete flag. Native removal would delete analysis metadata, not memory bytes;
its effects on blocks, variables, flags and references need their own
verified contract before implementation.

## Acceptance cases

- Create/recover a missed function at a selected address.
- Targeted requests still execute after whole-file analysis was cached.
- Whole-file calls preserve their existing skip behavior.
- Timeout/error reporting, unchanged unrelated metadata and seek, and no
  false advancement of whole-file analysis level.
