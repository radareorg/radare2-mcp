# RFC: Write memory

Status: Proposed. First milestone. See the [RFC index](README.md).

## Purpose

Add `write_memory` as the counterpart to [read_memory](read-memory.md).
Operate on the current r2 IO address space with the same type and format
interpretations. Filesystem paths are outside this interface.

## Interface

```text
write_memory(address, value, type?, format?, field?)
```

`address` is a required numeric expression. `type` and `format` have the
same meaning as in the reader and are mutually exclusive. With neither,
`value` is a raw hexadecimal string. With a layout, it is a scalar, an array
or an object containing field values. `field` optionally selects one nested
member or array element.

There is no separate `size`: the decoded bytes or selected values determine
the write extent.

```text
write_memory(address="0x4000", value="9090")
write_memory(address="obj.counter", type="uint32_t", value=42)
write_memory(address="obj.header", type="Header", field="flags", value=3)
write_memory(address="obj.header", type="Header", value={"length":128,"flags":3})
```

## Mutation rules

- Decode and validate the entire raw hex payload before writing. Reject
  malformed or incomplete pairs instead of accepting a partial payload.
- A scalar replaces the selected scalar; a field selection changes only
  that field or element.
- An object patches the supplied fields, preserving omitted fields and
  padding. An array must match the selected extent.
- Pointer values are addresses. Select pointed-to memory explicitly through
  `address`; assigning a pointer does not implicitly patch its pointee.
- Reject unknown fields, unsupported encodings and out-of-range values
  before the first write. Preserve exact large integers.
- Validate the full request before execution, but do not claim that native
  IO makes multiple field writes atomic. Report any ranges already applied
  when execution fails.

Successful responses identify the address and applied byte count or ranges,
plus updated field information where relevant. A plain `ok` cannot describe
a partial or failed operation.

## IO permissions and caches

`open_file` currently opens local files with `R_PERM_RX`. Direct file editing
needs an explicit writable-open option while retaining the existing default.

Honor active IO permissions and cache behavior. If neither the target nor
an active write cache accepts the operation, return an error. Do not
silently reopen a file, change permissions or commit caches. Distinguish
cached changes from target writes when the backend supplies that information.

Exclude the tool from read-only mode and enforce this during dispatch as
well as tool listing. Dedicated writes do not require enabling arbitrary
command execution.

## Implementation

Share address/range handling and IO access with the reader. Resolve layouts
through the native type and format machinery and encode using target
bitness, endianness, offsets and stride.

Several `pf` setters emit write commands. Verify their behavior before
wrapping them; do not assume they mutate an input buffer. Use or improve
native bounded field setters and encoding support. Missing layout or
encoding support belongs in r2, rather than a parallel C layout encoder in
r2mcp. Return a clear unsupported-operation error when a readable format
cannot yet be written.

Implement raw writes first, scalar and selected-field writes next, and
array/object patches afterward. Preserve seek, block size and configuration
on success and failure.

## Acceptance cases

- Read -> write -> read round trips for bytes and supported typed values.
- Malformed hex, address/size overflow and unsupported values rejected
  before mutation.
- Nested-field and array updates preserving adjacent bytes and padding.
- Both endiannesses, integer boundaries and target pointer widths.
- Read-only and writable mappings, active caches, failed writes and
  accurate partial-execution results.
- Content modes, unchanged session state and read-only dispatch rejection.
