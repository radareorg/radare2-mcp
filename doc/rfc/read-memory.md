# RFC: Read memory

Status: Proposed. First milestone. See the [RFC index](README.md).

## Purpose

Add one `read_memory` action for bytes, scalars, strings, arrays and
structures. The current `hexdump` tool already reads memory through `px`;
this proposal exposes the other native representations without requiring
`run_command` and `-r`.

## Interface

```text
read_memory(address, size?, type?, format?, field?, view?)
```

| Parameter | Meaning |
| --- | --- |
| `address` | Required expression in the current r2 IO space. |
| `size` | Positive byte count or numeric expression for a raw read. |
| `type` | C type resolved through r2's type database. |
| `format` | Inline `pf` layout, or an existing named format using `.name`. |
| `field` | Optional field or array-element path within the layout. |
| `view` | Text presentation: initially `hex`, `hexdump` or `values`. |

`type` and `format` are mutually exclusive. Omitting both selects raw bytes
and requires `size`. Typed and formatted reads derive their extent from the
layout; initially reject `size` combined with a layout. `field` requires a
layout. Unknown types, formats and fields produce errors.

Raw reads default to compact hex; interpreted reads default to values.
`view` controls text presentation. The existing `-C` content mode separately
selects text, JSON, structured or combined output. A hexdump view leaves the
underlying structured result unchanged.

## Examples

These are proposed tool calls, not additional CLI or DSL syntax.

```text
read_memory(address="0x4000", size=32)
read_memory(address="0x4000", size=32, view="hexdump")
read_memory(address="obj.header", type="Header")
read_memory(address="obj.header", type="Header", field="flags")
read_memory(address="0x4000", format="N4N2 length flags")
read_memory(address="0x4000", format=".pe_image_file_header")
```

## Implementation

Resolve addresses through existing expression validation. Compute and
validate the required extent, including overflow checks, before reading.
Read that span rather than relying on the current block size.

```text
C type -> r_type_format -> pf decoder -> existing MCP content modes
pf format -------------------^
```

Reuse the native type database and format registry. Preserve `pf`'s field
names, offsets, types, values, arrays, enum labels and pointer metadata.
Add only response metadata identifying the address, layout and read extent;
do not create a second decoded-layout model.

Honor target bitness, endianness, member offsets, padding and array stride.
Bound byte counts, arrays, strings, pointer traversal and output size.
Report unreadable ranges and incomplete reads without presenting fabricated
or zero-filled bytes as successful memory reads. Preserve seek, block size
and configuration, including on errors. A read must not define a format,
assign a field or create a type link.

Use the existing mode-aware response helpers and diagnostics handling.
Keep the reader reusable by [write verification](write-memory.md) and the
compatibility wrapper below.

## Hexdump compatibility

Keep `hexdump` callable as a wrapper around the shared reader with
`view="hexdump"`. Preserve its text behavior and its current block-size
default when `size` is omitted; the new raw reader still requires `size`.

Once the general reader is established, remove `hexdump` from the default
catalog while retaining explicit compatibility access. Verify this against
the current tool-selection and dispatch rules before changing visibility.

## Acceptance cases

- Raw bytes, invalid addresses, overflow, map boundaries and incomplete reads.
- Scalars, large integers, floats and bounded strings.
- Both endiannesses and 32-bit and 64-bit pointer layouts.
- Padded/packed and nested structures, unions and array stride where the
  native parser and decoder support them.
- Named formats, C types and selected nested fields or array elements.
- Every content mode, unchanged session state, read-only mode and the
  `hexdump` wrapper, including omitted size.
