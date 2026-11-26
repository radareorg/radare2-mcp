# RFCs: Memory, types and analysis tools

Status: Proposed

These RFCs collect the tool-design discussion prompted by
[issue #4](https://github.com/radareorg/radare2-mcp/issues/4), including memory
access, types, variable editing, function details and smaller analysis
extensions. The issue supplies use cases; tool names and boundaries follow
r2's existing concepts and interfaces.

## Tool proposals

| Proposal | Action | Priority |
| --- | --- | --- |
| [Read memory](read-memory.md) | Add `read_memory`; reuse `hexdump` as a compatibility view. | First milestone |
| [Write memory](write-memory.md) | Add `write_memory` for bytes, scalars and field patches. | First milestone |
| [Define types](define-types.md) | Add `define_types` using the native c2 parser. | First milestone |
| [List types](list-types.md) | Add `list_types` with optional layout details. | First milestone |
| [Set a type](set-type.md) | Add `set_type` for address links and function variables. | Second milestone |
| [Function details](function-details.md) | Extend `show_function_details` with variable discovery. | Second milestone |
| [Rename a variable](rename-variable.md) | Add `rename_variable` for function arguments and locals. | Second milestone |
| [Rename a flag](rename-flag.md) | Correct the existing tool's description and verify its result. | Second milestone |
| [Function prototypes](function-prototypes.md) | Reuse `get_function_prototype` and `set_function_prototype`. | Second milestone integration |
| [Targeted analysis](analysis.md) | Extend `analyze` with an optional function address. | Later |
| [Search](search.md) | Extend `search` with decoded immediate-operand search. | Later |
| [Disassembly](disassemble.md) | Add structured instruction metadata, including length. | Later |
| [Outgoing references](xrefs-from.md) | Add `xrefs_from`, matching the existing `xrefs_to`. | Later |

## Design agreements

- Model memory access with two actions, `read_memory` and `write_memory`.
  Hexdumps, integers, strings and structures are interpretations or views of
  those operations, not separate tools for every width and representation.
- Reuse the native type database, c2 parser, `pf` decoder and IO APIs. Layout
  and encoding fixes belong in r2 when the native implementation is missing
  support. Add no dependencies beyond radare2.
- Extend existing tools when their names already describe the capability.
  Preserve the existing function, flag, prototype and lookup names.
- Keep type definitions, analysis annotations and memory contents distinct.
  A temporary typed read changes no annotation; `set_type` changes metadata;
  `write_memory` changes bytes.
- Honor the existing text, JSON, structured and combined content modes.
  Use the existing response helpers and separate command diagnostics from
  structured results. Preserve exact large integers without conversion
  through floating point.
- Operate within the current session. Preserve seek, block size and
  configuration unless changing them is the explicit action requested.
- Expose read operations in read-only mode. Exclude metadata mutations and
  memory writes, and enforce mode restrictions during dispatch as well as
  catalog listing. Dedicated tools do not require arbitrary command access.
- Test every advertised backend. Local, core-plugin, remote HTTP and Frida
  support can differ. Preserve the supported-header build policy when
  adopting newer native APIs.

## Existing capabilities to reuse

| Capability discussed | Existing interface or decision |
| --- | --- |
| Find a function by name or address | `show_function_details(address=...)` accepts address expressions and selects the containing function. |
| Inspect the current function | Omit `address` from `show_function_details`; `get_current_address` provides the seek and flag context. |
| Convert numbers or resolve symbols | `calculate` and existing numeric-expression arguments. |
| Rename functions | Keep `rename_function`. |
| Rename global data labels | Keep `rename_flag`; function locals use `rename_variable`. |
| Read scalar widths, floats and strings | Interpret memory through `read_memory` with `type` or `format`. |
| Read sections, imports, exports, entrypoints and strings | Keep the existing listing tools. |
| Get the current file path or list files | Reuse `show_info` and `list_files`. |
| Execute scripts | Reuse the existing execution-gated script tools; language parity is not a requirement. |
| Read and write arbitrary host files | Outside this memory API; the actions operate on r2 IO addresses. |
| Delete a mistaken function | Deferred separately in the targeted-analysis proposal. |

## Delivery order

1. Add shared exact-span IO, raw reads/writes and the writable-open contract.
2. Add type definition and discovery, then complete formatted and typed
   reads through the c2 -> type database -> `pf` path.
3. Add typed scalar and selected-field writes, followed by arrays and object
   patches. Verify native setter behavior before wrapping it.
4. Complete the memory milestone with the `hexdump` compatibility wrapper,
   examples and backend/content-mode checks.
5. Extend function details with variables, then implement renaming and
   `set_type`. Integrate the existing prototype and flag tools.
6. Implement the smaller analysis, search, disassembly and xref extensions
   independently after the first two milestones.

## Validation and completion

Use focused regressions in the existing test suite and deterministic
fixtures. Each proposal lists its acceptance cases. Verify relevant catalog
and dispatch behavior, unchanged session state on errors, and structured
output independently of the human text view.

Run `make -j` and `make test` for implementation changes. Run sanitizer
checks for new buffer, parser-integration and encoding paths. The first
milestone is complete when an agent can define a type, inspect its layout,
read memory through it and update supported fields without enabling raw
command execution. The second is complete when variable discovery, renaming
and type application work together through the existing function workflow.
