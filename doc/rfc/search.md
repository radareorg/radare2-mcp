# RFC: Search decoded immediate operands

Status: Proposed extension; later milestone. See the [RFC index](README.md).

## Purpose

Add decoded instruction-immediate search to the existing `search` action.
The current `type="value"` searches encoded numeric bytes. A decoded
instruction operand can have a different encoding, so these are distinct
search modes.

## Interface

Extend the existing `type` selector with `immediate`:

```text
search(query="0x1234", type="immediate")
```

Preserve the existing string, wide-string, hex and value modes, including
`value_size` behavior. `value_size` describes raw value width and does not
become an instruction-immediate width selector.

## Implementation

Validate the numeric query through existing expression helpers and use
native decoded search, such as the `/ai` facilities. Respect target
architecture, bitness and native search ranges; do not simulate operand
search with byte matching.

Return matching instruction addresses, decoded instructions and immediate
values/operand metadata where native results provide them. Preserve exact
large integers and support existing content modes and bounded output.
Do not create separate tools for numeric search widths or name search
already covered by listing filters.

Verify native search side effects and tool-mode eligibility before exposing
the new mode. Do not make analysis-mutating search modes available in
read-only mode merely because they return matches.

## Acceptance cases

- A constant whose instruction encoding differs from its raw byte value.
- Target-specific decoding, signed values and invalid expressions.
- Existing search modes and `value_size` unchanged.
- Native range behavior, bounded results, content modes and preserved seek.
