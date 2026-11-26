# RFC: Structured instruction details

Status: Proposed extension; later milestone. See the [RFC index](README.md).

## Purpose

Extend `disassemble` with native structured instruction metadata. Instruction
length belongs in each decoded instruction rather than in a separate
length-only tool.

## Existing interface

```text
disassemble(address, num_instructions?)
```

Keep the existing name, address-expression support, default instruction
count and text listing. The existing content mode selects structured output
without another tool or output-format argument.

```text
disassemble(address="sym.parse + 8", num_instructions=4)
```

## Implementation

Use native disassembly/analysis JSON or equivalent APIs. Each instruction
should expose its address, byte length, bytes and decoded text, plus native
operand or reference metadata when available. Do not calculate lengths
from printed text or decode through a second architecture implementation.

Text and structured views must cover the same instruction sequence. Report
invalid or incomplete instructions using native semantics and preserve the
current seek and configuration. Honor target bitness and endianness.

Retain `disassemble_function` for function-boundary-aware listings and
`decompile_function` for pseudocode; neither needs a duplicate lookup alias.

## Acceptance cases

- Correct lengths and addresses for variable-length and fixed-length targets.
- Arbitrary addresses independent of function analysis boundaries.
- Invalid/truncated instructions and bounded instruction counts.
- Matching text/structured sequences, unchanged session state and read-only
  availability for supported backends.
