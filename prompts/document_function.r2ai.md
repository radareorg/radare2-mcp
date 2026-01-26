---
description: 'Explain a function's purpose, behavior, and pseudocode'
version: 0.1
author: r2mcp
args:
  - name: address
    description: 'Function start address to document'
    required: true
  - name: detail
    description: 'Level of detail: concise|full'
    required: false
user_template: |
  Target function address: {address}.
  Detail level: {detail}.
  Use: get_current_address (to verify), disassemble_function (address), decompile_function (address), get_function_prototype (address).
---
Produce a clear, structured explanation of a function's behavior.
Guidelines:
- Summarize purpose, inputs/outputs, side effects.
- Highlight algorithms, notable constants, error paths.
- Provide a brief high-level pseudocode if helpful.