---
description: 'Find a control-flow path between two addresses for reachability or exploit planning'
version: 0.1
author: r2mcp
args:
  - name: source_address
    description: 'Source address or block'
    required: true
  - name: target_address
    description: 'Target address or block'
    required: true
user_template: |
  Compute a path with minimal output.
  Source: {source_address}. Target: {target_address}. Use: get_current_address, disassemble_function, disassemble, xrefs_to.
---
Find and explain a feasible control-flow path between two addresses.
Approach:
- Identify function boundaries for source/target.
- Use xrefs_to and selective disassembly to traverse edges.
- Summarize the path as a sequence of blocks with conditions.