---
description: 'Locate keys, IVs, S-boxes, and crypto constants'
version: 0.1
author: r2mcp
args:
  - name: hint
    description: 'Extra context (e.g., suspected algorithm)'
    required: false
user_template: |
  Focus: {hint}.
  Use: list_imports, list_strings (filter to crypto keywords), list_functions (scan for suspicious names), and xrefs_to (address).
  If needed, disassemble/decompile only tight regions where material is assigned.
---
You are tasked with locating cryptographic material in a binary.
Strategy:
- List imports and strings to find crypto APIs/signatures.
- Search for constants (AES S-box, SHA tables), base64 sets, or long random-looking blobs.
- Inspect xrefs to functions handling buffers just before encryption/decryption.
- Use selective decompilation and avoid dumping entire files.