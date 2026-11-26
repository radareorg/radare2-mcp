# RFC: Outgoing cross references

Status: Proposed; later milestone. See the [RFC index](README.md).

## Purpose

Add `xrefs_from` as the outgoing counterpart of the existing `xrefs_to`.
The names describe direction directly. Avoid adding a direction option that
would make the existing `xrefs_to` name misleading.

## Interface

```text
xrefs_from(address)
```

The required expression selects the reference source address, matching the
address convention of `xrefs_to`. It does not implicitly mean every outgoing
reference in the containing function.

```text
xrefs_from(address="sym.parse + 12")
xrefs_to(address="obj.header")
```

## Implementation

Use native cross-reference APIs or the supported `axf` output path. Return
source, destination and native reference kind, preserving code/data
distinctions. An empty result means no known references; the tool does not
run analysis or discover missing references implicitly.

Use existing content modes and output bounds. Keep it available in
read-only mode and preserve current seek and reference metadata. Advertise
only tested backends with actual native reference support.

## Acceptance cases

- Known outgoing code and data references at an instruction address.
- No known references and invalid address expressions.
- Direction consistency with `xrefs_to`, structured reference kinds,
  unchanged analysis state and read-only availability.
