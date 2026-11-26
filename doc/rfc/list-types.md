# RFC: List types

Status: Proposed. First milestone. See the [RFC index](README.md).

## Purpose

Add one type-discovery tool for built-in, loaded and newly defined types.
Agents need to inspect available layouts before using them to interpret
memory or annotate variables.

## Interface

```text
list_types(filter?, kind?, details?, count?, cursor?, page_size?)
```

Reuse existing list-tool conventions for regex filtering, counting and
pagination. `kind` optionally selects a native category such as structure,
union, enum, typedef, primitive or function. `details` defaults to false.

```text
list_types(filter="Header")
list_types(filter="^Header$", details=true)
list_types(kind="enum", count=true)
```

Basic entries identify the name, kind and size when known. Detailed entries
include members, offsets, member types, dimensions, alignment and enum
values where the native database provides them, plus the derived `pf`
format when available. Unknown size or alignment must remain unknown.

An exact-name regex with `details=true` inspects a definition without adding
a separate type-detail tool. Return structured data and an appropriate text
view using the existing content modes.

## Implementation

Query the session's native type database. Use native size and format
conversion APIs, resolving typedefs without flattening away their identity.
Do not reconstruct original C source or infer missing layout information.

Distinguish declarations that parse successfully from types that can also
be converted to a readable or writable format. Report an unavailable derived
format without hiding the definition or guessing a pointer layout.

Keep C types and named `pf` formats distinct: `format=".name"` selects a
format definition, while `type="Header"` selects a C type. Listing types
does not read target memory, create links or change parser configuration.

Expose in read-only mode. Bound detailed results and paginate by complete
type entries so nested member data is not split by text lines.

## Acceptance cases

- Filtering, kind selection, counts and entry-based pagination.
- Primitive, compound and function types and typedef identity.
- Accurate member offsets, sizes and derived formats after `define_types`.
- Incomplete declarations and unsupported formats represented explicitly.
- Content modes, read-only access and unchanged session state.
