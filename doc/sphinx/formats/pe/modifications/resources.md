# {fa}`solid fa-gears` Resources Modification

:::{figure} ../../../_static/pe_rsrc/overview.webp
:alt: PE Resources Overview
:scale: 50%
:::

LIEF allows you to modify (or create) PE resources at different levels:

- Directly on the binary tree ({sub-ref}`lief-pe-resource-node`)
- Using the {sub-ref}`lief-pe-resource-manager`.

## Binary Tree Modifications

The resource root node can be accessed using the {sub-ref}`lief-pe-binary-resources`
function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_resources.py", "access-root") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_resources.cpp", "access-root") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_resources.rs", "access-root") }}
:::
::::

From this {sub-ref}`lief-pe-resource-node` instance, you can use the
{sub-ref}`lief-pe-resource-node-add-child` or {sub-ref}`lief-pe-resource-node-remove-child`
functions to add or delete nodes:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_resources.py", "add-child") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_resources.cpp", "add-child") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_resources.rs", "add-child") }}
:::
::::

This low-level API can be used to modify the tree or change the data of a
specific node.

:::{admonition} Pretty Printing
:class: tip

You can also *print* a node to get a formatted representation of the
resource tree:

{{ literalinclude("../../../../code/python/pe_resources.py", "pretty-print") }}

```text
├── Directory ID: 0000 (0x0000)
│  ├── Directory ID: 0016 (0x0010) type: VERSION
│  │  └── Directory ID: 0001 (0x0001)
│  │      └── Data ID: 0000 (0x0000) Lang: 0x00 / Sublang: 0x00 length=772 (0x000304), offset: 0x1ca0
│  │          ├── Hex: 04:03:34:00:00:00:56:00:53:00:5f:00:56:00:45:00:52:00:53:00
│  │          └── Str: ..4...V.S._.V.E.R.S.
│  └── Directory ID: 0024 (0x0018) type: MANIFEST
│      └── Directory ID: 0001 (0x0001)
│          └── Data ID: 1033 (0x0409) Lang: 0x09 / Sublang: 0x01 length=1900 (0x00076c), offset: 0x1fa4
│              ├── Hex: 3c:61:73:73:65:6d:62:6c:79:20:78:6d:6c:6e:73:3d:22:75:72:6e
│              └── Str: <assembly xmlns="urn
```
:::

## Resources Manager

The {sub-ref}`lief-pe-resource-manager` provides a higher-level API for the resource
tree. It can also be used to set or change resource elements such as the
manifest:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_resources.py", "manifest") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_resources.cpp", "manifest") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_resources.rs", "manifest") }}
:::
::::

## Path-based Resource Editing

The {sub-ref}`lief-pe-resource-manager` can also address resources by a
`type/name/language` path. Type and name components accept numeric IDs or
resource names, and the type accepts the usual names and aliases
(`ICON`, `RT_ICON`, `MANIFEST`, `RT_MANIFEST`, ...). This makes it possible
to export, replace, add, and remove entries without traversing the tree:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_resources.py", "edit-resource") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_resources.cpp", "edit-resource") }}
:::
::::

- `export(path)` returns the resource payload as `bytes`.
- `replace(path, data)` replaces an existing data node or creates the
  missing path.
- `add(path, data)` is the same operation but fails if the path already
  exists.
- `remove(path)` deletes the matching node or subtree.
- `entries` returns type, name, language, size, RVA, and path for every
  data node.

```python
resources = pe.resources_manager

for entry in resources.entries:
    print(entry.type_name, entry.name, entry.language, entry.size, entry.rva)

icon = resources.export("ICON/1/1033")
resources.replace("ICON/1/1033", icon)
resources.remove("MANIFEST/1/1033")
```

### Authenticode Signatures

Changing resources invalidates an existing Authenticode signature. LIEF
keeps the original certificate table available through
{sub-ref}`lief-pe-binary-signature_data` and warns when a path-based
modification is performed:

{{ literalinclude("../../../../code/python/pe_resources.py", "preserve-signature") }}

`Binary.remove_signatures()` drops the stale certificate table so the
rebuilt PE is an explicitly unsigned binary. Save the original data first
if it needs to be compared with a future signature.

## Command-line Tool

The `lief-pe-resource` tool exposes the same operations from the command
line.

```console
# TYPE, NAME, LANGUAGE, SIZE, RVA, and PATH
lief-pe-resource list app.exe

# Export one resource; omit -o to write the raw payload to stdout
lief-pe-resource export app.exe ICON/1/1033 -o icon.bin

# Replace and rebuild
lief-pe-resource replace app.exe ICON/1/1033 icon.bin -o app-patched.exe

# Add or delete a resource
lief-pe-resource add app.exe RCDATA/42/1033 payload.bin -o app-patched.exe
lief-pe-resource remove app.exe MANIFEST/1/1033 -o app-patched.exe
```

The builder recomputes the PE checksum by default. For signed inputs,
`lief-pe-resource` saves the original certificate table to
`<output>.sig` (or the file passed to `--signature`), prints a warning,
and writes the rebuilt PE without the invalid signature. Pass
`--no-checksum` to keep the original checksum field.

## Resource Tree Transfer between Binaries

LIEF can transfer the resource tree from one binary to another.
This operation can be performed using the {sub-ref}`lief-pe-binary-set_resources`
function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_resources.py", "transfer") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_resources.cpp", "transfer") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_resources.rs", "transfer") }}
:::
::::

{{ cross_api }}
