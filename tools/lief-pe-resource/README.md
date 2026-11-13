# lief-pe-resource

`lief-pe-resource` lists, exports, replaces, adds, and removes resources in
Portable Executable files.

Resource paths use a `type/name/language` layout. Components can be numeric
IDs or resource names, and the type accepts both numeric IDs and names
(`ICON`, `RT_ICON`, ...).

```console
# List every resource with type, name, language, size, and RVA
lief-pe-resource list app.exe

# Export an icon
lief-pe-resource export app.exe ICON/1/1033 -o icon.bin

# Replace the icon and rebuild the PE
lief-pe-resource replace app.exe ICON/1/1033 new-icon.bin -o app-patched.exe

# Add or remove a resource
lief-pe-resource add app.exe RCDATA/42/1033 payload.bin -o app-patched.exe
lief-pe-resource remove app.exe MANIFEST/1/1033 -o app-patched.exe
```

When the input is Authenticode-signed, the original certificate table is
saved to `<output>.sig` (or the path given with `--signature`) and the rebuilt
PE is written without the now-invalid signature. The checksum is recomputed
by default; use `--no-checksum` to keep the original value.
