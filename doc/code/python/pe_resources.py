import lief


def access_root(pe: lief.PE.Binary) -> None:
    # lief-doc: access-root-start
    pe: lief.PE.Binary
    rsrc = pe.resources

    print(rsrc)
    # lief-doc: access-root-end


def add_child(pe: lief.PE.Binary) -> None:
    # lief-doc: add-child-start
    pe: lief.PE.Binary

    rsrc = pe.resources
    assert isinstance(rsrc, lief.PE.ResourceNode)

    dir_node = lief.PE.ResourceDirectory(100)
    data_node = lief.PE.ResourceData([1, 2, 3])

    rsrc.add_child(dir_node).add_child(data_node)
    # lief-doc: add-child-end


def pretty_print(pe: lief.PE.Binary) -> None:
    # lief-doc: pretty-print-start
    pe: lief.PE.Binary

    tree = pe.resources
    print(tree)
    # lief-doc: pretty-print-end


def set_manifest(pe: lief.PE.Binary) -> None:
    # lief-doc: manifest-start
    pe: lief.PE.Binary

    manager = pe.resources_manager
    assert isinstance(manager, lief.PE.ResourcesManager)

    manager.manifest = """
    <?xml version="1.0" standalone="yes"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1"
              manifestVersion="1.0">
      <trustInfo>
        <security>
          <requestedPrivileges>
             <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>
    """

    pe.write("new.exe")
    # lief-doc: manifest-end


def list_resources(pe: lief.PE.Binary) -> None:
    # lief-doc: list-resources-start
    pe: lief.PE.Binary

    resources = pe.resources_manager
    assert isinstance(resources, lief.PE.ResourcesManager)

    for entry in resources.entries:
        print(
            entry.type_name,
            entry.name or entry.name_id,
            entry.language,
            entry.size,
            hex(entry.rva),
            entry.path,
        )
    # lief-doc: list-resources-end


def edit_resource(pe: lief.PE.Binary) -> None:
    # lief-doc: edit-resource-start
    pe: lief.PE.Binary

    resources = pe.resources_manager
    assert isinstance(resources, lief.PE.ResourcesManager)

    # The path is <type>/<name>/<language>. Type names and numeric IDs are
    # both accepted.
    icon = resources.export("ICON/1/1033")

    # replace() creates the intermediate directories and the data node if the
    # path does not exist yet.
    resources.replace("ICON/1/1033", icon)
    resources.replace("RCDATA/42/1033", b"new payload")

    # remove() accepts the same path syntax.
    resources.remove("RCDATA/42/1033")

    pe.write("new.exe")
    # lief-doc: edit-resource-end


def preserve_signature(pe: lief.PE.Binary) -> None:
    # lief-doc: preserve-signature-start
    pe: lief.PE.Binary

    if pe.has_signatures:
        original = pe.signature_data
        with open("original-signature.bin", "wb") as output:
            output.write(original)

        # The resource changes invalidate the signature. Remove the stale
        # certificate table before rebuilding the unsigned PE.
        pe.resources_manager.replace("ICON/1/1033", b"new icon")
        pe.remove_signatures()

    pe.write("new.exe")
    # lief-doc: preserve-signature-end


def transfer_resources(from_pe: lief.PE.Binary, to_pe: lief.PE.Binary) -> None:
    # lief-doc: transfer-start
    from_pe: lief.PE.Binary
    to_pe: lief.PE.Binary

    resources = from_pe.resources
    assert isinstance(resources, lief.PE.ResourceNode)

    to_pe.set_resources(resources)
    to_pe.write("new.exe")
    # lief-doc: transfer-end
