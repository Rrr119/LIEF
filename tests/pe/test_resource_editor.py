from pathlib import Path

import lief
import pytest
from utils import (
    get_sample,
    is_windows_x86_64,
    parse_pe,
    win_exec,
)


def _icon_paths(resources: lief.PE.ResourcesManager) -> list[str]:
    return [
        entry.path
        for entry in resources.entries
        if entry.type == lief.PE.ResourcesManager.TYPE.ICON.value
    ]


def test_list_export_and_replace_icon(tmp_path: Path):
    source_path = Path(get_sample("PE/PE64_x86-64_binary_mfc-application.exe"))
    target_path = Path(get_sample("PE/PE64_x86-64_binary_cmd.exe"))

    source = parse_pe(source_path)
    resources = source.resources_manager
    assert isinstance(resources, lief.PE.ResourcesManager)
    assert resources.entries
    assert _icon_paths(resources)

    source_icon_path = _icon_paths(resources)[0]
    source_icon = resources.export(source_icon_path)
    assert source_icon == resources.export(source_icon_path.replace("ICON/", "3/"))

    target = parse_pe(target_path)
    target_resources = target.resources_manager
    assert isinstance(target_resources, lief.PE.ResourcesManager)
    assert _icon_paths(target_resources)

    target_icon_path = _icon_paths(target_resources)[0]
    assert target_resources.replace(target_icon_path, source_icon)
    assert target_resources.replace("RCDATA/42/1033", b"resource-payload")
    assert target_resources.has_path("RCDATA/42/1033")

    output = tmp_path / target_path.name
    target.write(output)

    rebuilt = parse_pe(output)
    assert rebuilt.has_resources
    rebuilt_resources = rebuilt.resources_manager
    assert isinstance(rebuilt_resources, lief.PE.ResourcesManager)

    assert rebuilt_resources.export(target_icon_path) == source_icon
    assert rebuilt_resources.export("RCDATA/42/1033") == b"resource-payload"
    assert rebuilt_resources.entries

    checked, msg = lief.PE.check_layout(rebuilt)
    assert checked, msg
    assert rebuilt.optional_header.checksum == rebuilt.compute_checksum()

    if is_windows_x86_64():
        ret = win_exec(output, gui=False, timeout=20, args=["/c", "exit", "0"])
        assert ret is not None
        assert ret[0] == 0


def test_remove_resource(tmp_path: Path):
    sample_path = Path(get_sample("PE/PE64_x86-64_binary_cmd.exe"))
    pe = parse_pe(sample_path)
    resources = pe.resources_manager
    assert isinstance(resources, lief.PE.ResourcesManager)

    assert resources.add("RCDATA/77/1033", b"temporary")
    assert resources.remove("RCDATA/77/1033")
    assert not resources.has_path("RCDATA/77/1033")

    output = tmp_path / "cmd-removed.exe"
    pe.write(output)
    rebuilt = parse_pe(output)
    assert not rebuilt.resources_manager.has_path("RCDATA/77/1033")


def test_signature_data_is_preserved(tmp_path: Path):
    sample_path = Path(
        get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe")
    )
    pe = parse_pe(sample_path)
    assert pe.has_signatures

    signature = pe.signature_data
    assert signature

    resources = pe.resources_manager
    assert isinstance(resources, lief.PE.ResourcesManager)
    assert resources.original_signature_data == signature

    icon_path = _icon_paths(resources)[0]
    icon = resources.export(icon_path)
    assert resources.replace(icon_path, icon)

    # The original certificate table remains available after the modification.
    assert resources.original_signature_data == signature
    assert pe.signature_data == signature

    assert pe.remove_signatures()
    assert not pe.has_signatures
    assert pe.signature_data == b""

    output = tmp_path / "avast-unsigned.exe"
    pe.write(output)
    rebuilt = parse_pe(output)
    assert not rebuilt.has_signatures
    assert rebuilt.resources_manager.export(icon_path) == icon
    checked, msg = lief.PE.check_layout(rebuilt)
    assert checked, msg
