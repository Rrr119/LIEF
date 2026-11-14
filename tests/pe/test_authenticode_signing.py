import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path

import lief
import pytest
from lief.authenticode import main as authenticode_cli


def _make_pe() -> lief.PE.Binary:
    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
    factory.add_section(lief.PE.Section(".text", [0x90] * 64))
    pe = factory.get()
    assert pe is not None
    return pe


def _make_certificate(
    tmp_path: Path, name: str = "signer", usage: str = "codeSigning"
) -> tuple[Path, Path]:
    cert = tmp_path / f"{name}.pem"
    key = tmp_path / f"{name}.key"
    not_before = time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() - 86400))
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "3650",
            "-not_before",
            not_before,
            "-subj",
            f"/CN=LIEF Authenticode {name}/O=LIEF",
            "-addext",
            f"extendedKeyUsage={usage}",
            "-addext",
            "keyUsage=digitalSignature",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def _write_signed(pe: lief.PE.Binary, path: Path, cert: Path, key: Path) -> None:
    assert pe.sign(str(cert), str(key))
    pe.write(path)


def _osslsigncode() -> str | None:
    return shutil.which("osslsigncode")


def test_unsigned_extract_and_strip(tmp_path: Path):
    pe = _make_pe()
    unsigned = tmp_path / "unsigned.exe"
    pe.write(unsigned)

    parsed = lief.PE.parse(unsigned)
    assert parsed is not None
    assert not parsed.has_signature
    assert not parsed.has_signatures

    extracted = parsed.extract_signature()
    assert isinstance(extracted, lief.PE.Authenticode.extracted_t)
    assert not extracted.present
    assert not extracted.corrupted
    assert extracted.ranges
    assert not parsed.remove_signature()


def test_sign_extract_strip_and_verify(tmp_path: Path):
    cert, key = _make_certificate(tmp_path)
    unsigned = tmp_path / "unsigned.exe"
    signed = tmp_path / "signed.exe"

    pe = _make_pe()
    pe.write(unsigned)
    parsed = lief.PE.parse(unsigned)
    assert parsed is not None
    assert parsed.sign(
        str(cert),
        str(key),
        program_name="LIEF Authenticode Test",
        more_info="https://lief.re",
    )
    parsed.write(signed)

    new = lief.PE.parse(signed)
    assert new is not None
    assert new.has_signature
    assert new.has_signatures
    assert new.compute_checksum() == new.optional_header.checksum
    assert new.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK

    extracted = new.extract_signature()
    assert extracted is not None
    assert extracted.present
    assert not extracted.corrupted
    assert len(extracted.signatures) == 1
    assert extracted.pkcs7
    assert extracted.certificates
    assert extracted.ranges
    assert extracted.table_offset == new.cert_dir.rva
    assert extracted.table_size == new.cert_dir.size
    assert bytes(extracted.signatures[0].raw_der) == bytes(extracted.pkcs7)
    opus = (
        new.signatures[0]
        .signers[0]
        .get_auth_attribute(lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO)
    )
    assert isinstance(opus, lief.PE.SpcSpOpusInfo)
    assert opus.program_name == "LIEF Authenticode Test"
    assert opus.more_info == "https://lief.re"
    signed_data = signed.read_bytes()
    range_hash = hashlib.sha256(
        b"".join(signed_data[item.start : item.end] for item in extracted.ranges)
    ).digest()
    assert range_hash == new.authentihash_sha256

    stripped = tmp_path / "stripped.exe"
    assert new.remove_signature()
    assert not new.has_signature
    assert not new.has_signatures
    assert new.cert_dir.rva == 0
    assert new.cert_dir.size == 0
    new.write(stripped)

    stripped_pe = lief.PE.parse(stripped)
    assert stripped_pe is not None
    assert not stripped_pe.has_signature
    assert stripped_pe.compute_checksum() == stripped_pe.optional_header.checksum

    resigned = lief.PE.parse(unsigned)
    assert resigned is not None
    _write_signed(resigned, tmp_path / "resigned.exe", cert, key)
    resigned_pe = lief.PE.parse(tmp_path / "resigned.exe")
    assert resigned_pe is not None
    assert resigned_pe.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK

    osslsigncode = _osslsigncode()
    if osslsigncode is not None:
        result = subprocess.run(
            [
                osslsigncode,
                "verify",
                "-CAfile",
                str(cert),
                "-in",
                str(signed),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert result.returncode == 0, result.stdout


def test_corrupted_signature(tmp_path: Path):
    cert, key = _make_certificate(tmp_path)
    signed = tmp_path / "signed.exe"

    pe = _make_pe()
    _write_signed(pe, signed, cert, key)

    parsed = lief.PE.parse(signed)
    assert parsed is not None
    extracted = parsed.extract_signature()
    assert extracted is not None

    corrupted = bytearray(signed.read_bytes())
    assert extracted.table_size > 32
    corrupted[extracted.table_offset + 32] ^= 0x80
    corrupted_path = tmp_path / "corrupted.exe"
    corrupted_path.write_bytes(corrupted)

    new = lief.PE.parse(corrupted_path)
    assert new is not None
    assert new.has_signature
    assert new.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK
    corrupted_extracted = new.extract_signature()
    assert corrupted_extracted is not None
    assert corrupted_extracted.present


def test_command_line_roundtrip(tmp_path: Path):
    cert, key = _make_certificate(tmp_path)
    unsigned = tmp_path / "unsigned.exe"
    signed = tmp_path / "signed.exe"
    stripped = tmp_path / "stripped.exe"
    export = tmp_path / "export"

    pe = _make_pe()
    pe.write(unsigned)
    assert (
        authenticode_cli(
            [
                "sign",
                str(unsigned),
                "-o",
                str(signed),
                "--certificate",
                str(cert),
                "--private-key",
                str(key),
            ]
        )
        == 0
    )
    assert authenticode_cli(["extract", str(signed), "-o", str(export)]) == 0
    assert (export / "signature.pkcs7").is_file()
    assert (export / "authenticode.json").is_file()
    assert (export / "certificates" / "cert-0.pem").is_file()

    assert authenticode_cli(["strip", str(signed), "-o", str(stripped)]) == 0
    stripped_pe = lief.PE.parse(stripped)
    assert stripped_pe is not None
    assert not stripped_pe.has_signature


def test_rfc3161_timestamp(tmp_path: Path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")

    cert, key = _make_certificate(tmp_path)
    tsa_cert, _tsa_key = _make_certificate(tmp_path, "tsa", "critical,timeStamping")

    unsigned = tmp_path / "unsigned.exe"
    first_signed = tmp_path / "first-signed.exe"
    timestamped = tmp_path / "timestamped.exe"

    pe = _make_pe()
    pe.write(unsigned)

    parsed = lief.PE.parse(unsigned)
    assert parsed is not None
    config = lief.PE.Authenticode.signing_config_t()
    config.certificate = str(cert)
    config.private_key = str(key)
    config.signing_time = [2026, 11, 14, 0, 0, 0]
    assert lief.PE.Authenticode.sign(parsed, config)
    parsed.write(first_signed)

    first = lief.PE.parse(first_signed)
    assert first is not None
    signature_value = bytes(first.signatures[0].signers[0].encrypted_digest)
    digest = hashlib.sha256(signature_value).hexdigest()

    query = tmp_path / "request.tsq"
    response = tmp_path / "response.tsr"
    serial = tmp_path / "serial"
    serial.write_text("01\n")
    config_path = tmp_path / "tsa.cnf"
    openssl_env = {**os.environ, "OPENSSL_CONF": "/dev/null"}
    config_path.write_text(
        "[tsa]\n"
        "default_tsa = tsa_config\n"
        "[tsa_config]\n"
        f"dir = {tmp_path}\n"
        "serial = serial\n"
        "signer_cert = tsa.pem\n"
        "certs = tsa.pem\n"
        "signer_key = tsa.key\n"
        "signer_digest = sha256\n"
        "crypto_device = builtin\n"
        "default_policy = 1.2.3.4.1\n"
        "digests = sha256\n"
        "accuracy = secs:1\n"
        "ordering = yes\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
    )

    subprocess.run(
        [
            "openssl",
            "ts",
            "-query",
            "-digest",
            digest,
            "-sha256",
            "-cert",
            "-out",
            str(query),
        ],
        check=True,
        env=openssl_env,
        cwd=tmp_path,
    )
    subprocess.run(
        [
            "openssl",
            "ts",
            "-reply",
            "-config",
            str(config_path),
            "-queryfile",
            str(query),
            "-out",
            str(response),
        ],
        check=True,
        env=openssl_env,
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    token = lief.PE.Authenticode.timestamp_token_from_response(
        list(response.read_bytes())
    )
    assert isinstance(token, bytes)
    assert token

    parsed = lief.PE.parse(unsigned)
    assert parsed is not None
    config = lief.PE.Authenticode.signing_config_t()
    config.certificate = str(cert)
    config.private_key = str(key)
    config.signing_time = [2026, 11, 14, 0, 0, 0]
    callback_digests: list[bytes] = []

    def timestamp_callback(digest: bytes) -> bytes:
        callback_digests.append(digest)
        return token

    config.timestamp_callback = timestamp_callback
    assert parsed.sign(config)
    parsed.write(timestamped)

    assert callback_digests == [bytes.fromhex(digest)]

    timestamped_pe = lief.PE.parse(timestamped)
    assert timestamped_pe is not None
    assert timestamped_pe.verify_signature() == (
        lief.PE.Signature.VERIFICATION_FLAGS.OK
    )
    extracted = timestamped_pe.extract_signature()
    assert extracted is not None
    assert len(extracted.timestamps) == 1
    assert extracted.timestamps[0].protocol == "RFC3161"
    assert extracted.timestamps[0].token

    parsed = lief.PE.parse(unsigned)
    assert parsed is not None
    config = lief.PE.Authenticode.signing_config_t()
    config.certificate = str(cert)
    config.private_key = str(key)
    config.timestamp_token = token
    assert parsed.sign(config)
    parsed.write(timestamped)

    direct = lief.PE.parse(timestamped)
    assert direct is not None
    assert direct.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK

    osslsigncode = _osslsigncode()
    if osslsigncode is not None:
        result = subprocess.run(
            [
                osslsigncode,
                "verify",
                "-CAfile",
                str(cert),
                "-TSA-CAfile",
                str(tsa_cert),
                "-in",
                str(timestamped),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert result.returncode == 0, result.stdout
