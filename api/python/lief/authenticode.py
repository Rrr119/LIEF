#!/usr/bin/env python
"""Command line interface for PE Authenticode operations."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path

import lief

_DIGESTS = {
    "sha1": lief.PE.ALGORITHMS.SHA_1,
    "sha256": lief.PE.ALGORITHMS.SHA_256,
    "sha384": lief.PE.ALGORITHMS.SHA_384,
    "sha512": lief.PE.ALGORITHMS.SHA_512,
}


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_wrap(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_oid(value: str) -> bytes:
    arcs = [int(x) for x in value.split(".")]
    encoded = bytearray()

    def append_base128(number: int) -> None:
        groups = [number & 0x7F]
        number >>= 7
        while number:
            groups.append(number & 0x7F)
            number >>= 7
        for index, group in enumerate(reversed(groups)):
            encoded.append(group | (0x80 if index + 1 < len(groups) else 0))

    append_base128(arcs[0] * 40 + arcs[1])
    for arc in arcs[2:]:
        append_base128(arc)
    return _der_wrap(0x06, bytes(encoded))


def _timestamp_request(digest: bytes) -> bytes:
    algorithm = _der_wrap(
        0x30,
        _der_oid("2.16.840.1.101.3.4.2.1") + b"\x05\x00",
    )
    message_imprint = _der_wrap(0x30, algorithm + _der_wrap(0x04, digest))
    return _der_wrap(0x30, b"\x02\x01\x01" + message_imprint)


def _fetch_timestamp(url: str, digest: bytes) -> bytes:
    request = urllib.request.Request(
        url,
        data=_timestamp_request(digest),
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()

    token = lief.PE.Authenticode.timestamp_token_from_response(payload)
    if isinstance(token, lief.lief_errors):
        raise ValueError(f"Invalid RFC3161 response: {token}")  # noqa: TRY004
    return bytes(token)


def _load(path: Path) -> lief.PE.Binary:
    binary = lief.PE.parse(path)
    if binary is None:
        raise RuntimeError(f"failed to parse '{path}' as PE")
    return binary


def _write_pem(path: Path, der: bytes) -> None:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    path.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE-----\n"
    )


def cmd_extract(args: argparse.Namespace) -> int:
    binary = _load(args.input)
    extracted = binary.extract_signature()
    if isinstance(extracted, lief.lief_errors):
        print(f"extract failed: {extracted}", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    if extracted.pkcs7:
        (out / "signature.pkcs7").write_bytes(bytes(extracted.pkcs7))
    for index, blob in enumerate(extracted.pkcs7_list):
        (out / f"signature-{index}.pkcs7").write_bytes(bytes(blob))

    certs_dir = out / "certificates"
    certs_dir.mkdir(exist_ok=True)
    for index, cert in enumerate(extracted.certificates):
        der = bytes(cert.raw)
        (certs_dir / f"cert-{index}.der").write_bytes(der)
        _write_pem(certs_dir / f"cert-{index}.pem", der)

    for index, timestamp in enumerate(extracted.timestamps):
        if timestamp.token:
            (out / f"timestamp-{index}.der").write_bytes(bytes(timestamp.token))

    ranges = [
        {
            "start": int(item.start),
            "end": int(item.end),
            "size": int(item.size),
        }
        for item in extracted.ranges
    ]
    metadata = {
        "present": bool(extracted.present),
        "corrupted": bool(extracted.corrupted),
        "certificate_table_offset": int(extracted.table_offset),
        "certificate_table_size": int(extracted.table_size),
        "signature_count": len(extracted.signatures),
        "certificate_count": len(extracted.certificates),
        "timestamp_count": len(extracted.timestamps),
        "ranges": ranges,
    }
    (out / "authenticode.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return 0


def cmd_strip(args: argparse.Namespace) -> int:
    binary = _load(args.input)
    removed = binary.remove_signature()
    binary.write(args.output)
    print("removed" if removed else "no signature")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    binary = _load(args.input)
    config = lief.PE.Authenticode.signing_config_t()
    config.certificate = args.certificate
    config.private_key = args.private_key
    config.private_key_password = args.password or ""
    config.certificate_chain = list(args.certificate_chain or [])
    config.digest_algorithm = _DIGESTS[args.digest]
    config.timestamp_digest_algorithm = _DIGESTS[args.timestamp_digest]
    config.program_name = args.program_name or ""
    config.more_info = args.more_info or ""
    config.include_signing_time = args.signing_time
    config.commercial = args.commercial

    if args.timestamp_token:
        config.timestamp_token = list(Path(args.timestamp_token).read_bytes())
    if args.timestamp_url:

        def timestamp_callback(digest: bytes) -> bytes:
            return _fetch_timestamp(args.timestamp_url, digest)

        config.timestamp_callback = timestamp_callback

    if not binary.sign(config):
        print("signing failed", file=sys.stderr)
        return 1
    binary.write(args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lief-authenticode")
    sub = parser.add_subparsers(dest="command", required=True)

    extract = sub.add_parser(
        "extract", help="export PKCS#7, chain, timestamps and ranges"
    )
    extract.add_argument("input", type=Path)
    extract.add_argument("-o", "--output", type=Path, required=True)
    extract.set_defaults(func=cmd_extract)

    strip = sub.add_parser("strip", help="remove the Authenticode signature")
    strip.add_argument("input", type=Path)
    strip.add_argument("-o", "--output", type=Path, required=True)
    strip.set_defaults(func=cmd_strip)

    sign = sub.add_parser("sign", help="sign a PE with an X.509 certificate")
    sign.add_argument("input", type=Path)
    sign.add_argument("-o", "--output", type=Path, required=True)
    sign.add_argument("--certificate", required=True, help="PEM or DER certificate")
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--password", help="private key password")
    sign.add_argument("--certificate-chain", nargs="*", default=[])
    sign.add_argument("--digest", choices=sorted(_DIGESTS), default="sha256")
    sign.add_argument("--timestamp-digest", choices=sorted(_DIGESTS), default="sha256")
    sign.add_argument("--timestamp-url", help="RFC3161 timestamp server URL")
    sign.add_argument(
        "--timestamp-token", type=Path, help="pre-computed TimeStampToken"
    )
    sign.add_argument("--program-name")
    sign.add_argument("--more-info")
    sign.add_argument(
        "--signing-time",
        action="store_true",
        help="include the PKCS#9 signingTime attribute",
    )
    sign.add_argument("--commercial", action="store_true")
    sign.set_defaults(func=cmd_sign)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
