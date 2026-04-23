"""
IEEE P1363 → ASN.1 DER translation layer for ECDSA P-256 signatures.

Hardware FIDO2 authenticators produce DER-encoded signatures per the WebAuthn spec.
The browser's SubtleCrypto.sign("ECDSA", key, data) returns raw P1363 (r || s, 64 bytes).
This module normalises both formats to DER before fido2-library verification so that
either signing path is handled transparently.
"""


def is_der(sig: bytes) -> bool:
    """Heuristic: DER SEQUENCE tag is 0x30. P1363 never starts with this byte."""
    return len(sig) > 2 and sig[0] == 0x30


def p1363_to_der(sig: bytes) -> bytes:
    """
    Convert a 64-byte IEEE P1363 ECDSA-P256 raw signature to ASN.1 DER.

    P1363 format : r (32 bytes big-endian) || s (32 bytes big-endian)
    DER format   : SEQUENCE { INTEGER r, INTEGER s }

    The INTEGER encoding prepends a 0x00 byte when the high bit of r or s is
    set, keeping the value positive in two's-complement representation.
    """
    if len(sig) != 64:
        raise ValueError(
            f"P1363 ECDSA-P256 signature must be exactly 64 bytes (got {len(sig)})"
        )

    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    def _der_integer(n: int) -> bytes:
        if n == 0:
            raw = b"\x00"
        else:
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
            if raw[0] & 0x80:      # high bit set → two's-complement sign bit
                raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def ensure_der(sig: bytes) -> bytes:
    """
    Return sig in ASN.1 DER format regardless of input encoding.
    Passes DER through unchanged; converts P1363 (exactly 64 bytes) to DER.
    """
    if is_der(sig):
        return sig
    return p1363_to_der(sig)
