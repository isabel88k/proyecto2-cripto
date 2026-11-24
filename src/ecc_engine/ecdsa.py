"""ECDSA P-256/SHA256 con nonce determinista RFC 6979."""
from .arithmetic import inverse_mod
from .ecc import P256, validate_private
from .hashes import sha256, hmac_sha256


def nonce_candidates(private: int, digest: bytes):
    validate_private(private)
    if len(digest) != 32:
        raise ValueError('Se requiere un resumen SHA-256')
    # bits2octets: reducir el resumen modulo n antes de alimentar HMAC.
    material = private.to_bytes(32, 'big') + (int.from_bytes(digest, 'big') % P256.n).to_bytes(32, 'big')
    v, k = b'\x01' * 32, bytes(32)
    k = hmac_sha256(k, v + b'\x00' + material)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b'\x01' + material)
    v = hmac_sha256(k, v)
    while True:
        v = hmac_sha256(k, v)
        candidate = int.from_bytes(v, 'big')
        if 1 <= candidate < P256.n:
            yield candidate
        k = hmac_sha256(k, v + b'\x00')
        v = hmac_sha256(k, v)


def sign(private: int, message: bytes) -> tuple[int, int]:
    validate_private(private)
    digest = sha256(message)
    z = int.from_bytes(digest, 'big')
    for nonce in nonce_candidates(private, digest):
        r = P256.mul(nonce, P256.g)[0] % P256.n
        if r == 0:
            continue
        s = inverse_mod(nonce, P256.n) * (z + r*private) % P256.n
        if s:
            return r, s
    raise RuntimeError('No se encontró nonce válido')


def verify(public, message: bytes, signature) -> bool:
    try:
        if not isinstance(signature, tuple) or len(signature) != 2:
            return False
        r, s = signature
        if any(type(x) is not int or not 1 <= x < P256.n for x in (r, s)):
            return False
        P256.validate_public(public)
        z = int.from_bytes(sha256(message), 'big')
        w = inverse_mod(s, P256.n)
        point = P256.add(P256.mul(z*w % P256.n, P256.g), P256.mul(r*w % P256.n, public))
        return point is not None and point[0] % P256.n == r
    except (ValueError, TypeError, OverflowError):
        return False
