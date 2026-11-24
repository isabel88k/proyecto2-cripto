"""SHA-256, HMAC-SHA256 y HKDF desde las operaciones de bits."""
import struct

_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)
_MASK = 0xffffffff


def _ror(x: int, bits: int) -> int:
    return ((x >> bits) | (x << (32 - bits))) & _MASK


def sha256(data: bytes) -> bytes:
    """FIPS 180-4: padding, 64 rondas por bloque y resumen de 32 bytes."""
    if not isinstance(data, bytes):
        raise TypeError('SHA-256 requiere bytes')
    bit_length = len(data) * 8
    if bit_length >= 1 << 64:
        raise ValueError('Mensaje demasiado largo')
    padded = data + b'\x80' + bytes((55 - len(data)) % 64) + bit_length.to_bytes(8, 'big')
    state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for offset in range(0, len(padded), 64):
        words = list(struct.unpack('>16I', padded[offset:offset + 64]))
        for i in range(16, 64):
            x, y = words[i - 15], words[i - 2]
            s0 = _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)
            s1 = _ror(y, 17) ^ _ror(y, 19) ^ (y >> 10)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & _MASK)
        a, b, c, d, e, f, g, h = state
        for constant, word in zip(_K, words):
            sigma1 = _ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)
            choice = (e & f) ^ (~e & g)
            t1 = (h + sigma1 + choice + constant + word) & _MASK
            sigma0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (sigma0 + majority) & _MASK
            a, b, c, d, e, f, g, h = ((t1 + t2) & _MASK, a, b, c,
                                      (d + t1) & _MASK, e, f, g)
        state = [(x + y) & _MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]
    return struct.pack('>8I', *state)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, b'\0')
    inner = bytes(x ^ 0x36 for x in key)
    outer = bytes(x ^ 0x5c for x in key)
    return sha256(outer + sha256(inner + data))


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869, extract y expand, con separación de contexto en info."""
    if type(length) is not int or not 0 <= length <= 255 * 32:
        raise ValueError('Longitud HKDF fuera de rango')
    prk = hmac_sha256(salt or bytes(32), ikm)
    result, previous = b'', b''
    for i in range(1, (length + 31) // 32 + 1):
        previous = hmac_sha256(prk, previous + info + bytes([i]))
        result += previous
    return result[:length]
