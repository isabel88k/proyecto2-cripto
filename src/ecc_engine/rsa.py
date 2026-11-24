"""RSA con primos propios y RSASSA-PSS/SHA256, sal de 32 bytes (RFC 8017)."""
from dataclasses import dataclass
from secrets import token_bytes, randbelow, compare_digest
from math import gcd
from .arithmetic import generate_prime, inverse_mod
from .encoding import wipe_buffer
from .hashes import sha256


@dataclass(frozen=True)
class RSAKey:
    n: int
    e: int = 65537
    d: int | None = None
    p: int | None = None
    q: int | None = None

    def public(self):
        return RSAKey(self.n, self.e)


def generate_key(bits: int = 3072) -> RSAKey:
    if type(bits) is not int or not 1024 <= bits <= 8192 or bits % 2:
        raise ValueError('RSA: tamaño par entre 1024 y 8192 bits; usar 3072 para comparación')
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        if p != q and (p*q).bit_length() == bits:
            return RSAKey(p*q, 65537, inverse_mod(65537, (p-1)*(q-1)), p, q)


def mgf1(seed: bytes, length: int) -> bytes:
    if not 0 <= length <= 2**32 * 32:
        raise ValueError('Longitud MGF1 inválida')
    return b''.join(sha256(seed + counter.to_bytes(4, 'big'))
                    for counter in range((length + 31) // 32))[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pss_sign(key: RSAKey, message: bytes) -> bytes:
    if key.d is None or key.p is None or key.q is None:
        raise ValueError('Se requiere la clave RSA privada completa')
    em_bits = key.n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    if em_len < 66:
        raise ValueError('Módulo RSA demasiado pequeño')
    salt = token_bytes(32)
    h = sha256(bytes(8) + sha256(message) + salt)
    db = bytes(em_len - 66) + b'\x01' + salt
    masked = bytearray(_xor(db, mgf1(h, em_len - 33)))
    try:
        masked[0] &= 255 >> (8*em_len - em_bits)
        representative = int.from_bytes(bytes(masked) + h + b'\xbc', 'big')
    finally:
        wipe_buffer(masked)
    # Blinding aleatorio y CRT; no convierte al intérprete en tiempo constante.
    while True:
        blind = randbelow(key.n - 2) + 2
        if gcd(blind, key.n) == 1:
            break
    blinded = representative * pow(blind, key.e, key.n) % key.n
    m1 = pow(blinded, key.d % (key.p-1), key.p)
    m2 = pow(blinded, key.d % (key.q-1), key.q)
    result = (m2 + key.q * ((m1-m2)*inverse_mod(key.q, key.p) % key.p)) % key.n
    result = result * inverse_mod(blind, key.n) % key.n
    if pow(result, key.e, key.n) != representative:
        raise ValueError('Autocomprobación de firma RSA fallida')
    return result.to_bytes((key.n.bit_length()+7)//8, 'big')


def pss_verify(key: RSAKey, message: bytes, signature: bytes) -> bool:
    if type(key.n) is not int or type(key.e) is not int or key.n <= 1 or key.e < 3:
        return False
    em_bits = key.n.bit_length() - 1
    em_len = (em_bits + 7)//8
    if em_len < 66 or len(signature) != (key.n.bit_length()+7)//8:
        return False
    number = int.from_bytes(signature, 'big')
    if number >= key.n:
        return False
    representative = pow(number, key.e, key.n)
    if representative.bit_length() > 8*em_len:
        return False
    encoded = representative.to_bytes(em_len, 'big')
    masked, h, trailer = encoded[:em_len-33], encoded[em_len-33:-1], encoded[-1]
    unused = 8*em_len - em_bits
    if trailer != 0xbc or masked[0] >> (8-unused):
        return False
    db = bytearray(_xor(masked, mgf1(h, em_len-33)))
    try:
        db[0] &= 255 >> unused
        if bytes(db[:em_len-66]) != bytes(em_len-66) or db[em_len-66] != 1:
            return False
        expected = sha256(bytes(8) + sha256(message) + bytes(db[-32:]))
    finally:
        wipe_buffer(db)
    return compare_digest(h, expected)
