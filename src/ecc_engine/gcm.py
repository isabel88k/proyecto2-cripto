"""GCM con IV de 96 bits y etiqueta completa de 128 bits (SP 800-38D)."""
from secrets import compare_digest
from .aes import AES128
from .encoding import wipe_buffer


def _multiply(x: int, y: int) -> int:
    """Producto en GF(2^128), polinomio x^128+x^7+x^2+x+1."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xe1000000000000000000000000000000 if v & 1 else 0)
    return z


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    stream = (aad + bytes((-len(aad)) % 16) + ciphertext + bytes((-len(ciphertext)) % 16)
              + (len(aad)*8).to_bytes(8, 'big') + (len(ciphertext)*8).to_bytes(8, 'big'))
    state, field_key = 0, int.from_bytes(h, 'big')
    for i in range(0, len(stream), 16):
        state = _multiply(state ^ int.from_bytes(stream[i:i + 16], 'big'), field_key)
    return state.to_bytes(16, 'big')


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _setup(key: bytes, nonce: bytes, data: bytes, aad: bytes):
    if len(nonce) != 12 or len(data) > (2**32 - 2)*16 or len(aad)*8 >= 2**64:
        raise ValueError('Nonce o longitud GCM fuera del perfil')
    aes = AES128(key)
    return aes, nonce + b'\0\0\0\x01'


def _ctr(aes: AES128, nonce: bytes, data: bytes) -> bytes:
    output = bytearray()
    try:
        for i in range(0, len(data), 16):
            counter = (i // 16 + 2).to_bytes(4, 'big')
            output.extend(_xor(data[i:i + 16], aes.encrypt_block(nonce + counter)))
        return bytes(output)
    finally:
        wipe_buffer(output)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> tuple[bytes, bytes]:
    aes, j0 = _setup(key, nonce, plaintext, aad)
    ciphertext = _ctr(aes, nonce, plaintext)
    tag = _xor(aes.encrypt_block(j0), _ghash(aes.encrypt_block(bytes(16)), aad, ciphertext))
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
            aad: bytes = b'') -> bytes:
    aes, j0 = _setup(key, nonce, ciphertext, aad)
    expected = _xor(aes.encrypt_block(j0), _ghash(aes.encrypt_block(bytes(16)), aad, ciphertext))
    # Autenticar ANTES de descifrar o liberar cualquier texto plano.
    if len(tag) != 16 or not compare_digest(tag, expected):
        raise ValueError('Autenticación GCM fallida')
    return _ctr(aes, nonce, ciphertext)
