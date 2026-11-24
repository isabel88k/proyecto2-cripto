"""AES-128: GF(2^8), S-box, expansión y diez rondas (FIPS 197)."""


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 255
        b >>= 1
    return result


def _sbox(x: int) -> int:
    # Inverso x**254 en GF(2^8), seguido de transformación afín.
    y, base, exponent = 1, x, 254
    while exponent:
        if exponent & 1:
            y = _gf_mul(y, base)
        base = _gf_mul(base, base)
        exponent >>= 1
    result = y
    for shift in (1, 2, 3, 4):
        result ^= ((y << shift) | (y >> (8 - shift))) & 255
    return result ^ 0x63


_SBOX = tuple(_sbox(x) for x in range(256))


class AES128:
    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != 16:
            raise ValueError('AES-128 requiere una clave de 16 bytes')
        expanded = list(key)
        rcon = 1
        while len(expanded) < 176:
            word = expanded[-4:]
            if len(expanded) % 16 == 0:
                word = [_SBOX[x] for x in word[1:] + word[:1]]
                word[0] ^= rcon
                rcon = _gf_mul(rcon, 2)
            for value in word:
                expanded.append(expanded[-16] ^ value)
        self._round_keys = [expanded[i:i + 16] for i in range(0, 176, 16)]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError('El bloque AES debe tener 16 bytes')
        state = [x ^ k for x, k in zip(block, self._round_keys[0])]
        for round_number in range(1, 11):
            state = [_SBOX[x] for x in state]
            # Matriz column-major: ShiftRows rota cada fila a la izquierda.
            state = [state[4*((col + row) % 4) + row] for col in range(4) for row in range(4)]
            if round_number != 10:
                for i in range(0, 16, 4):
                    a, b, c, d = state[i:i + 4]
                    total = a ^ b ^ c ^ d
                    state[i:i + 4] = [a ^ total ^ _gf_mul(a ^ b, 2),
                                      b ^ total ^ _gf_mul(b ^ c, 2),
                                      c ^ total ^ _gf_mul(c ^ d, 2),
                                      d ^ total ^ _gf_mul(d ^ a, 2)]
            state = [x ^ k for x, k in zip(state, self._round_keys[round_number])]
        return bytes(state)
