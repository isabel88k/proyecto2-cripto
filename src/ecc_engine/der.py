"""Subconjunto DER estricto y acotado para el perfil X.509 del proyecto."""


def tlv(tag: int, value: bytes) -> bytes:
    size = len(value)
    length = (bytes([size]) if size < 128 else
              bytes([0x80 | ((size.bit_length()+7)//8)]) + size.to_bytes((size.bit_length()+7)//8, 'big'))
    return bytes([tag]) + length + value


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b''.join(items))


def integer(value: int) -> bytes:
    if type(value) is not int or value < 0:
        raise ValueError('DER INTEGER requiere entero no negativo')
    raw = value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')
    if raw[0] & 0x80:
        raw = b'\0' + raw
    return tlv(2, raw)


def decode_integer(value: bytes) -> int:
    if not value or value[0] & 0x80 or (len(value) > 1 and value[0] == 0 and value[1] < 128):
        raise ValueError('INTEGER DER negativo o no mínimo')
    return int.from_bytes(value, 'big')


class Reader:
    def __init__(self, data: bytes):
        self.data, self.position = data, 0
        if len(data) > 65536:
            raise ValueError('Objeto DER demasiado grande')

    def read(self, expected: int | None = None) -> tuple[bytes, bytes]:
        start = self.position
        if len(self.data) - start < 2:
            raise ValueError('DER truncado')
        tag, size = self.data[start], self.data[start+1]
        pos = start + 2
        if tag & 31 == 31 or (expected is not None and tag != expected):
            raise ValueError('Etiqueta DER fuera del perfil')
        if size & 0x80:
            count = size & 0x7f
            if count == 0 or count > 3 or pos+count > len(self.data) or self.data[pos] == 0:
                raise ValueError('Longitud DER inválida')
            size = int.from_bytes(self.data[pos:pos+count], 'big')
            pos += count
            if size < 128:
                raise ValueError('Longitud DER no mínima')
        if pos+size > len(self.data):
            raise ValueError('DER truncado')
        self.position = pos+size
        return self.data[pos:pos+size], self.data[start:self.position]

    def done(self):
        if self.position != len(self.data):
            raise ValueError('Datos DER adicionales')


EC_ALGORITHM = sequence(tlv(6, bytes.fromhex('2a8648ce3d0201')),
                        tlv(6, bytes.fromhex('2a8648ce3d030107')))
SIGN_ALGORITHM = sequence(tlv(6, bytes.fromhex('2a8648ce3d040302')))
