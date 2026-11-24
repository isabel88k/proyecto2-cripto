"""Formatos estrictos, límites de entrada y escritura exclusiva de archivos."""
import base64
import json
import os
from pathlib import Path
import re
from .ecc import P256, public_key, validate_private
from .der import Reader, sequence, integer, decode_integer, tlv, EC_ALGORITHM

MAX_DATA = 1024*1024
MAX_DOCUMENT = 3*1024*1024


def wipe_buffer(buffer: bytearray) -> None:
    """Sobrescribe un búfer mutable con ceros (mejor esfuerzo en Python)."""
    for i in range(len(buffer)):
        buffer[i] = 0


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def read_bytes(path, limit=MAX_DATA) -> bytes:
    with open(path, 'rb') as stream:
        data = stream.read(limit+1)
    if len(data) > limit:
        raise ValueError(f'Entrada supera el límite de {limit} bytes')
    return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Clave JSON duplicada')
        result[key] = value
    return result


def load_json(path) -> dict:
    try:
        value = json.loads(read_bytes(path, MAX_DOCUMENT), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Número JSON inválido')))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('Documento JSON inválido') from error
    if not isinstance(value, dict):
        raise ValueError('Se requiere un objeto JSON')
    return value


def write_bytes(path, data: bytes, private: bool = False):
    """O_EXCL evita sobrescritura y seguir un enlace simbólico ya existente."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def save_json(path, value: dict, private: bool = False):
    write_bytes(path, canonical(value) + b'\n', private)


def write_pair(first_path, first_data: bytes, second_path, second_data: bytes):
    """Crear clave privada y salida pública; revertir solo archivos propios.

    No es una transacción ante corte de energía. Sí revierte ante excepciones
    de escritura y preserva cualquier salida que ya existía antes del comando.
    """
    created = []
    descriptors = []
    try:
        for path, data, mode in ((Path(first_path), first_data, 0o600),
                                 (Path(second_path), second_data, 0o644)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            descriptors.append(descriptor)
            # os.write puede ser parcial; fdopen/write maneja el buffering.
            with os.fdopen(descriptor, 'wb') as stream:
                descriptors.pop()
                stream.write(data)
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        for path in created:
            path.unlink(missing_ok=True)
        raise


def unhex(value, size: int | None = None, maximum: int = MAX_DATA) -> bytes:
    if (not isinstance(value, str) or len(value) % 2 or len(value) > maximum*2
            or re.fullmatch('[0-9a-f]*', value) is None):
        raise ValueError('Hexadecimal inválido; usar minúsculas sin espacios')
    result = bytes.fromhex(value)
    if size is not None and len(result) != size:
        raise ValueError('Longitud hexadecimal incorrecta')
    return result


def point_bytes(point) -> bytes:
    P256.validate_public(point)
    return b'\x04' + point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big')


def decode_point(raw: bytes):
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError('Se requiere punto P-256 SEC1 sin comprimir')
    point = int.from_bytes(raw[1:33], 'big'), int.from_bytes(raw[33:], 'big')
    P256.validate_public(point)
    return point


def key_record(private_scalar: int, purpose: str, private: bool = False) -> dict:
    if purpose not in ('sign', 'exchange'):
        raise ValueError('Propósito de clave inválido')
    point = public_key(private_scalar)
    result = {'version': 1, 'curve': 'P-256', 'purpose': purpose,
              'x': f'{point[0]:064x}', 'y': f'{point[1]:064x}'}
    if private:
        result['d'] = f'{private_scalar:064x}'
    return result


def read_key(path, purpose: str, private: bool = False):
    item = load_json(path)
    expected = {'version', 'curve', 'purpose', 'x', 'y'} | ({'d'} if private else set())
    if (set(item) != expected or type(item['version']) is not int or item['version'] != 1
            or item['curve'] != 'P-256' or item['purpose'] != purpose):
        raise ValueError('Formato, curva o propósito de clave incorrecto')
    point = (int.from_bytes(unhex(item['x'], 32), 'big'), int.from_bytes(unhex(item['y'], 32), 'big'))
    P256.validate_public(point)
    if not private:
        return point
    scalar = int.from_bytes(unhex(item['d'], 32), 'big')
    validate_private(scalar)
    if public_key(scalar) != point:
        raise ValueError('La clave pública no corresponde a la privada')
    return scalar


def encode_signature(signature) -> bytes:
    if not isinstance(signature, tuple) or len(signature) != 2:
        raise ValueError('Firma inválida')
    if any(type(x) is not int or not 1 <= x < P256.n for x in signature):
        raise ValueError('Escalares de firma fuera de rango')
    return b''.join(x.to_bytes(32, 'big') for x in signature)


def decode_signature(raw: bytes) -> tuple[int, int]:
    if len(raw) != 64:
        raise ValueError('La firma debe tener 64 bytes')
    result = int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')
    encode_signature(result)
    return result


def signature_der(signature) -> bytes:
    encode_signature(signature)
    return sequence(*(integer(x) for x in signature))


def decode_signature_der(raw: bytes) -> tuple[int, int]:
    reader = Reader(raw)
    body, _ = reader.read(0x30)
    reader.done()
    values = Reader(body)
    result = tuple(decode_integer(values.read(2)[0]) for _ in range(2))
    values.done()
    encode_signature(result)
    return result


def pem(label: str, data: bytes) -> bytes:
    encoded = base64.b64encode(data)
    return (f'-----BEGIN {label}-----\n'.encode() + b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))
            + f'\n-----END {label}-----\n'.encode())


def public_der(point) -> bytes:
    return sequence(EC_ALGORITHM, tlv(3, b'\0' + point_bytes(point)))


def public_pem(point) -> bytes:
    return pem('PUBLIC KEY', public_der(point))
