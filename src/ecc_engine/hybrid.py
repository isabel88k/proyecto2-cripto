"""Sobre académico autenticado: ECDH + HKDF + AES-GCM + ECDSA.

No es un formato estandarizado ECIES/HPKE. La confianza del emisor procede
de una clave fijada o un certificado validado FUERA del sobre.
"""
from secrets import token_bytes, compare_digest
from .ecc import P256, generate_private, public_key, ecdh
from .hashes import sha256, hkdf
from .ecdsa import sign, verify
from .gcm import encrypt, decrypt
from .encoding import (canonical, point_bytes, decode_point, encode_signature,
                       decode_signature, unhex, MAX_DATA)

SUITE = 'P256-HKDF-SHA256-AES128GCM-ECDSA-SHA256'
_HEADER = {'version', 'suite', 'ephemeral', 'recipient_id', 'sender_id', 'salt', 'nonce', 'aad'}
_FIELDS = _HEADER | {'ciphertext', 'tag', 'signature'}
_DOMAIN = b'ELC107-ENVELOPE-v1\0'


def fingerprint(point) -> str:
    return sha256(point_bytes(point)).hex()


def seal(recipient, signing_private: int, plaintext: bytes, aad: bytes = b'') -> dict:
    if len(plaintext) > MAX_DATA or len(aad) > 65536:
        raise ValueError('Mensaje o AAD demasiado grande')
    ephemeral_private = generate_private()
    header = {'version': 1, 'suite': SUITE, 'ephemeral': point_bytes(public_key(ephemeral_private)).hex(),
              'recipient_id': fingerprint(recipient), 'sender_id': fingerprint(public_key(signing_private)),
              'salt': token_bytes(32).hex(), 'nonce': token_bytes(12).hex(), 'aad': aad.hex()}
    context = _DOMAIN + canonical(header)
    key = hkdf(ecdh(ephemeral_private, recipient), bytes.fromhex(header['salt']), context, 16)
    ciphertext, tag = encrypt(key, bytes.fromhex(header['nonce']), plaintext, context)
    body = dict(header, ciphertext=ciphertext.hex(), tag=tag.hex())
    r, s = sign(signing_private, _DOMAIN + canonical(body))
    body['signature'] = encode_signature((r, min(s, P256.n-s))).hex()
    return body


def open_envelope(recipient_private: int, trusted_sender, envelope: dict) -> bytes:
    if (not isinstance(envelope, dict) or set(envelope) != _FIELDS
            or type(envelope['version']) is not int or envelope['version'] != 1
            or envelope['suite'] != SUITE):
        raise ValueError('Sobre fuera del perfil admitido')
    # Validación de estructura y tamaño antes de operaciones criptográficas.
    for name, size in (('salt', 32), ('nonce', 12), ('tag', 16), ('recipient_id', 32), ('sender_id', 32)):
        unhex(envelope[name], size)
    ephemeral = decode_point(unhex(envelope['ephemeral'], 65))
    signature = decode_signature(unhex(envelope['signature'], 64))
    if signature[1] > P256.n//2:
        raise ValueError('La firma del sobre debe tener representación canónica low-S')
    ciphertext = unhex(envelope['ciphertext'])
    unhex(envelope['aad'], maximum=65536)
    if (not compare_digest(envelope['recipient_id'], fingerprint(public_key(recipient_private)))
            or not compare_digest(envelope['sender_id'], fingerprint(trusted_sender))):
        raise ValueError('Identidad de emisor o receptor incorrecta')
    unsigned = {name: value for name, value in envelope.items() if name != 'signature'}
    if not verify(trusted_sender, _DOMAIN + canonical(unsigned), signature):
        raise ValueError('Firma del sobre inválida')
    header = {name: envelope[name] for name in _HEADER}
    context = _DOMAIN + canonical(header)
    key = hkdf(ecdh(recipient_private, ephemeral), unhex(envelope['salt'], 32), context, 16)
    return decrypt(key, unhex(envelope['nonce'], 12), ciphertext, unhex(envelope['tag'], 16), context)
