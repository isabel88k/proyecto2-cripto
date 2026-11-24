"""X.509 v3 real, perfil cerrado P-256 con raíz local y una hoja.

No sustituye un validador PKIX general: no CRL/OCSP, SAN, políticas,
intermedias ni certificados arbitrarios. El nombre es una identidad local CN.
"""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from secrets import randbits
from .der import (Reader, sequence, integer, decode_integer, tlv,
                  EC_ALGORITHM, SIGN_ALGORITHM)
from .encoding import (public_der, point_bytes, decode_point, signature_der,
                       decode_signature_der, pem)
from .ecc import public_key
from .ecdsa import sign, verify
from .hashes import sha256


def _name(name: str) -> bytes:
    if (not isinstance(name, str) or not 1 <= len(name) <= 64
            or len(name.encode('utf-8')) > 128 or any(ord(x) < 32 or ord(x) == 127 for x in name)):
        raise ValueError('CN debe tener 1..64 caracteres sin controles')
    return sequence(tlv(0x31, sequence(tlv(6, bytes.fromhex('550403')), tlv(0x0c, name.encode('utf-8')))))


def _parse_name(raw: bytes) -> str:
    reader = Reader(raw)
    body = Reader(reader.read(0x30)[0])
    reader.done()
    rdn = Reader(body.read(0x31)[0])
    body.done()
    pair = Reader(rdn.read(0x30)[0])
    rdn.done()
    if pair.read(6)[0] != bytes.fromhex('550403'):
        raise ValueError('Solo se admite CN en este perfil')
    try:
        name = pair.read(0x0c)[0].decode('utf-8')
    except UnicodeError as error:
        raise ValueError('CN UTF-8 inválido') from error
    pair.done()
    if _name(name) != raw:
        raise ValueError('Nombre fuera del perfil')
    return name


def _time(value: datetime) -> bytes:
    if value.tzinfo is None:
        raise ValueError('Se requiere fecha con zona horaria')
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    if not 1950 <= value.year <= 9999:
        raise ValueError('Año fuera de rango')
    return (tlv(0x17, value.strftime('%y%m%d%H%M%SZ').encode()) if value.year < 2050
            else tlv(0x18, value.strftime('%Y%m%d%H%M%SZ').encode()))


def _parse_time(raw: bytes) -> datetime:
    reader = Reader(raw)
    body, _ = reader.read()
    reader.done()
    tag = raw[0]
    if tag not in (0x17, 0x18):
        raise ValueError('Fecha ASN.1 inválida')
    try:
        text = body.decode('ascii')
        if tag == 0x17:
            if len(text) != 13:
                raise ValueError('UTCTime inválido')
            year = int(text[:2])
            text = str(1900+year if year >= 50 else 2000+year) + text[2:]
        value = datetime.strptime(text, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    except (UnicodeError, ValueError) as error:
        raise ValueError('Fecha ASN.1 inválida') from error
    if _time(value) != raw:
        raise ValueError('Fecha ASN.1 no canónica')
    return value


def _key_id(point) -> bytes:
    # RFC 5280 permite otros métodos únicos de generación de identificadores.
    return sha256(point_bytes(point))[:20]


def _extension(oid: str, content: bytes, critical=False) -> bytes:
    return sequence(tlv(6, bytes.fromhex(oid)), *( [tlv(1, b'\xff')] if critical else []), tlv(4, content))


def _extensions(ca: bool, subject_id: bytes, authority_id: bytes) -> bytes:
    basic = sequence(tlv(1, b'\xff'), integer(0)) if ca else sequence()
    usage = tlv(3, b'\x01\x06' if ca else b'\x07\x80')
    return tlv(0xa3, sequence(_extension('551d13', basic, True),
                              _extension('551d0f', usage, True),
                              _extension('551d0e', tlv(4, subject_id)),
                              _extension('551d23', sequence(tlv(0x80, authority_id)))))


def create_certificate(subject_public, subject: str, issuer: str, issuer_private: int,
                       not_before: datetime, not_after: datetime, ca=False) -> bytes:
    if not_before.tzinfo is None or not_after.tzinfo is None:
        raise ValueError('Intervalo de validez inválido')
    not_before = not_before.astimezone(timezone.utc).replace(microsecond=0)
    not_after = not_after.astimezone(timezone.utc).replace(microsecond=0)
    if not_before >= not_after:
        raise ValueError('Intervalo de validez inválido')
    if ca and (subject != issuer or subject_public != public_key(issuer_private)):
        raise ValueError('El perfil solo permite CA raíz autofirmada')
    tbs = sequence(tlv(0xa0, integer(2)), integer(randbits(159) | 1), SIGN_ALGORITHM,
                   _name(issuer), sequence(_time(not_before), _time(not_after)),
                   _name(subject), public_der(subject_public),
                   _extensions(ca, _key_id(subject_public), _key_id(public_key(issuer_private))))
    return sequence(tbs, SIGN_ALGORITHM, tlv(3, b'\0' + signature_der(sign(issuer_private, tbs))))


def pem_certificate(der: bytes) -> bytes:
    return pem('CERTIFICATE', der)


@dataclass(frozen=True)
class Certificate:
    tbs: bytes
    signature: tuple[int, int]
    subject: str
    issuer: str
    public: tuple[int, int]
    not_before: datetime
    not_after: datetime
    ca: bool
    subject_id: bytes
    authority_id: bytes


def parse_certificate(data: bytes) -> Certificate:
    if len(data) > 65536:
        raise ValueError('Certificado demasiado grande')
    if data.startswith(b'-----BEGIN CERTIFICATE-----'):
        lines = data.strip().splitlines()
        if lines[0] != b'-----BEGIN CERTIFICATE-----' or lines[-1] != b'-----END CERTIFICATE-----':
            raise ValueError('PEM inválido')
        try:
            data = base64.b64decode(b''.join(lines[1:-1]), validate=True)
        except ValueError as error:
            raise ValueError('PEM inválido') from error
    top = Reader(data)
    cert = Reader(top.read(0x30)[0])
    top.done()
    tbs_body, tbs = cert.read(0x30)
    if cert.read(0x30)[1] != SIGN_ALGORITHM:
        raise ValueError('Algoritmo de firma fuera del perfil')
    sig_bits = cert.read(3)[0]
    cert.done()
    if not sig_bits or sig_bits[0] != 0:
        raise ValueError('BIT STRING de firma inválido')
    signature = decode_signature_der(sig_bits[1:])
    body = Reader(tbs_body)
    if body.read(0xa0)[0] != integer(2):
        raise ValueError('Se requiere X.509 v3')
    serial = body.read(2)[0]
    if not 0 < decode_integer(serial) < 1 << 159 or len(serial) > 20:
        raise ValueError('Serial inválido')
    if body.read(0x30)[1] != SIGN_ALGORITHM:
        raise ValueError('Algoritmos interno y externo no coinciden')
    issuer = _parse_name(body.read(0x30)[1])
    validity = Reader(body.read(0x30)[0])
    not_before = _parse_time(validity.read()[1])
    not_after = _parse_time(validity.read()[1])
    validity.done()
    if not_before >= not_after:
        raise ValueError('Validez vacía')
    subject = _parse_name(body.read(0x30)[1])
    spki = Reader(body.read(0x30)[0])
    if spki.read(0x30)[1] != EC_ALGORITHM:
        raise ValueError('SPKI fuera del perfil P-256')
    bits = spki.read(3)[0]
    spki.done()
    if not bits or bits[0] != 0:
        raise ValueError('Clave pública mal codificada')
    public = decode_point(bits[1:])
    extensions_raw = body.read(0xa3)[1]
    body.done()
    wrapper = Reader(extensions_raw)
    ext_wrapper = Reader(wrapper.read(0xa3)[0])
    wrapper.done()
    ext_list = Reader(ext_wrapper.read(0x30)[0])
    ext_wrapper.done()
    extensions = {}
    while ext_list.position < len(ext_list.data):
        ext = Reader(ext_list.read(0x30)[0])
        oid = ext.read(6)[0].hex()
        if oid in extensions:
            raise ValueError('Extensión repetida')
        content, raw = ext.read()
        critical = False
        if raw[0] == 1:
            if content != b'\xff':
                raise ValueError('Boolean DER inválido')
            critical = True
            content, raw = ext.read(4)
        if raw[0] != 4:
            raise ValueError('Extensión mal codificada')
        ext.done()
        extensions[oid] = critical, content
    if set(extensions) != {'551d13', '551d0f', '551d0e', '551d23'}:
        raise ValueError('Extensiones fuera del perfil cerrado')
    ca = extensions['551d13'] == (True, sequence(tlv(1, b'\xff'), integer(0)))
    ski = Reader(extensions['551d0e'][1])
    subject_id = ski.read(4)[0]
    ski.done()
    aki = Reader(extensions['551d23'][1])
    akiseq = Reader(aki.read(0x30)[0])
    aki.done()
    authority_id = akiseq.read(0x80)[0]
    akiseq.done()
    if (len(subject_id) != 20 or len(authority_id) != 20 or subject_id != _key_id(public)
            or extensions_raw != _extensions(ca, subject_id, authority_id)):
        raise ValueError('BasicConstraints, KeyUsage o identificadores inválidos')
    return Certificate(tbs, signature, subject, issuer, public, not_before, not_after, ca,
                       subject_id, authority_id)


def verify_certificate(leaf_data: bytes, trusted_root: bytes, expected_name: str,
                       now: datetime | None = None):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Se requiere fecha con zona horaria')
    root, leaf = parse_certificate(trusted_root), parse_certificate(leaf_data)
    if (not root.ca or root.subject != root.issuer or root.subject_id != root.authority_id
            or not verify(root.public, root.tbs, root.signature)):
        raise ValueError('La raíz de confianza no es una CA válida')
    for cert in (root, leaf):
        if not cert.not_before <= now <= cert.not_after:
            raise ValueError('Certificado vencido o aún no vigente')
    if (leaf.ca or leaf.subject != expected_name or leaf.issuer != root.subject
            or leaf.authority_id != root.subject_id or not verify(root.public, leaf.tbs, leaf.signature)):
        raise ValueError('Identidad, emisor o firma de certificado inválida')
    return leaf.public
