"""CLI sin dependencias externas; errores controlados con estado no cero."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from .ecc import generate_private, public_key
from .ecdsa import sign, verify
from .encoding import (read_key, key_record, load_json, save_json, read_bytes,
                       write_bytes, write_pair, canonical, encode_signature, decode_signature, unhex, public_pem)
from .hybrid import seal, open_envelope
from .pki import create_certificate, verify_certificate, parse_certificate, pem_certificate


def _identity(args):
    certificate = getattr(args, 'cert', None)
    if certificate:
        if not args.ca or not args.expect_name:
            raise ValueError('--cert requiere --ca y --expect-name')
        return verify_certificate(read_bytes(certificate, 65536), read_bytes(args.ca, 65536), args.expect_name)
    if getattr(args, 'ca', None) or getattr(args, 'expect_name', None):
        raise ValueError('--ca y --expect-name requieren --cert')
    return read_key(getattr(args, 'public', None) or getattr(args, 'sender', None), 'sign')


def _identity_options(parser, public_flag):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(public_flag, type=Path)
    group.add_argument('--cert', type=Path)
    parser.add_argument('--ca', type=Path)
    parser.add_argument('--expect-name')


def build_parser():
    parser = argparse.ArgumentParser(
        description='Motor académico ECC/ECDSA - ELC107 (Python puro; use "gui" o cripto_gui.py para la interfaz gráfica)'
    )
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('gui', help='Abrir interfaz gráfica de escritorio (Tkinter)')
    keygen = sub.add_parser('keygen', help='Crear par P-256 con propósito independiente')
    keygen.add_argument('--prefix', type=Path, required=True)
    keygen.add_argument('--purpose', choices=['sign', 'exchange'], required=True)
    signing = sub.add_parser('sign', help='Firmar archivo con ECDSA/SHA256')
    signing.add_argument('--key', type=Path, required=True)
    signing.add_argument('--input', type=Path, required=True)
    signing.add_argument('--output', type=Path, required=True)
    verification = sub.add_parser('verify', help='Verificar firma con clave fijada o certificado')
    _identity_options(verification, '--public')
    verification.add_argument('--input', type=Path, required=True)
    verification.add_argument('--signature', type=Path, required=True)
    enc = sub.add_parser('encrypt', help='Cifrar y firmar sobre ECDH/HKDF/AES-GCM')
    enc.add_argument('--recipient', type=Path, required=True)
    enc.add_argument('--sign-key', type=Path, required=True)
    enc.add_argument('--input', type=Path, required=True)
    enc.add_argument('--output', type=Path, required=True)
    enc.add_argument('--aad', default='ELC107')
    dec = sub.add_parser('decrypt', help='Verificar y autenticar antes de escribir texto plano')
    _identity_options(dec, '--sender')
    dec.add_argument('--key', type=Path, required=True)
    dec.add_argument('--input', type=Path, required=True)
    dec.add_argument('--output', type=Path, required=True)
    ca = sub.add_parser('ca-init', help='Crear CA raíz local, no publicar su clave privada')
    ca.add_argument('--out', type=Path, required=True)
    ca.add_argument('--name', default='CA ELC107')
    issue = sub.add_parser('cert-issue', help='Emitir certificado de firma desde CA local')
    for name in ('ca-key', 'ca-cert', 'public', 'output'):
        issue.add_argument('--'+name, type=Path, required=True)
    issue.add_argument('--name', required=True)
    issue.add_argument('--days', type=int, default=30)
    check = sub.add_parser('cert-verify', help='Verificar perfil X.509 y nombre esperado')
    for name in ('cert', 'ca'):
        check.add_argument('--'+name, type=Path, required=True)
    check.add_argument('--expect-name', required=True)
    export = sub.add_parser('export-public', help='Exportar SPKI PEM para verificación externa')
    export.add_argument('--public', type=Path, required=True)
    export.add_argument('--output', type=Path, required=True)
    return parser


def main(argv=None) -> int:
    raw_args = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    if not raw_args:
        parser.print_help()
        return 0
    args = parser.parse_args(raw_args)
    if args.command == 'gui':
        from .gui import launch_gui
        return launch_gui()
    try:
        if args.command == 'keygen':
            private_path = Path(str(args.prefix)+'.private.json')
            public_path = Path(str(args.prefix)+'.public.json')
            if private_path.exists() or public_path.exists():
                raise FileExistsError('Ya existe uno de los archivos de claves')
            private = generate_private()
            write_pair(private_path, canonical(key_record(private, args.purpose, True))+b'\n',
                       public_path, canonical(key_record(private, args.purpose))+b'\n')
            print(f'Claves {args.purpose}: {private_path}, {public_path}')
        elif args.command == 'sign':
            signature = sign(read_key(args.key, 'sign', True), read_bytes(args.input))
            save_json(args.output, {'version': 1, 'algorithm': 'ECDSA-P256-SHA256',
                                   'signature': encode_signature(signature).hex()})
            print(f'Firma creada: {args.output}')
        elif args.command == 'verify':
            item = load_json(args.signature)
            if (set(item) != {'version', 'algorithm', 'signature'} or type(item['version']) is not int
                    or item['version'] != 1 or item['algorithm'] != 'ECDSA-P256-SHA256'):
                raise ValueError('Formato de firma no admitido')
            valid = verify(_identity(args), read_bytes(args.input), decode_signature(unhex(item['signature'], 64)))
            print('Firma VÁLIDA' if valid else 'Firma INVÁLIDA')
            return 0 if valid else 1
        elif args.command == 'encrypt':
            envelope = seal(read_key(args.recipient, 'exchange'), read_key(args.sign_key, 'sign', True),
                            read_bytes(args.input), args.aad.encode('utf-8'))
            save_json(args.output, envelope)
            print(f'Sobre cifrado y firmado: {args.output}')
        elif args.command == 'decrypt':
            plaintext = open_envelope(read_key(args.key, 'exchange', True), _identity(args), load_json(args.input))
            write_bytes(args.output, plaintext, private=True)
            print(f'Firma y GCM válidos; archivo recuperado: {args.output}')
        elif args.command == 'ca-init':
            args.out.mkdir(parents=True, exist_ok=True)
            private_path, certificate_path = args.out/'ca.private.json', args.out/'ca.pem'
            if private_path.exists() or certificate_path.exists():
                raise FileExistsError('La CA ya existe')
            private, now = generate_private(), datetime.now(timezone.utc)
            certificate = create_certificate(public_key(private), args.name, args.name, private,
                                             now-timedelta(minutes=5), now+timedelta(days=365), ca=True)
            write_pair(private_path, canonical(key_record(private, 'sign', True))+b'\n',
                       certificate_path, pem_certificate(certificate))
            print(f'CA local creada: {certificate_path}')
        elif args.command == 'cert-issue':
            private = read_key(args.ca_key, 'sign', True)
            ca_bytes = read_bytes(args.ca_cert, 65536)
            root = parse_certificate(ca_bytes)
            now = datetime.now(timezone.utc)
            if not 1 <= args.days <= 365 or root.public != public_key(private):
                raise ValueError('Días inválidos o clave de CA incorrecta')
            after = min(now+timedelta(days=args.days), root.not_after)
            certificate = create_certificate(read_key(args.public, 'sign'), args.name, root.subject,
                                             private, max(now-timedelta(minutes=5), root.not_before), after)
            verify_certificate(certificate, ca_bytes, args.name)
            write_bytes(args.output, pem_certificate(certificate))
            print(f'Certificado emitido: {args.output}')
        elif args.command == 'cert-verify':
            verify_certificate(read_bytes(args.cert, 65536), read_bytes(args.ca, 65536), args.expect_name)
            print('Certificado VÁLIDO para la identidad esperada')
        elif args.command == 'export-public':
            write_bytes(args.output, public_pem(read_key(args.public, 'sign')))
            print(f'SPKI PEM exportado: {args.output}')
        return 0
    except (ValueError, TypeError, OSError, OverflowError, KeyError, RecursionError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
