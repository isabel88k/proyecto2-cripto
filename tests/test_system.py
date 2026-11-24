import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from ecc_engine.ecc import public_key, P256
from ecc_engine.encoding import (key_record, read_key, save_json, load_json,
                                 encode_signature, signature_der, public_pem)
from ecc_engine.hybrid import seal, open_envelope
from ecc_engine.pki import create_certificate, verify_certificate, pem_certificate, parse_certificate


class EncodingTests(unittest.TestCase):
    def test_key_roundtrip_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'key.json'
            save_json(path, key_record(7, 'sign', private=True), private=True)
            self.assertEqual(read_key(path, 'sign', private=True), 7)
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                save_json(path, {})
            with self.assertRaises(ValueError):
                read_key(path, 'exchange', private=True)
            item = load_json(path)
            item['x'] = '00'*32
            path.unlink()
            save_json(path, item)
            with self.assertRaises(ValueError):
                read_key(path, 'sign', private=True)

    def test_duplicate_keys_and_oversized_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.json'
            path.write_text('{"x":1,"x":2}')
            with self.assertRaises(ValueError):
                load_json(path)
            path.write_bytes(b' '*(3*1024*1024+1))
            with self.assertRaises(ValueError):
                load_json(path)


class HybridTests(unittest.TestCase):
    def test_malleated_signature_is_rejected(self):
        from ecc_engine.encoding import decode_signature, unhex
        envelope = seal(public_key(11), 7, b'contenido')
        r, s = decode_signature(unhex(envelope['signature'], 64))
        self.assertLessEqual(s, P256.n//2)
        envelope['signature'] = encode_signature((r, P256.n-s)).hex()
        with self.assertRaises(ValueError):
            open_envelope(11, public_key(7), envelope)

    def test_invalid_gcm_tag_with_valid_outer_signature(self):
        from ecc_engine.encoding import canonical
        from ecc_engine.ecdsa import sign
        envelope = seal(public_key(11), 7, b'contenido', b'AAD')
        envelope['tag'] = '00'*16
        unsigned = {k: v for k, v in envelope.items() if k != 'signature'}
        r, s = sign(7, b'ELC107-ENVELOPE-v1\0'+canonical(unsigned))
        envelope['signature'] = encode_signature((r, min(s, P256.n-s))).hex()
        with self.assertRaisesRegex(ValueError, 'GCM'):
            open_envelope(11, public_key(7), envelope)

    def test_empty_binary_roundtrip(self):
        for message in (b'', bytes(range(256)) + 'Criptografía'.encode()):
            envelope = seal(public_key(11), 7, message, b'ELC107')
            self.assertEqual(open_envelope(11, public_key(7), envelope), message)
            other = seal(public_key(11), 7, message, b'ELC107')
            self.assertNotEqual(envelope['ephemeral'], other['ephemeral'])
            self.assertNotEqual(envelope['nonce'], other['nonce'])

    def test_every_authenticated_field_rejects_tampering(self):
        original = seal(public_key(11), 7, b'confidencial', b'cabecera')
        for field in original:
            bad = copy.deepcopy(original)
            bad[field] = 2 if field == 'version' else ('00' if bad[field] != '00' else '01')
            with self.subTest(field=field), self.assertRaises(ValueError):
                open_envelope(11, public_key(7), bad)
        for private, sender in ((12, public_key(7)), (11, public_key(8))):
            with self.assertRaises(ValueError):
                open_envelope(private, sender, original)
        bad = dict(original, unknown='injected')
        with self.assertRaises(ValueError):
            open_envelope(11, public_key(7), bad)
        with self.assertRaises(ValueError):
            seal(public_key(11), 7, b'x'*(1024*1024+1))


class PKITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime(2026, 11, 24, tzinfo=timezone.utc)
        cls.root = create_certificate(public_key(3), 'CA ELC107', 'CA ELC107', 3,
                                      cls.now-timedelta(days=1), cls.now+timedelta(days=365), ca=True)
        cls.leaf = create_certificate(public_key(7), 'alicia', 'CA ELC107', 3,
                                      cls.now-timedelta(days=1), cls.now+timedelta(days=30))

    def test_real_certificate_and_trust(self):
        self.assertEqual(verify_certificate(self.leaf, self.root, 'alicia', self.now), public_key(7))
        self.assertEqual(parse_certificate(pem_certificate(self.leaf)).subject, 'alicia')
        for name, when in (('mallory', self.now), ('alicia', self.now+timedelta(days=31))):
            with self.assertRaises(ValueError):
                verify_certificate(self.leaf, self.root, name, when)
        wrong = create_certificate(public_key(5), 'CA ELC107', 'CA ELC107', 5,
                                    self.now-timedelta(days=1), self.now+timedelta(days=365), ca=True)
        with self.assertRaises(ValueError):
            verify_certificate(self.leaf, wrong, 'alicia', self.now)
        with self.assertRaises(ValueError):
            verify_certificate(self.leaf, self.leaf, 'alicia', self.now)

    def test_malformed_and_tampered_der(self):
        for data in (self.leaf[:-1], self.leaf+b'\0', b'\x30\x80\0\0',
                     self.leaf[:20] + bytes([self.leaf[20] ^ 1]) + self.leaf[21:]):
            with self.assertRaises(ValueError):
                verify_certificate(data, self.root, 'alicia', self.now)

    def test_rejects_interval_collapsing_at_der_precision(self):
        with self.assertRaises(ValueError):
            create_certificate(public_key(7), 'alicia', 'CA ELC107', 3,
                               self.now+timedelta(microseconds=1), self.now+timedelta(microseconds=2))

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL opcional para interoperabilidad')
    def test_openssl_validates_x509_and_ecdsa(self):
        from ecc_engine.ecdsa import sign
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'root.pem'
            leaf = Path(directory)/'leaf.pem'
            root.write_bytes(pem_certificate(self.root))
            leaf.write_bytes(pem_certificate(self.leaf))
            verified = subprocess.run(['openssl', 'verify', '-attime', str(int(self.now.timestamp())),
                                       '-CAfile', str(root), str(leaf)], capture_output=True)
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())
            pub, sig, msg = (Path(directory)/name for name in ('pub.pem', 'sig.der', 'message'))
            pub.write_bytes(public_pem(public_key(7)))
            msg.write_bytes(b'ELC107')
            sig.write_bytes(signature_der(sign(7, b'ELC107')))
            checked = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(pub),
                                      '-signature', str(sig), str(msg)], capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())


class CLITests(unittest.TestCase):
    def command(self, *args):
        return subprocess.run([sys.executable, '-m', 'ecc_engine', *map(str, args)],
                              capture_output=True, text=True)

    @unittest.skipUnless(os.name == 'posix', 'Prueba de enlace simbólico POSIX')
    def test_keygen_and_ca_rollback_when_second_path_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for command, public, private, arguments in (
                ('keygen', d/'alice.public.json', d/'alice.private.json',
                 ['--prefix', d/'alice', '--purpose', 'sign']),
                ('ca-init', d/'ca.pem', d/'ca.private.json', ['--out', d])):
                public.symlink_to(d/'missing-target')
                result = self.command(command, *arguments)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(private.exists(), f'Clave privada huérfana tras fallo en {command}')
                self.assertTrue(public.is_symlink())
                public.unlink()

    def test_cli_sign_encrypt_and_no_output_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for name, purpose in (('alice', 'sign'), ('bob', 'exchange')):
                result = self.command('keygen', '--prefix', d/name, '--purpose', purpose)
                self.assertEqual(result.returncode, 0, result.stderr)
            source = d/'message'
            source.write_bytes(b'ELC107')
            signature = d/'signature.json'
            self.assertEqual(self.command('sign', '--key', d/'alice.private.json',
                            '--input', source, '--output', signature).returncode, 0)
            self.assertEqual(self.command('verify', '--public', d/'alice.public.json',
                            '--input', source, '--signature', signature).returncode, 0)
            env = d/'envelope.json'
            encrypted = self.command('encrypt', '--recipient', d/'bob.public.json',
                      '--sign-key', d/'alice.private.json', '--input', source, '--output', env)
            self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
            out = d/'clear'
            decrypted = self.command('decrypt', '--key', d/'bob.private.json',
                        '--sender', d/'alice.public.json', '--input', env, '--output', out)
            self.assertEqual(decrypted.returncode, 0, decrypted.stderr)
            self.assertEqual(out.read_bytes(), b'ELC107')
            existing_out = self.command('decrypt', '--key', d/'bob.private.json',
                        '--sender', d/'alice.public.json', '--input', env, '--output', out)
            self.assertEqual(existing_out.returncode, 1)
            self.assertEqual(out.read_bytes(), b'ELC107')
            source.write_bytes(b'alterado')
            self.assertEqual(self.command('verify', '--public', d/'alice.public.json',
                         '--input', source, '--signature', signature).returncode, 1)
            content = json.loads(env.read_text())
            content['tag'] = '00'*16
            env.write_text(json.dumps(content))
            out.unlink()
            failed = self.command('decrypt', '--key', d/'bob.private.json',
                     '--sender', d/'alice.public.json', '--input', env, '--output', out)
            self.assertEqual(failed.returncode, 1)
            self.assertFalse(out.exists())
            self.assertNotIn('Traceback', failed.stderr)
            existing = self.command('keygen', '--prefix', d/'alice', '--purpose', 'sign')
            self.assertEqual(existing.returncode, 1)


if __name__ == '__main__':
    unittest.main()
