import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ToolTests(unittest.TestCase):
    def test_benchmark_rejects_colliding_output_names_before_work(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'benchmark.csv'
            result = subprocess.run([sys.executable, str(ROOT/'scripts/benchmark.py'),
                      '--rsa-bits', '1024', '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_reused_nonce_recovers_private_key(self):
        result = subprocess.run([sys.executable, str(ROOT/'scripts/nonce_attack.py')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RECUPERADA', result.stdout)

    def test_benchmark_outputs_measured_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'benchmark.json'
            result = subprocess.run([sys.executable, str(ROOT/'scripts/benchmark.py'),
                      '--rsa-bits', '1024', '--samples', '2', '--keygen-samples', '1',
                      '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data['rsa_bits'], 1024)
            self.assertEqual(len(data['measurements']), 18)
            for row in data['measurements']:
                self.assertGreater(row['median_ms'], 0)
                self.assertEqual(len(row['samples_ms']), row['samples'])

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL opcional')
    def test_rsa_pss_openssl_verification(self):
        from ecc_engine.rsa import generate_key, pss_sign
        from ecc_engine.der import sequence, integer, tlv
        from ecc_engine.encoding import pem
        key = generate_key(1024)
        spki = sequence(sequence(tlv(6, bytes.fromhex('2a864886f70d010101')), tlv(5, b'')),
                        tlv(3, b'\0'+sequence(integer(key.n), integer(key.e))))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory/'public.pem').write_bytes(pem('PUBLIC KEY', spki))
            (directory/'signature').write_bytes(pss_sign(key, b'ELC107'))
            (directory/'message').write_bytes(b'ELC107')
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(directory/'public.pem'),
                     '-signature', str(directory/'signature'), '-sigopt', 'rsa_padding_mode:pss',
                     '-sigopt', 'rsa_pss_saltlen:32', str(directory/'message')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
