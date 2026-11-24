"""Vectores independientes; hashlib solo actúa como oráculo EN LAS PRUEBAS."""
import hashlib
import unittest

from ecc_engine.arithmetic import inverse_mod, is_probable_prime, generate_prime
from ecc_engine.hashes import sha256, hmac_sha256, hkdf
from ecc_engine.ecc import Curve, P256, public_key, ecdh
from ecc_engine.ecdsa import sign, verify, nonce_candidates
from ecc_engine.aes import AES128
from ecc_engine.gcm import encrypt, decrypt
from ecc_engine.rsa import generate_key, pss_sign, pss_verify, mgf1


class ArithmeticTests(unittest.TestCase):
    def test_inverse_and_noninvertible(self):
        self.assertEqual(inverse_mod(-3, 17), 11)
        for a, m in [(0, 17), (2, 4), (1, 0)]:
            with self.assertRaises(ValueError):
                inverse_mod(a, m)

    def test_primality_and_carmichael(self):
        for n in (2, 3, 17, 65537, 2147483647):
            self.assertTrue(is_probable_prime(n))
        for n in (-1, 0, 1, 4, 9, 561, 1105, 1729, 3215031751):
            self.assertFalse(is_probable_prime(n))
        p = generate_prime(32)
        self.assertEqual(p.bit_length(), 32)
        self.assertTrue(is_probable_prime(p))


class HashTests(unittest.TestCase):
    def test_sha256_vectors(self):
        self.assertEqual(sha256(b'abc').hex(),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        for size in (0, 1, 55, 56, 63, 64, 65, 1000):
            data = bytes(i % 256 for i in range(size))
            self.assertEqual(sha256(data), hashlib.sha256(data).digest())

    def test_hmac_rfc4231(self):
        self.assertEqual(hmac_sha256(b'\x0b' * 20, b'Hi There').hex(),
                         'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
        self.assertEqual(hmac_sha256(b'\xaa' * 131,
                         b'Test Using Larger Than Block-Size Key - Hash Key First').hex(),
                         '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54')

    def test_hkdf_rfc5869(self):
        result = hkdf(b'\x0b' * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)
        self.assertEqual(result.hex(), '3cb25f25faacd57a90434f64d0362f2a'
                         '2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
        with self.assertRaises(ValueError):
            hkdf(b'x', b'', b'', 8161)


class ECCTests(unittest.TestCase):
    def setUp(self):
        self.curve = Curve(17, 2, 2, (5, 1), 19)

    def test_toy_group(self):
        c = self.curve
        self.assertEqual(c.add(c.g, c.g), (6, 3))
        self.assertEqual(c.mul(3, c.g), (10, 6))
        self.assertIsNone(c.add(c.g, (5, 16)))
        self.assertEqual(c.add(None, c.g), c.g)
        self.assertIsNone(c.mul(19, c.g))
        self.assertIsNone(c.mul(0, c.g))
        self.assertIsNone(Curve(17, 1, 0, (0, 0), 2).add((0, 0), (0, 0)))

    def test_reject_invalid_points(self):
        for point in ((1, 1), (-1, 2), (17, 1), (True, 1)):
            with self.assertRaises(ValueError):
                self.curve.mul(2, point)
        with self.assertRaises(ValueError):
            Curve(17, 0, 0, (0, 0), 2)
        with self.assertRaises(ValueError):
            self.curve.mul(-1, self.curve.g)
        for scalar in (0, P256.n):
            with self.assertRaises(ValueError):
                public_key(scalar)

    def test_constructor_rejects_incompatible_subgroup_order(self):
        for order in (18, 17, 38):
            with self.subTest(order=order), self.assertRaises(ValueError):
                Curve(17, 2, 2, (5, 1), order)

    def test_p256_generator_and_ecdh(self):
        self.assertIsNone(P256.mul(P256.n, P256.g))
        self.assertEqual(P256.mul(2, P256.g)[0], int(
            '7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978', 16))
        self.assertEqual(ecdh(3, public_key(7)), ecdh(7, public_key(3)))
        with self.assertRaises(ValueError):
            ecdh(3, None)


class ECDSATests(unittest.TestCase):
    D = int('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721', 16)

    def test_rfc6979_p256_sha256_sample(self):
        self.assertEqual(next(nonce_candidates(self.D, sha256(b'sample'))), int(
            'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60', 16))
        expected = (int('EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716', 16),
                    int('F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8', 16))
        self.assertEqual(sign(self.D, b'sample'), expected)
        self.assertTrue(verify(public_key(self.D), b'sample', expected))
        self.assertEqual(sign(self.D, b'sample'), sign(self.D, b'sample'))

    def test_reject_modified_message_key_and_signature(self):
        sig = sign(7, b'mensaje')
        self.assertFalse(verify(public_key(7), b'Mensaje', sig))
        self.assertFalse(verify(public_key(8), b'mensaje', sig))
        for bad in ((0, 1), (1, 0), (P256.n, 1), (-1, 1), (True, 3), (), None):
            self.assertFalse(verify(public_key(7), b'mensaje', bad))
        self.assertFalse(verify(None, b'mensaje', sig))


class SymmetricTests(unittest.TestCase):
    def test_aes128_fips197(self):
        aes = AES128(bytes.fromhex('000102030405060708090a0b0c0d0e0f'))
        self.assertEqual(aes.encrypt_block(bytes.fromhex('00112233445566778899aabbccddeeff')).hex(),
                         '69c4e0d86a7b0430d8cdb78070b4c55a')
        with self.assertRaises(ValueError):
            AES128(b'short')

    def test_gcm_nist_empty_and_block(self):
        key, nonce = bytes(16), bytes(12)
        self.assertEqual(encrypt(key, nonce, b''),
                         (b'', bytes.fromhex('58e2fccefa7e3061367f1d57a4e7455a')))
        c, tag = encrypt(key, nonce, bytes(16))
        self.assertEqual(c.hex(), '0388dace60b6a392f328c2b971b2fe78')
        self.assertEqual(tag.hex(), 'ab6e47d42cec13bdf53a67b21257bddf')
        self.assertEqual(decrypt(key, nonce, c, tag), bytes(16))

    def test_gcm_nist_aad_partial_block(self):
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        nonce = bytes.fromhex('cafebabefacedbaddecaf888')
        aad = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
        plain = bytes.fromhex('d9313225f88406e5a55909c5aff5269a'
                              '86a7a9531534f7da2e4c303d8a318a72'
                              '1c3c0c95956809532fcf0e2449a6b525'
                              'b16aedf5aa0de657ba637b39')
        c, tag = encrypt(key, nonce, plain, aad)
        self.assertEqual(c.hex(), '42831ec2217774244b7221b784d0d49c'
                         'e3aa212f2c02a4e035c17e2329aca12e'
                         '21d514b25466931c7d8f6a5aac84aa05'
                         '1ba30b396a0aac973d58e091')
        self.assertEqual(tag.hex(), '5bc94fbc3221a5db94fae95ae7121a47')
        self.assertEqual(decrypt(key, nonce, c, tag, aad), plain)
        for wrong_c, wrong_tag, wrong_aad in ((c + b'x', tag, aad),
                (c, bytes(16), aad), (c, tag, b'otra cabecera')):
            with self.assertRaises(ValueError):
                decrypt(key, nonce, wrong_c, wrong_tag, wrong_aad)
        with self.assertRaises(ValueError):
            encrypt(key, b'bad', plain)


class RSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_key(1024)  # Solo pruebas; comparación real usa 3072.

    def test_rsa_pss_and_negative_cases(self):
        signature = pss_sign(self.key, b'ELC107')
        self.assertEqual(len(signature), 128)
        self.assertTrue(pss_verify(self.key.public(), b'ELC107', signature))
        self.assertFalse(pss_verify(self.key.public(), b'ELC108', signature))
        for sig in (b'', bytes(128), signature + b'0'):
            self.assertFalse(pss_verify(self.key.public(), b'ELC107', sig))
        self.assertEqual(self.key.n.bit_length(), 1024)
        self.assertEqual((self.key.e * self.key.d) % ((self.key.p-1)*(self.key.q-1)), 1)

    def test_mgf1_independent_hash_oracle(self):
        expected = b''.join(hashlib.sha256(b'seed' + i.to_bytes(4, 'big')).digest()
                            for i in range(3))[:70]
        self.assertEqual(mgf1(b'seed', 70), expected)


if __name__ == '__main__':
    unittest.main()
