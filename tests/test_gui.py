"""Pruebas de las operaciones de la interfaz gráfica Tkinter simplificada."""
from pathlib import Path
import tempfile
import tkinter as tk
import unittest

from ecc_engine import gui


class GUIOperationsTests(unittest.TestCase):
    def test_gui_crypto_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            alicia = gui.op_keygen(d / 'alicia', 'sign')
            bob = gui.op_keygen(d / 'bob', 'exchange')
            self.assertNotIn('d', alicia)
            with self.assertRaises(FileExistsError):
                gui.op_keygen(d / 'alicia', 'sign')

            exported = gui.op_export_public(alicia['public_path'], d / 'alicia.spki.pem')
            self.assertTrue(exported['output_path'].is_file())

            msg = d / 'mensaje.txt'
            msg.write_text('Prueba GUI ELC107', encoding='utf-8')
            sig = gui.op_sign(alicia['private_path'], msg, d / 'firma.json')
            self.assertTrue(gui.op_verify(msg, sig['output_path'], 'public', public_path=alicia['public_path'])['valid'])

            ca = gui.op_ca_init(d / 'pki', 'CA Test')
            cert = gui.op_cert_issue(ca['private_path'], ca['cert_path'], alicia['public_path'], 'alicia', 30, d / 'alicia.pem')
            self.assertTrue(gui.op_cert_verify(cert['output_path'], ca['cert_path'], 'alicia')['valid'])
            with self.assertRaises(ValueError):
                gui.op_cert_verify(cert['output_path'], ca['cert_path'], 'mallory')

            env = gui.op_encrypt(bob['public_path'], alicia['private_path'], msg, d / 'sobre.json', 'ELC107')
            dec = gui.op_decrypt(
                bob['private_path'], env['output_path'], d / 'recuperado.txt',
                'cert', cert_path=cert['output_path'], ca_path=ca['cert_path'], expect_name='alicia',
            )
            self.assertEqual(dec['output_path'].read_text(encoding='utf-8'), 'Prueba GUI ELC107')

    def test_gui_curve_attack_and_compare(self):
        curve_res = gui.op_curve_calc(17, 2, 2, 5, 1, 19, 3, 5)
        self.assertTrue(curve_res['cancel_is_inf'])
        self.assertTrue(curve_res['order_is_inf'])

        atk = gui.op_nonce_attack(123456789, 987654321, 'uno', 'dos')
        self.assertTrue(atk['matched'])
        self.assertTrue(atk['rfc6979_distinct'])

        cmp_res = gui.op_compare_rsa(1024, 1)
        self.assertEqual(cmp_res['ec_sig_bytes'], 64)
        self.assertEqual(cmp_res['rsa_sig_bytes'], 128)

    def test_tkinter_window_instantiation_smoke(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest('Entorno sin pantalla gráfica para instanciar Tk')
        try:
            root.withdraw()
            app = gui.ECCEngineApp(root)
            root.update_idletasks()
            self.assertEqual(len(app.notebook.tabs()), 5)
            app._do_curve()
            app._do_attack()
            root.update_idletasks()
        finally:
            root.destroy()


if __name__ == '__main__':
    unittest.main()
