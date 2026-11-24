"""Interfaz gráfica simple (Tkinter) para el Motor ECC/ECDSA - ELC107.

Usa solo la biblioteca estándar de Python y delega toda la criptografía en los
módulos propios de ``ecc_engine``. Nunca muestra claves privadas en pantalla.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .arithmetic import inverse_mod
from .ecc import Curve, P256, generate_private, public_key
from .ecdsa import nonce_candidates, sign, verify
from .encoding import (
    canonical,
    decode_signature,
    encode_signature,
    key_record,
    load_json,
    public_pem,
    read_bytes,
    read_key,
    save_json,
    unhex,
    write_bytes,
    write_pair,
)
from .hashes import sha256
from .hybrid import SUITE, fingerprint, open_envelope, seal
from .pki import create_certificate, parse_certificate, pem_certificate, verify_certificate
from .rsa import generate_key as rsa_generate_key, pss_sign, pss_verify


# ---------------------------------------------------------------------------
# Operaciones puras (desacopladas de Tkinter para claridad y pruebas)
# ---------------------------------------------------------------------------

def _resolve_trusted_key(mode: str, public_path: Path | None = None,
                         cert_path: Path | None = None, ca_path: Path | None = None,
                         expect_name: str = ''):
    if mode == 'cert':
        if not cert_path or not ca_path or not expect_name.strip():
            raise ValueError('El modo certificado requiere certificado, CA y CN esperado.')
        return verify_certificate(
            read_bytes(cert_path, 65536), read_bytes(ca_path, 65536), expect_name.strip()
        )
    if not public_path:
        raise ValueError('Seleccione la clave pública confiable (.public.json).')
    return read_key(public_path, 'sign')


def op_keygen(prefix: Path, purpose: str) -> dict:
    if purpose not in ('sign', 'exchange'):
        raise ValueError('El propósito debe ser sign o exchange.')
    if not str(prefix).strip():
        raise ValueError('Indique una ruta base para guardar el par de claves.')
    private_path = Path(f'{prefix}.private.json')
    public_path = Path(f'{prefix}.public.json')
    if private_path.exists() or public_path.exists():
        raise FileExistsError('Ya existe uno de los archivos de claves.')
    private_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter_ns()
    private = generate_private()
    pub = public_key(private)
    write_pair(
        private_path, canonical(key_record(private, purpose, True)) + b'\n',
        public_path, canonical(key_record(private, purpose)) + b'\n',
    )
    return {
        'private_path': private_path,
        'public_path': public_path,
        'purpose': purpose,
        'fingerprint': fingerprint(pub),
        'x': f'{pub[0]:064x}',
        'y': f'{pub[1]:064x}',
        'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
    }


def op_export_public(public_path: Path, output_path: Path) -> dict:
    point = read_key(public_path, 'sign', private=False)
    pem_bytes = public_pem(point)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    write_bytes(output_path, pem_bytes)
    return {'output_path': Path(output_path), 'fingerprint': fingerprint(point)}


def op_curve_calc(p: int, a: int, b: int, gx: int, gy: int, n: int, k: int, m: int) -> dict:
    curve = Curve(p, a, b, (gx, gy), n)
    p_pt = curve.mul(k, curve.g)
    q_pt = curve.mul(m, curve.g)
    neg_p = None if p_pt is None else (p_pt[0], (-p_pt[1]) % p)
    return {
        'discriminant': (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p,
        'p_point': p_pt,
        'q_point': q_pt,
        'sum_pq': curve.add(p_pt, q_pt),
        'double_p': curve.add(p_pt, p_pt),
        'cancel_is_inf': curve.add(p_pt, neg_p) is None,
        'order_is_inf': curve.mul(n, curve.g) is None,
    }


def op_sign(key_path: Path, input_path: Path, output_path: Path) -> dict:
    start = time.perf_counter_ns()
    private = read_key(key_path, 'sign', private=True)
    data = read_bytes(input_path)
    sig = sign(private, data)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    save_json(output_path, {
        'version': 1, 'algorithm': 'ECDSA-P256-SHA256',
        'signature': encode_signature(sig).hex(),
    })
    return {
        'output_path': Path(output_path),
        'sha256': sha256(data).hex(),
        'r': f'{sig[0]:064x}',
        's': f'{sig[1]:064x}',
        'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
    }


def op_verify(input_path: Path, signature_path: Path, mode: str = 'public',
              public_path: Path | None = None, cert_path: Path | None = None,
              ca_path: Path | None = None, expect_name: str = '') -> dict:
    start = time.perf_counter_ns()
    item = load_json(signature_path)
    if (set(item) != {'version', 'algorithm', 'signature'} or type(item['version']) is not int
            or item['version'] != 1 or item['algorithm'] != 'ECDSA-P256-SHA256'):
        raise ValueError('Formato de firma no admitido.')
    trusted_pub = _resolve_trusted_key(mode, public_path, cert_path, ca_path, expect_name)
    valid = verify(trusted_pub, read_bytes(input_path), decode_signature(unhex(item['signature'], 64)))
    return {
        'valid': valid,
        'signer_fingerprint': fingerprint(trusted_pub),
        'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
    }


def op_encrypt(recipient_path: Path, sign_key_path: Path, input_path: Path,
               output_path: Path, aad: str = 'ELC107') -> dict:
    start = time.perf_counter_ns()
    envelope = seal(
        read_key(recipient_path, 'exchange', private=False),
        read_key(sign_key_path, 'sign', private=True),
        read_bytes(input_path),
        aad.encode('utf-8'),
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    save_json(output_path, envelope)
    return {
        'output_path': Path(output_path),
        'suite': SUITE,
        'ciphertext_bytes': len(envelope['ciphertext']) // 2,
        'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
    }


def op_decrypt(key_path: Path, input_path: Path, output_path: Path, mode: str = 'public',
               sender_path: Path | None = None, cert_path: Path | None = None,
               ca_path: Path | None = None, expect_name: str = '') -> dict:
    start = time.perf_counter_ns()
    plaintext = open_envelope(
        read_key(key_path, 'exchange', private=True),
        _resolve_trusted_key(mode, sender_path, cert_path, ca_path, expect_name),
        load_json(input_path),
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    write_bytes(output_path, plaintext, private=True)
    return {
        'output_path': Path(output_path),
        'plaintext_bytes': len(plaintext),
        'sha256': sha256(plaintext).hex(),
        'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
    }


def op_ca_init(out_dir: Path, name: str = 'CA ELC107') -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path, cert_path = out_dir / 'ca.private.json', out_dir / 'ca.pem'
    if private_path.exists() or cert_path.exists():
        raise FileExistsError('La CA ya existe en esa carpeta.')
    private, now = generate_private(), datetime.now(timezone.utc)
    der = create_certificate(
        public_key(private), name.strip(), name.strip(), private,
        now - timedelta(minutes=5), now + timedelta(days=365), ca=True,
    )
    write_pair(
        private_path, canonical(key_record(private, 'sign', True)) + b'\n',
        cert_path, pem_certificate(der),
    )
    return {'private_path': private_path, 'cert_path': cert_path, 'subject': name.strip()}


def op_cert_issue(ca_key_path: Path, ca_cert_path: Path, public_path: Path,
                  name: str, days: int, output_path: Path) -> dict:
    private = read_key(ca_key_path, 'sign', private=True)
    ca_bytes = read_bytes(ca_cert_path, 65536)
    root = parse_certificate(ca_bytes)
    now = datetime.now(timezone.utc)
    if not 1 <= days <= 365 or root.public != public_key(private):
        raise ValueError('Días inválidos (1..365) o clave de CA incorrecta.')
    after = min(now + timedelta(days=days), root.not_after)
    der = create_certificate(
        read_key(public_path, 'sign', private=False), name.strip(), root.subject,
        private, max(now - timedelta(minutes=5), root.not_before), after,
    )
    verify_certificate(der, ca_bytes, name.strip())
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    write_bytes(output_path, pem_certificate(der))
    return {'output_path': Path(output_path), 'subject': name.strip(), 'issuer': root.subject}


def op_cert_verify(cert_path: Path, ca_path: Path, expect_name: str) -> dict:
    pub = verify_certificate(
        read_bytes(cert_path, 65536), read_bytes(ca_path, 65536), expect_name.strip()
    )
    return {'valid': True, 'subject': expect_name.strip(), 'fingerprint': fingerprint(pub)}


def op_nonce_attack(private_d: int, nonce_k: int, msg1: str, msg2: str) -> dict:
    if not 1 <= private_d < P256.n or not 1 <= nonce_k < P256.n:
        raise ValueError('d y k deben estar en [1, n-1].')
    b1, b2 = msg1.encode('utf-8'), msg2.encode('utf-8')
    if b1 == b2:
        raise ValueError('Use dos mensajes distintos.')
    z1, z2 = int.from_bytes(sha256(b1), 'big'), int.from_bytes(sha256(b2), 'big')
    r = P256.mul(nonce_k, P256.g)[0] % P256.n
    inv_k = inverse_mod(nonce_k, P256.n)
    s1 = inv_k * (z1 + r * private_d) % P256.n
    s2 = inv_k * (z2 + r * private_d) % P256.n
    recovered_k = (z1 - z2) * inverse_mod((s1 - s2) % P256.n, P256.n) % P256.n
    recovered_d = (s1 * recovered_k - z1) * inverse_mod(r, P256.n) % P256.n
    rfc_k1 = next(nonce_candidates(private_d, sha256(b1)))
    rfc_k2 = next(nonce_candidates(private_d, sha256(b2)))
    return {
        'recovered_k': recovered_k,
        'recovered_d': recovered_d,
        'matched': (recovered_k, recovered_d) == (nonce_k, private_d),
        'rfc6979_distinct': rfc_k1 != rfc_k2,
    }


def op_compare_rsa(rsa_bits: int = 1024, samples: int = 3) -> dict:
    if rsa_bits not in (1024, 2048, 3072) or not 1 <= samples <= 20:
        raise ValueError('Use RSA 1024/2048/3072 bits y 1..20 muestras.')
    msg = bytes(i % 256 for i in range(1024))

    def avg_ms(count, fn):
        t0 = time.perf_counter_ns()
        last = None
        for _ in range(count):
            last = fn()
        return (time.perf_counter_ns() - t0) / 1e6 / count, last

    ec_kg, (ec_priv, ec_pub) = avg_ms(1, lambda: (lambda d: (d, public_key(d)))(generate_private()))
    rsa_kg, rsa_key = avg_ms(1, lambda: rsa_generate_key(rsa_bits))
    rsa_pub = rsa_key.public()
    ec_sign_ms, ec_sig = avg_ms(samples, lambda: sign(ec_priv, msg))
    ec_ver_ms, ok1 = avg_ms(samples, lambda: verify(ec_pub, msg, ec_sig))
    rsa_sign_ms, rsa_sig = avg_ms(samples, lambda: pss_sign(rsa_key, msg))
    rsa_ver_ms, ok2 = avg_ms(samples, lambda: pss_verify(rsa_pub, msg, rsa_sig))
    if not (ok1 and ok2):
        raise RuntimeError('Error interno al verificar firma de prueba.')
    return {
        'rsa_bits': rsa_bits, 'samples': samples,
        'ec_sig_bytes': 64, 'rsa_sig_bytes': (rsa_bits + 7) // 8,
        'ec_keygen_ms': ec_kg, 'rsa_keygen_ms': rsa_kg,
        'ec_sign_ms': ec_sign_ms, 'rsa_sign_ms': rsa_sign_ms,
        'ec_verify_ms': ec_ver_ms, 'rsa_verify_ms': rsa_ver_ms,
    }


# ---------------------------------------------------------------------------
# Ventana principal Tkinter (simple y directa)
# ---------------------------------------------------------------------------

class ECCEngineApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('Motor ECC / ECDSA en GF(p) — ELC107 (Grupo E)')
        self.root.geometry('920x770')
        self.root.minsize(840, 720)
        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self.root, bg='#1F3864', padx=14, pady=9)
        header.pack(side='top', fill='x')
        tk.Label(
            header, text='Motor de Cifrado y Firma sobre Curvas Elípticas (ECC / ECDSA)',
            bg='#1F3864', fg='white', font=('Arial', 12, 'bold'),
        ).pack(anchor='w')
        tk.Label(
            header, text='ELC107 — Python puro desde cero (GF(p), NIST P-256, AES-128-GCM, X.509 y RSA-PSS)',
            bg='#1F3864', fg='#D9E2F3', font=('Arial', 9),
        ).pack(anchor='w')

        log_box = ttk.LabelFrame(self.root, text='Registro de salida', padding=5)
        log_box.pack(side='bottom', fill='x', padx=10, pady=(4, 8))
        self.log = scrolledtext.ScrolledText(log_box, height=6, font=('Courier New', 9), state='disabled')
        self.log.pack(fill='x')
        ttk.Button(log_box, text='Limpiar registro', command=self._clear_log).pack(anchor='e', pady=(3, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side='top', fill='both', expand=True, padx=10, pady=(6, 4))

        self._tab_keys()
        self._tab_ecdsa()
        self._tab_hybrid()
        self._tab_pki()
        self._tab_compare()

    def _write_log(self, text: str):
        self.log.configure(state='normal')
        self.log.insert('end', text.rstrip() + '\n' + '-' * 72 + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def _clear_log(self):
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        self.log.configure(state='disabled')

    def _run(self, fn):
        try:
            fn()
        except Exception as err:
            self._write_log(f'ERROR: {err}')
            messagebox.showerror('Error', str(err))

    def _file_row(self, parent, row: int, label: str, var: tk.StringVar, mode: str = 'open'):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', padx=4, pady=2)
        ttk.Entry(parent, textvariable=var, width=54).grid(row=row, column=1, sticky='ew', padx=4, pady=2)
        def browse():
            if mode == 'dir':
                chosen = filedialog.askdirectory()
            elif mode == 'save':
                chosen = filedialog.asksaveasfilename()
            else:
                chosen = filedialog.askopenfilename()
            if chosen:
                var.set(chosen)
        ttk.Button(parent, text='Examinar...', command=browse).grid(row=row, column=2, padx=4, pady=2)
        parent.columnconfigure(1, weight=1)

    # --- Pestaña 1: Claves y aritmética GF(p) ---
    def _tab_keys(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text='1. Claves y Curva GF(p)')

        f1 = ttk.LabelFrame(tab, text='Generar par de claves NIST P-256', padding=8)
        f1.pack(fill='x', pady=(0, 8))
        self.kg_prefix = tk.StringVar(value='alicia')
        self.kg_purpose = tk.StringVar(value='sign')
        self._file_row(f1, 0, 'Prefijo / ruta base:', self.kg_prefix, 'save')
        ttk.Label(f1, text='Propósito:').grid(row=1, column=0, sticky='w', padx=4, pady=3)
        ttk.Combobox(f1, textvariable=self.kg_purpose, values=('sign', 'exchange'),
                     state='readonly', width=18).grid(row=1, column=1, sticky='w', padx=4, pady=3)
        ttk.Button(f1, text='Generar par P-256', command=lambda: self._run(self._do_keygen)).grid(
            row=1, column=2, padx=4, pady=3)

        f2 = ttk.LabelFrame(tab, text='Exportar clave pública a SPKI PEM', padding=8)
        f2.pack(fill='x', pady=(0, 8))
        self.exp_in, self.exp_out = tk.StringVar(), tk.StringVar()
        self._file_row(f2, 0, 'Clave pública (.public.json):', self.exp_in, 'open')
        self._file_row(f2, 1, 'Archivo PEM de salida:', self.exp_out, 'save')
        ttk.Button(f2, text='Exportar PEM', command=lambda: self._run(self._do_export)).grid(
            row=2, column=2, padx=4, pady=3)

        f3 = ttk.LabelFrame(tab, text='Aritmética de curva y² = x³ + ax + b (mod p)', padding=8)
        f3.pack(fill='x')
        defaults = [('p', '17'), ('a', '2'), ('b', '2'), ('Gx', '5'), ('Gy', '1'), ('n', '19'), ('k', '3'), ('m', '5')]
        self.curve_vars = {k: tk.StringVar(value=v) for k, v in defaults}
        for idx, (name, _) in enumerate(defaults):
            ttk.Label(f3, text=f'{name}:').grid(row=idx // 4, column=(idx % 4) * 2, sticky='e', padx=3, pady=3)
            ttk.Entry(f3, textvariable=self.curve_vars[name], width=10).grid(
                row=idx // 4, column=(idx % 4) * 2 + 1, sticky='w', padx=3, pady=3)
        ttk.Button(f3, text='Calcular puntos', command=lambda: self._run(self._do_curve)).grid(
            row=0, column=8, rowspan=2, sticky='e', padx=12, pady=4)

    def _do_keygen(self):
        res = op_keygen(Path(self.kg_prefix.get()), self.kg_purpose.get())
        self._write_log(
            f"[KEYGEN OK] Propósito: {res['purpose']} ({res['elapsed_ms']:.1f} ms)\n"
            f"  Privada (0600): {res['private_path']}\n  Pública: {res['public_path']}\n"
            f"  Huella SHA-256: {res['fingerprint']}"
        )

    def _do_export(self):
        res = op_export_public(Path(self.exp_in.get()), Path(self.exp_out.get()))
        self._write_log(f"[EXPORT PEM OK] {res['output_path']} (huella {res['fingerprint'][:24]}...)")

    def _do_curve(self):
        vals = {k: int(v.get(), 0) for k, v in self.curve_vars.items()}
        res = op_curve_calc(vals['p'], vals['a'], vals['b'], vals['Gx'], vals['Gy'], vals['n'], vals['k'], vals['m'])
        self._write_log(
            f"[CURVA GF({vals['p']})] Δ={res['discriminant']} (≠0) | "
            f"P=kG={res['p_point']} | Q=mG={res['q_point']}\n"
            f"  P+Q={res['sum_pq']} | 2P={res['double_p']} | "
            f"P+(-P)=O: {res['cancel_is_inf']} | nG=O: {res['order_is_inf']}"
        )

    def _identity_block(self, parent, start_row: int, pub_label: str):
        mode = tk.StringVar(value='public')
        pub, cert, ca, cn = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
        bar = ttk.Frame(parent)
        bar.grid(row=start_row, column=0, columnspan=3, sticky='w', pady=2)
        ttk.Label(bar, text='Confianza emisor:').pack(side='left', padx=(4, 8))
        ttk.Radiobutton(bar, text='Clave pública', variable=mode, value='public').pack(side='left', padx=4)
        ttk.Radiobutton(bar, text='Certificado X.509', variable=mode, value='cert').pack(side='left', padx=4)

        pub_frame = ttk.Frame(parent)
        pub_frame.grid(row=start_row + 1, column=0, columnspan=3, sticky='ew')
        self._file_row(pub_frame, 0, pub_label, pub, 'open')

        cert_frame = ttk.Frame(parent)
        self._file_row(cert_frame, 0, 'Certificado (.pem):', cert, 'open')
        self._file_row(cert_frame, 1, 'CA raíz (.pem):', ca, 'open')
        ttk.Label(cert_frame, text='CN esperado:').grid(row=2, column=0, sticky='w', padx=4, pady=2)
        ttk.Entry(cert_frame, textvariable=cn, width=30).grid(row=2, column=1, sticky='w', padx=4, pady=2)

        def refresh(*_):
            if mode.get() == 'public':
                cert_frame.grid_forget()
                pub_frame.grid(row=start_row + 1, column=0, columnspan=3, sticky='ew')
            else:
                pub_frame.grid_forget()
                cert_frame.grid(row=start_row + 1, column=0, columnspan=3, sticky='ew')

        mode.trace_add('write', refresh)
        return mode, pub, cert, ca, cn

    # --- Pestaña 2: Firma y verificación ECDSA ---
    def _tab_ecdsa(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text='2. Firma ECDSA')

        fs = ttk.LabelFrame(tab, text='Firmar archivo (ECDSA P-256 / SHA-256 / RFC 6979)', padding=6)
        fs.pack(fill='x', pady=(0, 6))
        self.s_key, self.s_in, self.s_out = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self._file_row(fs, 0, 'Clave privada (sign):', self.s_key, 'open')
        self._file_row(fs, 1, 'Archivo a firmar:', self.s_in, 'open')
        self._file_row(fs, 2, 'Firma salida (.json):', self.s_out, 'save')
        ttk.Button(fs, text='Firmar archivo', command=lambda: self._run(self._do_sign)).grid(row=3, column=2, pady=3)

        fv = ttk.LabelFrame(tab, text='Verificar firma (clave pública fijada o certificado X.509)', padding=6)
        fv.pack(fill='x')
        self.v_in, self.v_sig = tk.StringVar(), tk.StringVar()
        self._file_row(fv, 0, 'Archivo original:', self.v_in, 'open')
        self._file_row(fv, 1, 'Archivo de firma (.json):', self.v_sig, 'open')
        self.v_mode, self.v_pub, self.v_cert, self.v_ca, self.v_cn = self._identity_block(
            fv, 2, 'Clave pública (.public.json):'
        )
        ttk.Button(fv, text='Verificar firma', command=lambda: self._run(self._do_verify)).grid(row=4, column=2, pady=3)

    def _do_sign(self):
        res = op_sign(Path(self.s_key.get()), Path(self.s_in.get()), Path(self.s_out.get()))
        self._write_log(
            f"[FIRMA OK] {res['output_path']} ({res['elapsed_ms']:.1f} ms)\n"
            f"  SHA-256: {res['sha256']}\n  r: {res['r'][:32]}...\n  s: {res['s'][:32]}..."
        )

    def _do_verify(self):
        res = op_verify(
            Path(self.v_in.get()), Path(self.v_sig.get()), self.v_mode.get(),
            Path(self.v_pub.get()) if self.v_pub.get() else None,
            Path(self.v_cert.get()) if self.v_cert.get() else None,
            Path(self.v_ca.get()) if self.v_ca.get() else None,
            self.v_cn.get(),
        )
        status = 'VÁLIDA' if res['valid'] else 'INVÁLIDA'
        self._write_log(f"[VERIFICACIÓN] Firma {status} ({res['elapsed_ms']:.1f} ms) | Emisor: {res['signer_fingerprint'][:24]}...")

    # --- Pestaña 3: Cifrado híbrido AEAD ---
    def _tab_hybrid(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text='3. Cifrado Híbrido')

        fe = ttk.LabelFrame(tab, text='Cifrar y firmar (ECDH + HKDF + AES-128-GCM + ECDSA)', padding=6)
        fe.pack(fill='x', pady=(0, 6))
        self.e_rec, self.e_skey, self.e_in, self.e_out = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.e_aad = tk.StringVar(value='ELC107')
        self._file_row(fe, 0, 'Pública receptor (exchange):', self.e_rec, 'open')
        self._file_row(fe, 1, 'Privada emisor (sign):', self.e_skey, 'open')
        self._file_row(fe, 2, 'Archivo a cifrar:', self.e_in, 'open')
        self._file_row(fe, 3, 'Sobre salida (.json):', self.e_out, 'save')
        ttk.Label(fe, text='AAD (metadato):').grid(row=4, column=0, sticky='w', padx=4, pady=2)
        ttk.Entry(fe, textvariable=self.e_aad, width=30).grid(row=4, column=1, sticky='w', padx=4, pady=2)
        ttk.Button(fe, text='Cifrar sobre', command=lambda: self._run(self._do_encrypt)).grid(row=4, column=2, pady=2)

        fd = ttk.LabelFrame(tab, text='Autenticar y descifrar sobre (Zero-Trust)', padding=6)
        fd.pack(fill='x')
        self.d_key, self.d_in, self.d_out = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self._file_row(fd, 0, 'Privada receptor (exchange):', self.d_key, 'open')
        self._file_row(fd, 1, 'Sobre cifrado (.json):', self.d_in, 'open')
        self._file_row(fd, 2, 'Archivo recuperado:', self.d_out, 'save')
        self.d_mode, self.d_pub, self.d_cert, self.d_ca, self.d_cn = self._identity_block(
            fd, 3, 'Pública emisor (.public.json):'
        )
        ttk.Button(fd, text='Descifrar sobre', command=lambda: self._run(self._do_decrypt)).grid(row=5, column=2, pady=2)

    def _do_encrypt(self):
        res = op_encrypt(
            Path(self.e_rec.get()), Path(self.e_skey.get()),
            Path(self.e_in.get()), Path(self.e_out.get()), self.e_aad.get(),
        )
        self._write_log(
            f"[CIFRADO OK] {res['output_path']} ({res['elapsed_ms']:.1f} ms)\n"
            f"  Suite: {res['suite']} | Cifrado: {res['ciphertext_bytes']} bytes"
        )

    def _do_decrypt(self):
        res = op_decrypt(
            Path(self.d_key.get()), Path(self.d_in.get()), Path(self.d_out.get()),
            self.d_mode.get(),
            Path(self.d_pub.get()) if self.d_pub.get() else None,
            Path(self.d_cert.get()) if self.d_cert.get() else None,
            Path(self.d_ca.get()) if self.d_ca.get() else None,
            self.d_cn.get(),
        )
        self._write_log(
            f"[DESCIFRADO OK] Firma ECDSA y etiqueta AES-GCM válidas ({res['elapsed_ms']:.1f} ms)\n"
            f"  Salida: {res['output_path']} ({res['plaintext_bytes']} bytes) | SHA-256: {res['sha256']}"
        )

    # --- Pestaña 4: PKI / X.509 ---
    def _tab_pki(self):
        tab = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(tab, text='4. PKI / X.509')

        f1 = ttk.LabelFrame(tab, text='1. Inicializar CA raíz local', padding=5)
        f1.pack(fill='x', pady=(0, 5))
        self.ca_dir, self.ca_name = tk.StringVar(value='pki'), tk.StringVar(value='CA ELC107')
        self._file_row(f1, 0, 'Carpeta de CA:', self.ca_dir, 'dir')
        ttk.Label(f1, text='Nombre CN de la CA:').grid(row=1, column=0, sticky='w', padx=4, pady=2)
        ttk.Entry(f1, textvariable=self.ca_name, width=30).grid(row=1, column=1, sticky='w', padx=4, pady=2)
        ttk.Button(f1, text='Crear CA', command=lambda: self._run(self._do_ca_init)).grid(row=1, column=2, pady=2)

        f2 = ttk.LabelFrame(tab, text='2. Emitir certificado de hoja X.509 v3', padding=5)
        f2.pack(fill='x', pady=(0, 5))
        self.ci_key, self.ci_ca, self.ci_pub, self.ci_out = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.ci_name, self.ci_days = tk.StringVar(value='alicia'), tk.StringVar(value='30')
        self._file_row(f2, 0, 'Clave privada CA:', self.ci_key, 'open')
        self._file_row(f2, 1, 'Certificado CA (.pem):', self.ci_ca, 'open')
        self._file_row(f2, 2, 'Pública sujeto (sign):', self.ci_pub, 'open')
        self._file_row(f2, 3, 'Certificado salida (.pem):', self.ci_out, 'save')
        ttk.Label(f2, text='CN sujeto / Días:').grid(row=4, column=0, sticky='w', padx=4, pady=2)
        row_sub = ttk.Frame(f2)
        row_sub.grid(row=4, column=1, sticky='w', padx=4)
        ttk.Entry(row_sub, textvariable=self.ci_name, width=22).pack(side='left')
        ttk.Entry(row_sub, textvariable=self.ci_days, width=6).pack(side='left', padx=6)
        ttk.Button(f2, text='Emitir certificado', command=lambda: self._run(self._do_cert_issue)).grid(row=4, column=2, pady=2)

        f3 = ttk.LabelFrame(tab, text='3. Verificar certificado X.509', padding=5)
        f3.pack(fill='x')
        self.cv_cert, self.cv_ca, self.cv_cn = tk.StringVar(), tk.StringVar(), tk.StringVar(value='alicia')
        self._file_row(f3, 0, 'Certificado hoja (.pem):', self.cv_cert, 'open')
        self._file_row(f3, 1, 'Certificado CA (.pem):', self.cv_ca, 'open')
        ttk.Label(f3, text='CN esperado:').grid(row=2, column=0, sticky='w', padx=4, pady=2)
        ttk.Entry(f3, textvariable=self.cv_cn, width=26).grid(row=2, column=1, sticky='w', padx=4, pady=2)
        ttk.Button(f3, text='Verificar certificado', command=lambda: self._run(self._do_cert_verify)).grid(row=2, column=2, pady=2)

    def _do_ca_init(self):
        res = op_ca_init(Path(self.ca_dir.get()), self.ca_name.get())
        self._write_log(f"[CA CREADA] {res['cert_path']} | CN={res['subject']}")

    def _do_cert_issue(self):
        res = op_cert_issue(
            Path(self.ci_key.get()), Path(self.ci_ca.get()), Path(self.ci_pub.get()),
            self.ci_name.get(), int(self.ci_days.get()), Path(self.ci_out.get()),
        )
        self._write_log(f"[CERTIFICADO EMITIDO] {res['output_path']} | Titular={res['subject']} | Emisor={res['issuer']}")

    def _do_cert_verify(self):
        res = op_cert_verify(Path(self.cv_cert.get()), Path(self.cv_ca.get()), self.cv_cn.get())
        self._write_log(f"[CERTIFICADO VÁLIDO] CN={res['subject']} | Huella={res['fingerprint'][:24]}...")

    # --- Pestaña 5: Comparación ECC vs RSA y ataque de nonce ---
    def _tab_compare(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text='5. ECC vs RSA y Ataque Nonce')

        fb = ttk.LabelFrame(tab, text='Comparativa de longitud de clave y rendimiento (1024 B)', padding=8)
        fb.pack(fill='x', pady=(0, 8))
        self.rsa_bits = tk.StringVar(value='1024')
        self.bench_samples = tk.StringVar(value='3')
        ttk.Label(fb, text='Módulo RSA (bits):').grid(row=0, column=0, sticky='w', padx=4, pady=3)
        ttk.Combobox(fb, textvariable=self.rsa_bits, values=('1024', '2048', '3072'),
                     state='readonly', width=10).grid(row=0, column=1, sticky='w', padx=4, pady=3)
        ttk.Label(fb, text='Muestras:').grid(row=0, column=2, sticky='e', padx=4, pady=3)
        ttk.Entry(fb, textvariable=self.bench_samples, width=6).grid(row=0, column=3, sticky='w', padx=4, pady=3)
        self.btn_bench = ttk.Button(fb, text='Ejecutar comparativa', command=self._do_compare_async)
        self.btn_bench.grid(row=0, column=4, padx=8, pady=3)
        ttk.Label(fb, text='Nota: 3072 bits equivale a P-256 (~128 bits de seguridad) y puede tardar ~15 s.').grid(
            row=1, column=0, columnspan=5, sticky='w', padx=4, pady=2)

        fa = ttk.LabelFrame(tab, text='Laboratorio: ataque por reutilización de nonce k en ECDSA', padding=8)
        fa.pack(fill='x')
        self.atk_d = tk.StringVar(value='123456789')
        self.atk_k = tk.StringVar(value='987654321')
        self.atk_m1 = tk.StringVar(value='mensaje uno')
        self.atk_m2 = tk.StringVar(value='mensaje dos')
        for idx, (lbl, var) in enumerate([('d laboratorio:', self.atk_d), ('Nonce repetido k:', self.atk_k),
                                          ('Mensaje 1:', self.atk_m1), ('Mensaje 2:', self.atk_m2)]):
            ttk.Label(fa, text=lbl).grid(row=idx // 2, column=(idx % 2) * 2, sticky='w', padx=4, pady=3)
            ttk.Entry(fa, textvariable=var, width=26).grid(row=idx // 2, column=(idx % 2) * 2 + 1, sticky='w', padx=4, pady=3)
        ttk.Button(fa, text='Demostrar ataque', command=lambda: self._run(self._do_attack)).grid(
            row=2, column=3, sticky='e', padx=4, pady=4)

    def _do_compare_async(self):
        bits, samples = int(self.rsa_bits.get()), int(self.bench_samples.get())
        self.btn_bench.configure(state='disabled')
        self._write_log(f'Ejecutando comparativa ECC P-256 vs RSA-{bits} ({samples} muestras)...')

        def worker():
            try:
                res = op_compare_rsa(bits, samples)
                text = (
                    f"[COMPARATIVA ECC P-256 vs RSA-{res['rsa_bits']}] (mensaje 1024 B, {res['samples']} muestras)\n"
                    f"  Tamaño de clave : ECC 256 bits (32 B priv) vs RSA {res['rsa_bits']} bits ({res['rsa_sig_bytes']} B módulo)\n"
                    f"  Tamaño de firma : ECDSA {res['ec_sig_bytes']} bytes vs RSA-PSS {res['rsa_sig_bytes']} bytes\n"
                    f"  Keygen          : ECC {res['ec_keygen_ms']:.2f} ms | RSA {res['rsa_keygen_ms']:.2f} ms\n"
                    f"  Firma           : ECC {res['ec_sign_ms']:.2f} ms | RSA {res['rsa_sign_ms']:.2f} ms\n"
                    f"  Verificación    : ECC {res['ec_verify_ms']:.2f} ms | RSA {res['rsa_verify_ms']:.2f} ms"
                )
            except Exception as err:
                text = f'ERROR comparativa: {err}'
            self.root.after(0, lambda: (self._write_log(text), self.btn_bench.configure(state='normal')))

        threading.Thread(target=worker, daemon=True).start()

    def _do_attack(self):
        res = op_nonce_attack(int(self.atk_d.get(), 0), int(self.atk_k.get(), 0), self.atk_m1.get(), self.atk_m2.get())
        self._write_log(
            f"[ATAQUE NONCE REPETIDO] Recuperación exacta: {res['matched']}\n"
            f"  k recuperado: {res['recovered_k']} | d recuperada: {res['recovered_d']}\n"
            f"  Protección RFC 6979 en API real (nonces distintos): {res['rfc6979_distinct']}"
        )


def launch_gui() -> int:
    root = tk.Tk()
    ECCEngineApp(root)
    root.mainloop()
    return 0
