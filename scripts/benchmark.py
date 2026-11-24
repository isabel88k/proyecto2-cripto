#!/usr/bin/env python3
"""Medición reproducible sin dependencias; nunca supone que ECC es más rápido."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from ecc_engine.ecc import generate_private, public_key
from ecc_engine.ecdsa import sign, verify
from ecc_engine.rsa import generate_key, pss_sign, pss_verify
from ecc_engine.hashes import sha256
from ecc_engine.gcm import encrypt
from ecc_engine.encoding import write_bytes


def measured(algorithm, operation, message_bytes, count, action):
    samples = []
    last = None
    for _ in range(count):
        start = time.perf_counter_ns()
        last = action()
        samples.append((time.perf_counter_ns()-start)/1e6)
    return {'algorithm': algorithm, 'operation': operation, 'message_bytes': message_bytes,
            'samples': count, 'samples_ms': samples, 'median_ms': statistics.median(samples),
            'mean_ms': statistics.mean(samples), 'stdev_ms': statistics.stdev(samples) if count > 1 else 0,
            'min_ms': min(samples), 'max_ms': max(samples)}, last


def run(bits=3072, samples=15, keygen_samples=3):
    rows = []
    def ec_keygen():
        private = generate_private()
        return private, public_key(private)
    row, (private, public) = measured('ECDSA-P256', 'keygen', 0, keygen_samples, ec_keygen)
    rows.append(row)
    print(f'Generando RSA-{bits} ({keygen_samples} muestras)...', flush=True)
    row, rsa = measured(f'RSA-PSS-{bits}', 'keygen', 0, keygen_samples, lambda: generate_key(bits))
    rows.append(row)
    rsa_public = rsa.public()
    for size in (64, 1024, 16384):
        message = bytes(i % 256 for i in range(size))
        ec_signature, rsa_signature = sign(private, message), pss_sign(rsa, message)
        if not verify(public, message, ec_signature) or not pss_verify(rsa_public, message, rsa_signature):
            raise RuntimeError('La firma de calentamiento no verifica')
        for algorithm, operation, action in (
            ('ECDSA-P256', 'sign', lambda: sign(private, message)),
            ('ECDSA-P256', 'verify', lambda: verify(public, message, ec_signature)),
            (f'RSA-PSS-{bits}', 'sign', lambda: pss_sign(rsa, message)),
            (f'RSA-PSS-{bits}', 'verify', lambda: pss_verify(rsa_public, message, rsa_signature)),
            ('SHA256', 'hash', lambda: sha256(message))):
            row, last = measured(algorithm, operation, size, samples, action)
            if operation == 'verify' and not last:
                raise RuntimeError('Verificación fallida durante medición')
            rows.append(row)
    # Nonce distinto por cifrado; incluso el benchmark respeta esta condición.
    from secrets import token_bytes
    aes_key = token_bytes(16)
    row, _ = measured('AES128-GCM', 'encrypt', 1024, samples,
                      lambda: encrypt(aes_key, token_bytes(12), bytes(1024), b'ELC107'))
    rows.append(row)
    cpu = platform.processor() or platform.machine()
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                cpu = line.split(':', 1)[1].strip()
                break
    except OSError:
        pass
    return {'created_utc': datetime.now(timezone.utc).isoformat(), 'python': sys.version,
            'platform': platform.platform(), 'cpu': cpu, 'rsa_bits': bits,
            'ecc_bits': 256, 'security_bits_approx': 128 if bits == 3072 else None,
            'timer': 'perf_counter_ns', 'signature_includes_hash': True,
            'rsa_optimization': 'CRT + random blinding + public self-check',
            'ecc_coordinates': 'affine double-and-add; subgroup validation on verify',
            'ecdsa_signature_raw_bytes': 64, 'rsa_signature_bytes': (bits+7)//8,
            'warning': 'Tiempos de esta implementación Python; no generalizar a bibliotecas optimizadas.',
            'measurements': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rsa-bits', type=int, default=3072)
    parser.add_argument('--samples', type=int, default=15)
    parser.add_argument('--keygen-samples', type=int, default=3)
    parser.add_argument('--output', type=Path, default=Path('results/benchmark.json'))
    args = parser.parse_args()
    if not 2 <= args.samples <= 1000 or not 1 <= args.keygen_samples <= 20:
        parser.error('Usar 2..1000 muestras y 1..20 generaciones de claves')
    csv_path = args.output.with_suffix('.csv')
    if csv_path == args.output:
        parser.error('--output debe tener una extensión distinta de .csv; usar .json')
    if args.output.exists() or csv_path.exists():
        parser.error('La salida ya existe; elija otro nombre o guarde la medición anterior')
    data = run(args.rsa_bits, args.samples, args.keygen_samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_bytes(args.output, json.dumps(data, indent=2).encode()+b'\n')
    fields = ['algorithm', 'operation', 'message_bytes', 'samples', 'median_ms', 'mean_ms', 'stdev_ms', 'min_ms', 'max_ms']
    with csv_path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data['measurements'])
    for row in data['measurements']:
        print(f"{row['algorithm']:16} {row['operation']:8} {row['message_bytes']:5} B: {row['median_ms']:10.3f} ms")
    print(f'Resultados: {args.output} y {csv_path}')


if __name__ == '__main__':
    main()
