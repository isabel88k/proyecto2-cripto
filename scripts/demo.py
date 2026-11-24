#!/usr/bin/env python3
"""Demostración real de consola; conserva evidencias públicas, nunca las claves."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('results/demo.txt'))
    args = parser.parse_args()
    if args.output.exists():
        parser.error('La salida existe; elija otro --output')
    transcript = ['DEMOSTRACIÓN ELC107: ejecución real capturada',
                  'Fecha UTC: '+datetime.now(timezone.utc).isoformat(),
                  'Las claves se generan en una carpeta temporal y se eliminan al terminar.']
    with tempfile.TemporaryDirectory(prefix='elc107-') as directory:
        directory = Path(directory)
        def run(arguments, expected=0):
            command = [sys.executable, str(ROOT/'cripto.py'), *map(str, arguments)]
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
            transcript.append('\n$ python3 cripto.py '+' '.join(map(str, arguments)))
            transcript.append((result.stdout+result.stderr).strip())
            transcript.append(f'Estado: {result.returncode} (esperado {expected})')
            if result.returncode != expected:
                raise RuntimeError('\n'.join(transcript))
        run(['keygen', '--prefix', 'alicia', '--purpose', 'sign'])
        run(['keygen', '--prefix', 'bob', '--purpose', 'exchange'])
        message = directory/'mensaje.txt'
        message.write_text('ELC107: mensaje auténtico de prueba.\n', encoding='utf-8')
        run(['sign', '--key', 'alicia.private.json', '--input', 'mensaje.txt', '--output', 'firma.json'])
        run(['verify', '--public', 'alicia.public.json', '--input', 'mensaje.txt', '--signature', 'firma.json'])
        message.write_text('Mensaje alterado por un tercero.\n')
        run(['verify', '--public', 'alicia.public.json', '--input', 'mensaje.txt', '--signature', 'firma.json'], 1)
        message.write_text('ELC107: mensaje auténtico de prueba.\n', encoding='utf-8')
        run(['ca-init', '--out', 'pki'])
        run(['cert-issue', '--ca-key', 'pki/ca.private.json', '--ca-cert', 'pki/ca.pem',
             '--public', 'alicia.public.json', '--name', 'alicia', '--output', 'alicia.pem'])
        run(['cert-verify', '--cert', 'alicia.pem', '--ca', 'pki/ca.pem', '--expect-name', 'alicia'])
        run(['cert-verify', '--cert', 'alicia.pem', '--ca', 'pki/ca.pem', '--expect-name', 'mallory'], 1)
        run(['encrypt', '--recipient', 'bob.public.json', '--sign-key', 'alicia.private.json',
             '--input', 'mensaje.txt', '--output', 'sobre.json', '--aad', 'ELC107'])
        run(['decrypt', '--key', 'bob.private.json', '--cert', 'alicia.pem', '--ca', 'pki/ca.pem',
             '--expect-name', 'alicia', '--input', 'sobre.json', '--output', 'recuperado.txt'])
        if (directory/'recuperado.txt').read_bytes() != message.read_bytes():
            raise RuntimeError('El contenido recuperado difiere')
        transcript.append('Integridad: archivo recuperado idéntico al original, comparación byte a byte.')
        bad = json.loads((directory/'sobre.json').read_text())
        bad['tag'] = '00'*16
        (directory/'alterado.json').write_text(json.dumps(bad))
        run(['decrypt', '--key', 'bob.private.json', '--sender', 'alicia.public.json',
             '--input', 'alterado.json', '--output', 'no_debe_existir.txt'], 1)
        if (directory/'no_debe_existir.txt').exists():
            raise RuntimeError('Se creó salida para un sobre inválido')
        transcript.append('Rechazo seguro: no se creó archivo de salida para el sobre alterado.')
        run(['sign', '--key', 'alicia.private.json', '--input', 'mensaje.txt', '--output', 'firma.json'], 1)
    attack = subprocess.run([sys.executable, str(ROOT/'scripts/nonce_attack.py')], capture_output=True, text=True)
    if attack.returncode:
        raise RuntimeError(attack.stderr)
    transcript.append('\n$ python3 scripts/nonce_attack.py\n'+attack.stdout.strip())
    transcript.append('\nDEMOSTRACIÓN COMPLETADA: todos los estados coinciden con lo esperado.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(transcript)+'\n')
    print('\n'.join(transcript))


if __name__ == '__main__':
    main()
