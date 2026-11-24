#!/usr/bin/env python3
"""Auditoría estática de imports del runtime; no prueba seguridad criptográfica."""
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CORE_ALLOWED = {'argparse', 'base64', 'dataclasses', 'datetime', 'json', 'math', 'os',
                'pathlib', 're', 'secrets', 'struct', 'sys'}
# La interfaz gráfica Tkinter usa únicamente módulos estándar no criptográficos.
GUI_ALLOWED = CORE_ALLOWED | {'threading', 'time', 'tkinter'}
ALLOWED = CORE_ALLOWED


def main():
    problems = []
    files = sorted((ROOT/'src').rglob('*.py'))
    for path in files:
        allowed = GUI_ALLOWED if path.name == 'gui.py' else CORE_ALLOWED
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [item.name.split('.')[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                names = [(node.module or '').split('.')[0]]
            else:
                continue
            for name in names:
                if name not in allowed:
                    problems.append(f'{path.relative_to(ROOT)}:{node.lineno}: import {name}')
        # Comprobar también llamadas dinámicas fuera de los nodos import.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('exec', 'eval', '__import__'):
                problems.append(f'{path.relative_to(ROOT)}:{node.lineno}: ejecución dinámica')
    if problems:
        print('\n'.join(problems))
        return 1
    print(f'OK: {len(files)} módulos del runtime sin imports criptográficos externos.')
    print('SHA-256/HMAC/HKDF, ECC/ECDSA/ECDH, RSA-PSS y AES/GCM son implementaciones propias.')
    print('secrets solo aporta entropía y compare_digest; math.gcd y pow son aritmética entera.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
