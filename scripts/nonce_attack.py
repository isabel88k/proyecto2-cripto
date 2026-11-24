#!/usr/bin/env python3
"""Laboratorio aislado: nonce repetido en ECDSA revela la clave privada.

La función de firma real no permite elegir k. Este script crea firmas
vulnerables deliberadamente con una clave fija pública de laboratorio.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from ecc_engine.ecc import P256
from ecc_engine.hashes import sha256
from ecc_engine.arithmetic import inverse_mod


def demonstrate():
    private, nonce = 123456789, 987654321
    z1 = int.from_bytes(sha256(b'mensaje uno'), 'big')
    z2 = int.from_bytes(sha256(b'mensaje dos'), 'big')
    r = P256.mul(nonce, P256.g)[0] % P256.n
    s1 = inverse_mod(nonce, P256.n)*(z1+r*private) % P256.n
    s2 = inverse_mod(nonce, P256.n)*(z2+r*private) % P256.n
    recovered_nonce = (z1-z2)*inverse_mod(s1-s2, P256.n) % P256.n
    recovered_private = (s1*recovered_nonce-z1)*inverse_mod(r, P256.n) % P256.n
    if (recovered_nonce, recovered_private) != (nonce, private):
        raise RuntimeError('El ataque no recuperó la clave')
    print('LABORATORIO: se firman dos mensajes distintos con el mismo k.')
    print('k = (z1-z2)/(s1-s2) mod n; d = (s1*k-z1)/r mod n')
    print(f'Nonce recuperado: {recovered_nonce}')
    print(f'Clave privada de laboratorio RECUPERADA: {recovered_private}')
    print('La API de firma normal usa RFC 6979 y no expone un parámetro k.')
    return recovered_private


if __name__ == '__main__':
    demonstrate()
