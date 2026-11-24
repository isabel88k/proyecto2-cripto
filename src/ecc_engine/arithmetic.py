"""Aritmética entera explícita; pow solo hace exponenciación modular."""
from math import gcd
from secrets import randbelow, randbits


def inverse_mod(a: int, modulus: int) -> int:
    """Euclides extendido: devuelve x tal que a*x = 1 (mod modulus)."""
    if type(a) is not int or type(modulus) is not int or modulus <= 1:
        raise ValueError('Módulo o entero inválido')
    old_r, r, old_s, s = a % modulus, modulus, 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError('No existe inverso modular')
    return old_s % modulus


def is_probable_prime(n: int, rounds: int = 64) -> bool:
    """Miller-Rabin; 64 rondas aleatorias para n >= 2**64.

    Para enteros de 64 bits se usan siete bases deterministas conocidas.
    Para mayores, cota de falso positivo <= 4**(-rounds), por candidato.
    """
    if type(n) is not int or n < 2:
        return False
    if type(rounds) is not int or rounds < 1:
        raise ValueError('Se requiere al menos una ronda')
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == prime:
            return True
        if n % prime == 0:
            return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    bases = ((2, 325, 9375, 28178, 450775, 9780504, 1795265022)
             if n < (1 << 64) else (randbelow(n - 3) + 2 for _ in range(rounds)))
    for base in bases:
        a = base % n
        if a in (0, 1):
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, e: int = 65537) -> int:
    if type(bits) is not int or bits < 16 or bits > 8192:
        raise ValueError('Tamaño de primo permitido: 16..8192 bits')
    if type(e) is not int or e < 3 or e % 2 == 0:
        raise ValueError('Exponente público inválido')
    while True:
        candidate = randbits(bits) | (1 << (bits - 1)) | 1
        if gcd(candidate - 1, e) == 1 and is_probable_prime(candidate):
            return candidate
