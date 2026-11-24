"""Curvas cortas de Weierstrass en GF(p), coordenadas afines educativas."""
from dataclasses import dataclass
from secrets import randbelow
from .arithmetic import inverse_mod, is_probable_prime

Point = tuple[int, int] | None  # None representa el punto al infinito O.


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int
    g: Point
    n: int

    def __post_init__(self):
        if (type(self.p) is not int or self.p <= 3 or not is_probable_prime(self.p)
                or type(self.a) is not int or type(self.b) is not int
                or type(self.n) is not int or self.n < 2 or not is_probable_prime(self.n)):
            raise ValueError('Parámetros de curva inválidos')
        if (4 * self.a**3 + 27 * self.b**2) % self.p == 0:
            raise ValueError('Curva singular')
        if self.g is None or not self.contains(self.g):
            raise ValueError('Generador inválido')
        if self.mul(self.n, self.g) is not None:
            raise ValueError('El generador no tiene el orden primo indicado')

    def contains(self, point: Point) -> bool:
        if point is None:
            return True
        if not isinstance(point, tuple) or len(point) != 2:
            return False
        x, y = point
        return (type(x) is int and type(y) is int and 0 <= x < self.p
                and 0 <= y < self.p and (y*y - x*x*x - self.a*x - self.b) % self.p == 0)

    def add(self, left: Point, right: Point) -> Point:
        if not self.contains(left) or not self.contains(right):
            raise ValueError('Punto fuera de la curva')
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        # Incluye P + (-P) y el doblado con y = 0.
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if left == right:
            slope = (3*x1*x1 + self.a) * inverse_mod(2*y1, self.p) % self.p
        else:
            slope = (y2-y1) * inverse_mod(x2-x1, self.p) % self.p
        x3 = (slope*slope - x1 - x2) % self.p
        y3 = (slope*(x1-x3) - y1) % self.p
        return x3, y3

    def mul(self, scalar: int, point: Point) -> Point:
        """Double-and-add O(log scalar); deliberadamente NO tiempo constante."""
        if type(scalar) is not int or scalar < 0 or not self.contains(point):
            raise ValueError('Escalar o punto inválido')
        result = None
        while scalar:
            if scalar & 1:
                result = self.add(result, point)
            point = self.add(point, point)
            scalar >>= 1
        return result

    def validate_public(self, point: Point) -> None:
        if point is None or not self.contains(point) or self.mul(self.n, point) is not None:
            raise ValueError('Clave pública inválida o fuera del subgrupo')


P256 = Curve(
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
       0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)


def validate_private(private: int) -> None:
    if type(private) is not int or not 1 <= private < P256.n:
        raise ValueError('La clave privada debe estar en [1, n-1]')


def generate_private() -> int:
    return randbelow(P256.n - 1) + 1


def public_key(private: int) -> Point:
    validate_private(private)
    return P256.mul(private, P256.g)


def ecdh(private: int, peer: Point) -> bytes:
    validate_private(private)
    P256.validate_public(peer)
    shared = P256.mul(private, peer)
    if shared is None:
        raise ValueError('Secreto ECDH inválido')
    return shared[0].to_bytes(32, 'big')
