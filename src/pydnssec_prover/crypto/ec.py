"""
Simple verification of ECDSA signatures over SECP Random curves

This module implements elliptic curve operations and ECDSA signature validation
compatible with the Rust implementation.
"""

from typing import Protocol, TypeVar, Generic, Optional, Tuple
from abc import ABC, abstractmethod


class CurveParams(Protocol):
    """Protocol defining the interface for elliptic curve parameters"""
    
    # Curve field prime (p)
    P: int
    
    # Scalar field prime (n) 
    N: int
    
    # Curve parameters for y^2 = x^3 + ax + b
    A: int
    B: int
    
    # Generator point coordinates
    G_X: int
    G_Y: int
    
    # Coordinate byte length
    COORD_BYTES: int


def _mod_inverse(a: int, m: int) -> Optional[int]:
    """
    Compute modular inverse of a mod m using extended Euclidean algorithm.
    Returns None if inverse doesn't exist.
    """
    if a < 0:
        return None
    
    # Extended Euclidean Algorithm
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        return None
    return (x % m + m) % m


class Point:
    """Elliptic curve point in Jacobian coordinates"""
    
    def __init__(self, x: int, y: int, z: int, curve: CurveParams):
        self.x = x
        self.y = y 
        self.z = z
        self.curve = curve
    
    @classmethod
    def from_affine(cls, x: int, y: int, curve: CurveParams) -> Optional['Point']:
        """Create point from affine coordinates, validating it's on the curve"""
        # Validate point is on curve: y^2 = x^3 + ax + b (mod p)
        x_mod = x % curve.P
        y_mod = y % curve.P
        
        left = (y_mod * y_mod) % curve.P
        right = (x_mod * x_mod * x_mod + curve.A * x_mod + curve.B) % curve.P
        
        if left != right:
            return None
        
        return cls(x_mod, y_mod, 1, curve)
    
    @classmethod
    def generator(cls, curve: CurveParams) -> 'Point':
        """Return the generator point for the curve"""
        return cls(curve.G_X, curve.G_Y, 1, curve)
    
    def is_infinity(self) -> bool:
        """Check if this is the point at infinity"""
        return self.z == 0
    
    def double(self) -> 'Point':
        """Point doubling in Jacobian coordinates"""
        if self.is_infinity() or self.y == 0:
            return Point(0, 1, 0, self.curve)  # Point at infinity
        
        # https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
        p = self.curve.P
        
        # delta = Z1^2
        delta = (self.z * self.z) % p
        # gamma = Y1^2
        gamma = (self.y * self.y) % p
        # beta = X1*gamma
        beta = (self.x * gamma) % p
        # alpha = 3*(X1-delta)*(X1+delta)
        alpha = (3 * (self.x - delta) * (self.x + delta)) % p
        # X3 = alpha^2-8*beta
        x3 = (alpha * alpha - 8 * beta) % p
        # Z3 = (Y1+Z1)^2-gamma-delta
        z3 = ((self.y + self.z) * (self.y + self.z) - gamma - delta) % p
        # Y3 = alpha*(4*beta-X3)-8*gamma^2
        y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
        
        return Point(x3, y3, z3, self.curve)
    
    def add(self, other: 'Point') -> 'Point':
        """Point addition in Jacobian coordinates"""
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        
        p = self.curve.P
        
        # https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
        z1z1 = (self.z * self.z) % p
        z2z2 = (other.z * other.z) % p
        u1 = (self.x * z2z2) % p
        u2 = (other.x * z1z1) % p
        s1 = (self.y * other.z * z2z2) % p
        s2 = (other.y * self.z * z1z1) % p
        
        if u1 == u2:
            if s1 != s2:
                return Point(0, 1, 0, self.curve)  # Point at infinity
            return self.double()
        
        h = (u2 - u1) % p
        i = (2 * h) % p
        i = (i * i) % p
        j = (h * i) % p
        r = (2 * (s2 - s1)) % p
        v = (u1 * i) % p
        x3 = (r * r - j - 2 * v) % p
        y3 = (r * (v - x3) - 2 * s1 * j) % p
        z3 = ((self.z + other.z) * (self.z + other.z) - z1z1 - z2z2) % p
        z3 = (z3 * h) % p
        
        return Point(x3, y3, z3, self.curve)
    
    def scalar_mult(self, k: int) -> 'Point':
        """Scalar multiplication using binary method"""
        if k == 0:
            return Point(0, 1, 0, self.curve)  # Point at infinity
        if k == 1:
            return self
        if k < 0:
            return Point(0, 1, 0, self.curve)  # Invalid for our use case
        
        result = Point(0, 1, 0, self.curve)  # Start with point at infinity
        addend = self
        
        while k > 0:
            if k & 1:
                result = result.add(addend)
            addend = addend.double()
            k >>= 1
        
        return result
    
    def to_affine(self) -> Optional[Tuple[int, int]]:
        """Convert to affine coordinates"""
        if self.is_infinity():
            return None
        
        z_inv = _mod_inverse(self.z, self.curve.P)
        if z_inv is None:
            return None
        
        z_inv_squared = (z_inv * z_inv) % self.curve.P
        z_inv_cubed = (z_inv_squared * z_inv) % self.curve.P
        
        x = (self.x * z_inv_squared) % self.curve.P
        y = (self.y * z_inv_cubed) % self.curve.P
        
        return (x, y)


def _add_two_mul(u_a: int, point_g: Point, u_b: int, point_pk: Point) -> Optional[Point]:
    """
    Calculates u_a * point_g + u_b * point_pk efficiently
    This is equivalent to Shamir's trick for dual scalar multiplication
    """
    if u_a == 0 or u_b == 0:
        return None
    
    # Simple double-and-add implementation
    g_mult = point_g.scalar_mult(u_a)
    pk_mult = point_pk.scalar_mult(u_b)
    
    return g_mult.add(pk_mult)


def validate_ecdsa(curve: CurveParams, pk: bytes, sig: bytes, hash_input: bytes) -> bool:
    """
    Validates the given signature against the given public key and message digest.
    
    Args:
        curve: Curve parameters
        pk: Public key bytes (uncompressed format: x || y)
        sig: Signature bytes (r || s)
        hash_input: Hash of the message that was signed
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        coord_bytes = curve.COORD_BYTES
        
        if len(pk) != coord_bytes * 2:
            return False
        if len(sig) != coord_bytes * 2:
            return False
        
        # Parse signature
        r_bytes = sig[:coord_bytes]
        s_bytes = sig[coord_bytes:]
        
        # Parse public key
        pk_x_bytes = pk[:coord_bytes]
        pk_y_bytes = pk[coord_bytes:]
        
        pk_x = int.from_bytes(pk_x_bytes, byteorder='big')
        pk_y = int.from_bytes(pk_y_bytes, byteorder='big')
        
        # Validate public key point is on curve
        PK = Point.from_affine(pk_x, pk_y, curve)
        if PK is None:
            return False
        
        # Parse signature components
        r = int.from_bytes(r_bytes, byteorder='big')
        s = int.from_bytes(s_bytes, byteorder='big')
        
        # Validate signature bounds (wycheproof tests expect this)
        if r > curve.N or s > curve.N:
            return False
        if r == 0 or s == 0:
            return False
        
        # Calculate s^(-1) mod n
        s_inv = _mod_inverse(s, curve.N)
        if s_inv is None:
            return False
        
        # Parse hash (truncate if necessary)
        if len(hash_input) > coord_bytes:
            hash_bytes = hash_input[:coord_bytes]
        else:
            hash_bytes = hash_input
        
        z = int.from_bytes(hash_bytes, byteorder='big')
        
        # Calculate u_a = z * s^(-1) mod n and u_b = r * s^(-1) mod n
        u_a = (z * s_inv) % curve.N
        u_b = (r * s_inv) % curve.N
        
        # Calculate point V = u_a * G + u_b * PK
        G = Point.generator(curve)
        V = _add_two_mul(u_a, G, u_b, PK)
        if V is None or V.is_infinity():
            return False
        
        # Convert V to affine coordinates to get x coordinate
        v_affine = V.to_affine()
        if v_affine is None:
            return False
        
        v_x, _ = v_affine
        
        # Verify that V.x ≡ r (mod n)
        return (v_x % curve.N) == r
        
    except Exception:
        return False 