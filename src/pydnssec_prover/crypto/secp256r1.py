"""
secp256r1 validation for DNSSEC signatures
"""

try:
    from . import ec
except ImportError:
    # Handle direct script execution
    import ec


class P256Curve:
    """secp256r1 (P-256) curve parameters"""
    
    # Curve field prime (p)
    P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    
    # Scalar field prime (n) - order of the base point
    N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    
    # Curve parameters for y^2 = x^3 + ax + b
    A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    
    # Generator point coordinates
    G_X = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    G_Y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    
    # Coordinate byte length (32 bytes for P-256)
    COORD_BYTES = 32


def validate_ecdsa(pk: bytes, sig: bytes, hash_input: bytes) -> bool:
    """
    Validates the given signature against the given public key and message digest.
    
    Args:
        pk: Public key bytes (64 bytes: x || y coordinates)
        sig: Signature bytes (64 bytes: r || s values)
        hash_input: Hash of the message that was signed
        
    Returns:
        True if signature is valid, False otherwise
    """
    return ec.validate_ecdsa(P256Curve(), pk, sig, hash_input) 