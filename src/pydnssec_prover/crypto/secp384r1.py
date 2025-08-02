"""
secp384r1 validation for DNSSEC signatures
"""

try:
    from . import ec
except ImportError:
    # Handle direct script execution
    import ec


class P384Curve:
    """secp384r1 (P-384) curve parameters"""
    
    # Curve field prime (p)
    P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
    
    # Scalar field prime (n) - order of the base point
    N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
    
    # Curve parameters for y^2 = x^3 + ax + b
    A = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
    B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
    
    # Generator point coordinates
    G_X = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
    G_Y = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
    
    # Coordinate byte length (48 bytes for P-384)
    COORD_BYTES = 48


def validate_ecdsa(pk: bytes, sig: bytes, hash_input: bytes) -> bool:
    """
    Validates the given signature against the given public key and message digest.
    
    Args:
        pk: Public key bytes (96 bytes: x || y coordinates)
        sig: Signature bytes (96 bytes: r || s values)
        hash_input: Hash of the message that was signed
        
    Returns:
        True if signature is valid, False otherwise
    """
    return ec.validate_ecdsa(P384Curve(), pk, sig, hash_input) 