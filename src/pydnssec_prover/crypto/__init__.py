"""
Cryptographic verification implementations for DNSSEC

This module provides RSA and ECDSA signature validation functionality
for DNSSEC, supporting secp256r1 and secp384r1 curves.
"""

try:
    from .rsa import validate_rsa
    from .secp256r1 import validate_ecdsa as validate_ecdsa_256r1
    from .secp384r1 import validate_ecdsa as validate_ecdsa_384r1
    from .hash import Hasher, HashResult
except ImportError:
    # Handle direct script execution
    from rsa import validate_rsa
    from secp256r1 import validate_ecdsa as validate_ecdsa_256r1
    from secp384r1 import validate_ecdsa as validate_ecdsa_384r1
    from hash import Hasher, HashResult

__all__ = [
    'validate_rsa',
    'validate_ecdsa_256r1', 
    'validate_ecdsa_384r1',
    'Hasher',
    'HashResult'
] 