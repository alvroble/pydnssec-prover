"""
A simple RSA implementation which handles DNSSEC RSA validation
"""

from typing import Tuple, Optional


def _bytes_to_rsa_mod_exp_modlen(pubkey: bytes) -> Optional[Tuple[int, int, int]]:
    """
    Parse DNSSEC-encoded RSA public key to extract modulus, exponent, and modulus length.
    
    Returns tuple of (modulus, exponent, modulus_byte_length) or None if invalid.
    """
    if len(pubkey) <= 3:
        return None
    
    pos = 0
    
    # Parse exponent length
    if pubkey[0] == 0:
        if len(pubkey) < 3:
            return None
        exponent_length = (pubkey[1] << 8) | pubkey[2]
        pos += 3
    else:
        exponent_length = pubkey[0]
        pos += 1
    
    if len(pubkey) <= pos + exponent_length:
        return None
    if exponent_length > 4:  # Max 4 bytes for exponent
        return None
    
    # Extract exponent
    exp_bytes = pubkey[pos:pos + exponent_length]
    exp = int.from_bytes(exp_bytes, byteorder='big')
    
    # Extract modulus
    mod_bytes = pubkey[pos + exponent_length:]
    modlen = len(pubkey) - pos - exponent_length
    modulus = int.from_bytes(mod_bytes, byteorder='big')
    
    return (modulus, exp, modlen)


def validate_rsa(pk: bytes, sig_bytes: bytes, hash_input: bytes) -> bool:
    """
    Validates the given RSA signature against the given RSA public key (up to 4096-bit, in
    DNSSEC-encoded form) and given message digest.
    
    Args:
        pk: DNSSEC-encoded RSA public key
        sig_bytes: RSA signature bytes
        hash_input: Hash of the message that was signed
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        parsed = _bytes_to_rsa_mod_exp_modlen(pk)
        if parsed is None:
            return False
        
        modulus, exponent, modulus_byte_len = parsed
        
        if modulus_byte_len > 512:  # Max 4096-bit RSA
            return False
        
        sig = int.from_bytes(sig_bytes, byteorder='big')
        
        if sig > modulus:
            return False
        
        # From https://www.rfc-editor.org/rfc/rfc5702#section-3.1
        # DigestInfo encoding prefixes for SHA256 and SHA512
        SHA256_PFX = bytes.fromhex("003031300d060960864801650304020105000420")
        SHA512_PFX = bytes.fromhex("003051300d060960864801650304020305000440")
        
        # Choose prefix based on hash length
        if len(hash_input) == 512 // 8:  # SHA512
            pfx = SHA512_PFX
        else:  # SHA256
            pfx = SHA256_PFX
        
        # Check if we have enough space for the hash structure
        if 512 - 2 - len(SHA256_PFX) <= len(hash_input):
            return False
        
        # Build the expected decrypted signature format
        # Format: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo prefix] [hash]
        hash_bytes = bytearray(512)
        
        # Place hash at the end
        hash_write_pos = 512 - len(hash_input)
        hash_bytes[hash_write_pos:hash_write_pos + len(hash_input)] = hash_input
        
        # Place DigestInfo prefix before hash
        hash_write_pos -= len(pfx)
        hash_bytes[hash_write_pos:hash_write_pos + len(pfx)] = pfx
        
        # Fill with 0xFF padding until we reach the required modulus length
        while 512 + 1 - hash_write_pos < modulus_byte_len:
            hash_write_pos -= 1
            hash_bytes[hash_write_pos] = 0xff
        
        # Set the leading byte to 0x01
        hash_bytes[hash_write_pos] = 1
        
        # Convert to integer (only use the bytes we need for this modulus size)
        start_pos = 512 - modulus_byte_len
        expected_hash = int.from_bytes(hash_bytes[start_pos:], byteorder='big')
        
        if expected_hash > modulus:
            return False
        
        # Verify signature by doing RSA public key operation: sig^exp mod modulus
        decrypted = pow(sig, exponent, modulus)
        
        return decrypted == expected_hash
        
    except Exception:
        return False 