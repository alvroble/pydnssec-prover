"""
Test cases for the crypto module, ported from the Rust implementation
"""

import os
import json
import pytest
from typing import Optional, Callable
import sys

# Add the parent directory to path to import crypto module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.secp256r1 import validate_ecdsa as validate_256r1
from crypto.secp384r1 import validate_ecdsa as validate_384r1
from crypto.rsa import validate_rsa
from crypto.hash import Hasher, HashResult


def open_file(name: str):
    """Open a test file, trying multiple possible locations"""
    possible_paths = [
        name,
        f"tests/{name}",
        f"python/tests/{name}",
        os.path.join(os.path.dirname(__file__), name),
        os.path.join(os.path.dirname(__file__), '..', 'tests', name),
    ]
    
    for path in possible_paths:
        try:
            with open(path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            continue
    
    raise FileNotFoundError(f"Failed to find file {name}")


def decode_asn(sig: str, int_len: int) -> Optional[bytes]:
    """
    Decode ASN.1 encoded signature to raw bytes format.
    Note that some tests are specifically for the ASN parser, so we have to carefully
    reject invalid crap here.
    """
    if len(sig) < 12:
        return None
    
    # Check for SEQUENCE tag
    if sig[:2] != "30":
        return None
    
    # Get total length
    total_len = int(sig[2:4], 16)
    if total_len + 2 != len(sig) // 2:
        return None
    
    # Parse r
    if sig[4:6] != "02":
        return None
    
    r_len = int(sig[6:8], 16)
    if len(sig) < r_len * 2 + 8:
        return None
    if r_len == 0:
        return None
    
    r = bytes.fromhex(sig[8:r_len * 2 + 8])
    
    # Validate r length and padding
    if len(r) > int_len:
        # If the MSB is 1, an extra byte is required to avoid the sign flag
        if len(r) > int_len + 1:
            return None
        if r[0] != 0:
            return None
        if r[1] & 0b1000_0000 == 0:
            return None
    elif r[0] & 0b1000_0000 != 0:
        return None
    
    # Parse s
    if len(sig) < r_len * 2 + 12:
        return None
    if sig[r_len * 2 + 8:r_len * 2 + 10] != "02":
        return None
    
    s_len = int(sig[r_len * 2 + 10:r_len * 2 + 12], 16)
    if len(sig) != r_len * 2 + s_len * 2 + 12:
        return None
    if s_len == 0:
        return None
    
    s = bytes.fromhex(sig[r_len * 2 + 12:])
    
    # Validate s length and padding
    if len(s) > int_len:
        # If the MSB is 1, an extra byte is required to avoid the sign flag
        if len(s) > int_len + 1:
            return None
        if s[0] != 0:
            return None
        if s[1] & 0b1000_0000 == 0:
            return None
    elif s[0] & 0b1000_0000 != 0:
        return None
    
    # Convert to fixed-length format
    sig_bytes = bytearray(int_len * 2)
    
    # Place r at correct position
    r_start = int_len - min(len(r), int_len)
    r_source_start = max(0, len(r) - int_len)
    sig_bytes[r_start:int_len] = r[r_source_start:]
    
    # Place s at correct position
    s_start = int_len + int_len - min(len(s), int_len)
    s_source_start = max(0, len(s) - int_len)
    sig_bytes[s_start:int_len * 2] = s[s_source_start:]
    
    return bytes(sig_bytes)


def run_ecdsa_tests(test_data: dict, int_len: int, validate_fn: Callable, hash_fn: Callable):
    """Helper function to run ECDSA validation using the provided test data"""
    for group_idx, group in enumerate(test_data["testGroups"]):
        pk_str = group["publicKey"]["uncompressed"]
        assert pk_str[:2] == "04"  # OpenSSL uncompressed encoding flag
        pk = bytes.fromhex(pk_str[2:])
        
        for test in group["tests"]:
            msg = bytes.fromhex(test["msg"])
            
            expected_result = test["result"]
            expected_valid = expected_result == "valid"
            
            sig = decode_asn(test["sig"], int_len)
            if sig is None:
                assert not expected_valid, f"ASN decode failed but expected valid for test {test['tcId']}"
                continue
            
            hash_result = hash_fn(msg)
            result = validate_fn(pk, sig, hash_result.as_ref())
            
            assert result == expected_valid, (
                f"Test case group {group_idx}, test id {test['tcId']}, "
                f"comment '{test['comment']}' failed. "
                f"Expected {expected_valid}, got {result}"
            )


def run_rsa_tests(test_data: dict, pk_len: int, hash_fn: Callable):
    """Helper function to run RSA validation using the provided test data"""
    for group_idx, group in enumerate(test_data["testGroups"]):
        pk_str = group["publicKey"]["modulus"]
        assert pk_str[:2] == "00"  # No idea why this is here
        pk_modulus = bytes.fromhex(pk_str[2:])
        assert len(pk_modulus) == pk_len
        
        exp_vec = bytes.fromhex(group["publicKey"]["publicExponent"])
        if len(exp_vec) > 4:
            pytest.skip("Exponent too large")
        
        exp_bytes = bytearray(4)
        exp_bytes[4 - len(exp_vec):] = exp_vec
        exp = int.from_bytes(exp_bytes, byteorder='big')
        
        # Build DNS-encoded public key
        pk_dns_encoded = bytearray()
        pk_dns_encoded.append(4)  # Exponent length encoding
        pk_dns_encoded.extend(exp.to_bytes(4, byteorder='big'))
        pk_dns_encoded.extend(pk_modulus)
        
        for test in group["tests"]:
            msg = bytes.fromhex(test["msg"])
            
            result_str = test["result"]
            if result_str == "acceptable":
                continue  # Why bother testing if the tests don't care?
            
            expected_valid = result_str == "valid"
            
            sig = bytes.fromhex(test["sig"])
            hash_result = hash_fn(msg)
            
            result = validate_rsa(pk_dns_encoded, sig, hash_result.as_ref())
            
            assert result == expected_valid, (
                f"Failed test case group {group_idx}, test id {test['tcId']}, "
                f"comment '{test['comment']}'"
            )


# ECDSA test cases
def test_ecdsa_256r1():
    """Test ECDSA secp256r1 with SHA256"""
    content = open_file("ecdsa_secp256r1_sha256_test.json")
    test_data = json.loads(content)
    
    run_ecdsa_tests(test_data, 32, validate_256r1, lambda msg: (
        hasher := Hasher.sha256(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_ecdsa_384r1_sha256():
    """Test ECDSA secp384r1 with SHA256"""
    content = open_file("ecdsa_secp384r1_sha256_test.json")
    test_data = json.loads(content)
    
    run_ecdsa_tests(test_data, 48, validate_384r1, lambda msg: (
        hasher := Hasher.sha256(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_ecdsa_384r1_sha384():
    """Test ECDSA secp384r1 with SHA384"""
    content = open_file("ecdsa_secp384r1_sha384_test.json")
    test_data = json.loads(content)
    
    run_ecdsa_tests(test_data, 48, validate_384r1, lambda msg: (
        hasher := Hasher.sha384(),
        hasher.update(msg),
        hasher.finish()
    )[2])


# RSA test cases
def test_rsa2048_sha256():
    """Test RSA-2048 with SHA256"""
    content = open_file("rsa_signature_2048_sha256_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 256, lambda msg: (
        hasher := Hasher.sha256(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_rsa2048_sha512():
    """Test RSA-2048 with SHA512"""
    content = open_file("rsa_signature_2048_sha512_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 256, lambda msg: (
        hasher := Hasher.sha512(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_rsa3072_sha256():
    """Test RSA-3072 with SHA256"""
    content = open_file("rsa_signature_3072_sha256_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 384, lambda msg: (
        hasher := Hasher.sha256(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_rsa3072_sha512():
    """Test RSA-3072 with SHA512"""
    content = open_file("rsa_signature_3072_sha512_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 384, lambda msg: (
        hasher := Hasher.sha512(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_rsa4096_sha256():
    """Test RSA-4096 with SHA256"""
    content = open_file("rsa_signature_4096_sha256_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 512, lambda msg: (
        hasher := Hasher.sha256(),
        hasher.update(msg),
        hasher.finish()
    )[2])


def test_rsa4096_sha512():
    """Test RSA-4096 with SHA512"""
    content = open_file("rsa_signature_4096_sha512_test.json")
    test_data = json.loads(content)
    
    run_rsa_tests(test_data, 512, lambda msg: (
        hasher := Hasher.sha512(),
        hasher.update(msg),
        hasher.finish()
    )[2])


if __name__ == "__main__":
    # Run a quick test to verify basic functionality
    print("Running basic crypto tests...")
    
    # Test hash functionality
    hasher = Hasher.sha256()
    hasher.update(b"test message")
    result = hasher.finish()
    print(f"SHA256 hash length: {len(result.as_ref())}")
    
    print("Basic tests passed. Run with pytest for full test suite.") 