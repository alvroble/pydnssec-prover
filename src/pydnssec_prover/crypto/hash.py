"""
Simple wrapper around various hash options to provide a single enum which can calculate
different hashes.
"""

import hashlib
from typing import Union


class HashResult:
    """Container for hash results that can return bytes via as_ref()"""
    
    def __init__(self, hash_bytes: bytes):
        self._bytes = hash_bytes
    
    def as_ref(self) -> bytes:
        """Return the hash bytes"""
        return self._bytes
    
    def __len__(self) -> int:
        return len(self._bytes)


class Hasher:
    """Hash engine that supports SHA1, SHA256, SHA384, and SHA512"""
    
    def __init__(self, algorithm: str):
        if algorithm not in ['sha1', 'sha256', 'sha384', 'sha512']:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        self._algorithm = algorithm
        self._hasher = hashlib.new(algorithm)
    
    @classmethod
    def sha1(cls) -> 'Hasher':
        """Create a SHA1 hasher"""
        return cls('sha1')
    
    @classmethod 
    def sha256(cls) -> 'Hasher':
        """Create a SHA256 hasher"""
        return cls('sha256')
    
    @classmethod
    def sha384(cls) -> 'Hasher':
        """Create a SHA384 hasher"""
        return cls('sha384')
    
    @classmethod
    def sha512(cls) -> 'Hasher':
        """Create a SHA512 hasher"""
        return cls('sha512')
    
    def update(self, data: bytes) -> None:
        """Update the hasher with new data"""
        self._hasher.update(data)
    
    def finish(self) -> HashResult:
        """Finalize the hash and return the result"""
        return HashResult(self._hasher.digest()) 