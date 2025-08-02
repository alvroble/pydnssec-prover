"""
Python DNSSEC Prover Library

A Python port of dnssec-prover: DNSSEC validation based on RFC 9102 proofs.
This library provides offline DNSSEC validation capabilities.

This is a Python port of the original Rust implementation by Matt Corallo:
https://github.com/TheBlueMatt/dnssec-prover

The original Rust implementation provides APIs to create and verify RFC 9102 proofs
with minimal dependencies. This Python port aims to bring the same capabilities
to Python applications while maintaining the same design philosophy.

For more information about the original implementation, see:
- Original repository: https://github.com/TheBlueMatt/dnssec-prover
- Documentation: https://docs.rs/dnssec-prover
- Live demo: https://http-dns-prover.as397444.net/
"""

from .validation import (
    verify_rr_stream,
    verify_rrsig,
    verify_rr_set,
    root_hints,
    ValidationError,
    VerifiedRRStream,
    resolve_time,
    verify_byte_stream
)

from .rr import (
    Name,
    Record,
    A,
    AAAA,
    NS,
    Txt,
    TLSA,
    CName,
    DName,
    DnsKey,
    DS,
    RRSig,
    NSec,
    NSec3,
    NSecTypeMask,
    parse_rr_stream,
    write_rr
)

from .base32 import (
    encode,
    decode
)

from .ser import (
    SerializationError,
    read_u8,
    read_u16,
    read_u32,
    read_wire_packet_name,
    write_name,
    name_len
)

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

# Reference to original work
__original_author__ = "Matt Corallo (TheBlueMatt)"
__original_repository__ = "https://github.com/TheBlueMatt/dnssec-prover"

__all__ = [
    # Validation functions
    "verify_rr_stream",
    "verify_rrsig", 
    "verify_rr_set",
    "root_hints",
    "ValidationError",
    "VerifiedRRStream",
    "resolve_time",
    "verify_byte_stream",
    
    # DNS record types
    "Name",
    "Record",
    "A",
    "AAAA", 
    "NS",
    "Txt",
    "TLSA",
    "CName",
    "DName",
    "DnsKey",
    "DS",
    "RRSig",
    "NSec",
    "NSec3",
    "NSecTypeMask",
    "parse_rr_stream",
    "write_rr",
    
    # Base32 functions
    "encode",
    "decode", 
    
    # Serialization
    "SerializationError",
    "read_u8",
    "read_u16",
    "read_u32",
    "read_wire_packet_name",
    "write_name",
    "name_len",
] 