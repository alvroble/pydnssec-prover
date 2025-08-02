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
    MAX_PROOF_STEPS
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
    RR,
    NsecTypeBitmask,
    NSec,
    NSec3,
    Soa,
    MX,
    write_name,
    read_name,
    parse_rr,
    RRType,
    RRData,
    NsecType
)

from .base32 import (
    encode,
    decode,
    Alphabet
)

from .ser import (
    Writer,
    Reader
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
    "MAX_PROOF_STEPS",
    
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
    "RR",
    "NsecTypeBitmask",
    "NSec",
    "NSec3",
    "Soa",
    "MX",
    "write_name",
    "read_name",
    "parse_rr",
    "RRType",
    "RRData",
    "NsecType",
    
    # Base32 functions
    "encode",
    "decode", 
    "Alphabet",
    
    # Serialization
    "Writer",
    "Reader",
] 