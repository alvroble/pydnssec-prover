# PyDNSSEC Prover

A Python port of [dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover): DNSSEC validation based on RFC 9102 proofs. This library provides offline DNSSEC validation capabilities.

> **Note**: This is a Python port of the original Rust implementation by [Matt Corallo](https://github.com/TheBlueMatt). The original Rust crate can be found at [TheBlueMatt/dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover).

## Features

- Offline DNSSEC validation
- Support for RFC 9102 proofs
- Cryptographic verification of DNS records
- Support for RSA and ECDSA signatures
- **Minimal dependencies** - uses only Python standard library
- Comprehensive test suite
- Python port of the battle-tested Rust implementation

## Background

This library implements RFC 9102 DNSSEC validation proofs, allowing for offline verification of DNS records without requiring trust in DNS resolvers. The original implementation was created in Rust by Matt Corallo and has been ported to Python to make these capabilities available to the Python ecosystem.

For more details about the original implementation and its architecture, see:
- [Original Rust repository](https://github.com/TheBlueMatt/dnssec-prover)
- [Rust documentation](https://docs.rs/dnssec-prover)
- [Live demo](https://http-dns-prover.as397444.net/)

## Installation

### From PyPI (when published)

```bash
pip install pydnssec-prover
```

### From Source

```bash
git clone <repository-url>
cd pydnssec-prover
pip install -e .
```

### Development Installation

```bash
git clone <repository-url>
cd pydnssec-prover
pip install -e ".[test]"
```

## Usage

```python
from pydnssec_prover import verify_rr_stream, ValidationError

try:
    # Verify a DNS record stream
    verified_stream = verify_rr_stream(proof_data, queries)
    print("Validation successful!")
except ValidationError as e:
    print(f"Validation failed: {e}")
```

## API Reference

### Main Functions

- `verify_rr_stream(proof, queries)` - Verify a stream of DNS resource records
- `verify_rrsig(rrsig, rrset, dnskey)` - Verify an RRSIG record
- `verify_rr_set(rrset, rrsigs, dnskeys)` - Verify a set of resource records

### Classes

- `ValidationError` - Exception raised when validation fails
- `VerifiedRRStream` - Container for verified DNS records
- `Name` - DNS name representation
- `RR` - DNS resource record representation

## Development

### Running Tests

```bash
pytest
```

## License

MIT License - see LICENSE file for details.

This Python port maintains the same MIT license as one of the licenses used by the original Rust implementation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Dependencies

This library has **zero runtime dependencies** and uses only Python's standard library, maintaining the minimal dependency philosophy of the original Rust implementation.

## Credits

- **Original Rust Implementation**: [Matt Corallo](https://github.com/TheBlueMatt) ([dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover))
- **Python Port**: [Your Name]

## Related Projects

- [Original Rust dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover) - The original implementation this is ported from
- [RFC 9102](https://tools.ietf.org/rfc/rfc9102.txt) - TLS DNSSEC Chain Extension 