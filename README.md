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
- Python port of the Rust implementation

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
git clone https://github.com/alvroble/pydnssec-prover
cd pydnssec-prover
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/alvroble/pydnssec-prover
cd pydnssec-prover
pip install -e ".[test]"
```

## Usage

The main entry point is the `verify_byte_stream` function, which takes an RFC 9102 DNSSEC proof and returns verification results:

```python
from pydnssec_prover import verify_byte_stream
import json

# Example RFC 9102 proof bytes (you would get this from a DNSSEC-enabled resolver)
proof_bytes = bytes.fromhex("00002e000100002bb3...")  # Your proof data here

# Verify the proof and resolve a specific name
result_json = verify_byte_stream(proof_bytes, "example.com.")

# Parse the JSON result
result = json.loads(result_json)

if "error" in result:
    print(f"Validation failed: {result['error']}")
else:
    print(f"✅ Validation successful!")
    print(f"Valid from: {result['valid_from']}")
    print(f"Expires: {result['expires']}")
    print(f"Max cache TTL: {result['max_cache_ttl']}")
    print(f"Verified records: {len(result['verified_rrs'])}")
    
    # Display the verified records
    for record in result['verified_rrs']:
        print(f"  - {record['type'].upper()}: {record['name']}")
```

## API Reference

### Main Function

- `verify_byte_stream(proof_bytes: bytes, name_to_resolve: str) -> str`
  - **proof_bytes**: RFC 9102 DNSSEC proof as bytes
  - **name_to_resolve**: Domain name to resolve (e.g., "example.com.")
  - **Returns**: JSON string with verification results or error information

### Response Format

**Success Response:**
```json
{
  "valid_from": 1234567890,
  "expires": 1234567890,
  "max_cache_ttl": 3600,
  "verified_rrs": [
    {
      "type": "txt",
      "name": "example.com."
    }
  ]
}
```

**Error Response:**
```json
{
  "error": "invalid"
}
```

### Lower-level APIs

For advanced usage, you can also use the lower-level functions:

- `verify_rr_stream(records: List[Record]) -> VerifiedRRStream` - Verify a list of DNS records
- `ValidationError` - Exception raised when validation fails
- `Name` - DNS name representation
- `Record` - DNS resource record representation

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