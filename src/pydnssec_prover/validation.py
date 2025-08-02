"""
Utilities to deserialize and validate RFC 9102 DNSSEC proofs

This module provides the core validation logic for DNSSEC signatures and proofs,
implementing the same algorithms as the Rust version.
"""

from typing import List, Dict, Set, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import time
from io import BytesIO

try:
    from .crypto import Hasher, validate_rsa, validate_ecdsa_256r1, validate_ecdsa_384r1
    from .rr import Name, Record, DnsKey, DS, RRSig, CName, DName
    from .ser import write_name
except ImportError:
    # Handle direct script execution
    from crypto import Hasher, validate_rsa, validate_ecdsa_256r1, validate_ecdsa_384r1
    from rr import Name, Record, DnsKey, DS, RRSig, CName, DName
    from ser import write_name

# Maximum number of proof steps to prevent infinite loops
MAX_PROOF_STEPS = 20


def root_hints() -> List[DS]:
    """
    Gets the trusted root anchors
    
    These are available at https://data.iana.org/root-anchors/root-anchors.xml
    """
    # Current IANA root trust anchors (production keys only)
    return [
        DS(
            Name("."), 20326, 8, 2,
            bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
        ),
        DS(
            Name("."), 38696, 8, 2,
            bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")
        )
    ]


class ValidationError(Exception):
    """An error when validating DNSSEC signatures or other data"""
    
    class ErrorType(Enum):
        """Types of validation errors"""
        UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
        INVALID = "invalid"
        VALIDATION_COUNT_LIMITED = "validation_count_limited"
    
    def __init__(self, error_type: ErrorType, message: str = ""):
        self.error_type = error_type
        super().__init__(f"{error_type.value}: {message}" if message else error_type.value)


@dataclass
class VerifiedRRStream:
    """
    Contains verified resource records with their validity timeframe
    
    This represents the result of DNSSEC validation, containing the records that
    were successfully verified along with timing information.
    """
    # The set of verified RRs, not including DnsKey, RRSig, NSec, and NSec3 records
    verified_rrs: List[Record]
    
    # The latest RRSig inception time of all validated signatures
    valid_from: int
    
    # The earliest RRSig expiration time of all validated signatures  
    expires: int
    
    # The minimum original TTL of all validated signatures
    max_cache_ttl: int
    
    def resolve_name(self, name_param: Name) -> List[Record]:
        """
        Resolve a name by following CNAME and DNAME redirections
        
        Args:
            name_param: The name to resolve
            
        Returns:
            List of records that match the resolved name
        """
        name = name_param
        dname_name = None
        
        while True:
            # Look for CNAME records
            cname_records = [
                rr for rr in self.verified_rrs 
                if isinstance(rr, CName) and rr.name == name
            ]
            
            if cname_records:
                # Follow the CNAME
                name = cname_records[0].canonical_name
                continue
            
            # Look for DNAME records
            dname_records = [
                rr for rr in self.verified_rrs 
                if isinstance(rr, DName) and name.name.endswith(rr.name.name)
            ]
            
            if dname_records:
                dname = dname_records[0]
                # Strip the suffix and replace with delegation name
                if name.name.endswith(dname.name.name):
                    prefix = name.name[:-len(dname.name.name)]
                    resolved_name_str = prefix + dname.delegation_name.name
                    try:
                        dname_name = Name(resolved_name_str)
                        name = dname_name
                        continue
                    except ValueError:
                        # Combined name too long
                        return []
            
            # No more redirections, return matching records
            return [rr for rr in self.verified_rrs if rr.name == name]


def resolve_time(time_value: int) -> int:
    """
    Resolve DNSSEC time values which may wrap around in 2106
    
    RFC 2065 was published in January 1997, so we arbitrarily use that as a cutoff and assume
    any timestamps before then are actually past 2106 instead.
    We ignore leap years for simplicity.
    """
    # Cutoff: approximately 27 years after Unix epoch (around 1997)
    cutoff = 60 * 60 * 24 * 365 * 27
    
    if time_value < cutoff:
        # Assume this is a post-2106 timestamp
        return time_value + (2**32)
    else:
        return time_value


def verify_rrsig(signature: RRSig, dnskeys: List[DnsKey], records: List[Record]) -> bool:
    """
    Verify an RRSig signature against a set of DNSKEYs and the records it should cover
    
    Args:
        signature: The RRSig to verify
        dnskeys: List of potential signing keys
        records: List of records that should be covered by this signature
        
    Returns:
        True if the signature is valid, False otherwise
        
    Raises:
        ValidationError: If validation fails due to unsupported algorithms or other issues
    """
    # Verify that all records match the signature's type
    for record in records:
        if signature.type_covered != record.type_code:
            raise ValidationError(ValidationError.ErrorType.INVALID, 
                                "Record type doesn't match signature type")
    
    # Find the matching DNSKEY
    for dnskey in dnskeys:
        if dnskey.key_tag() != signature.key_tag:
            continue
        
        # Protocol must be 3 for DNSSEC
        if dnskey.protocol != 3:
            continue
        
        # The ZONE flag must be set for validation
        if (dnskey.flags & 0b100000000) == 0:
            continue
        
        # Algorithm must match
        if dnskey.algorithm != signature.algorithm:
            continue
        
        # Choose hash algorithm based on signature algorithm
        if signature.algorithm == 8:  # RSA/SHA-256
            hasher = Hasher.sha256()
        elif signature.algorithm == 10:  # RSA/SHA-512
            hasher = Hasher.sha512()
        elif signature.algorithm == 13:  # ECDSA Curve P-256 with SHA-256
            hasher = Hasher.sha256()
        elif signature.algorithm == 14:  # ECDSA Curve P-384 with SHA-384
            hasher = Hasher.sha384()
        elif signature.algorithm == 15:  # ECDSA Curve P-521 with SHA-512
            hasher = Hasher.sha512()
        else:
            raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM,
                                f"Algorithm {signature.algorithm} not supported")
        
        # Build the signature data according to RFC 4034
        # First, add the RRSIG RDATA (without the signature field)
        hasher.update(signature.type_covered.to_bytes(2, 'big'))
        hasher.update(signature.algorithm.to_bytes(1, 'big'))
        hasher.update(signature.labels.to_bytes(1, 'big'))
        hasher.update(signature.original_ttl.to_bytes(4, 'big'))
        hasher.update(signature.expiration.to_bytes(4, 'big'))
        hasher.update(signature.inception.to_bytes(4, 'big'))
        hasher.update(signature.key_tag.to_bytes(2, 'big'))
        
        # Add the signer name
        signer_name_buf = BytesIO()
        write_name(signer_name_buf, str(signature.signer_name))
        hasher.update(signer_name_buf.getvalue())
        
        # Sort and deduplicate records (some resolvers give duplicates)
        sorted_records = sorted(records)
        unique_records = []
        for record in sorted_records:
            if not unique_records or record != unique_records[-1]:
                unique_records.append(record)
        
        # Add each record to the hash
        for record in unique_records:
            record_labels = record.name.labels()
            sig_labels = signature.labels
            
            # Handle wildcards
            if record_labels > sig_labels:
                # This is a wildcard expansion
                wildcard_name = "*." + (record.name.trailing_n_labels(sig_labels - 1) or "")
                name_to_hash = Name(wildcard_name)
            else:
                name_to_hash = record.name
            
            # Add the canonical name
            name_buf = BytesIO()
            write_name(name_buf, str(name_to_hash))
            hasher.update(name_buf.getvalue())
            
            # Add type, class, TTL, and data
            hasher.update(record.type_code.to_bytes(2, 'big'))
            hasher.update((1).to_bytes(2, 'big'))  # Internet class
            hasher.update(signature.original_ttl.to_bytes(4, 'big'))
            
            # Add record data with length prefix
            data_buf = BytesIO()
            record.write_data(data_buf)
            data = data_buf.getvalue()
            hasher.update(len(data).to_bytes(2, 'big'))
            hasher.update(data)
        
        # Get the hash
        hash_result = hasher.finish()
        
        # Verify the signature based on algorithm
        if signature.algorithm in [8, 10]:  # RSA algorithms
            return validate_rsa(dnskey.public_key, signature.signature, hash_result.as_ref())
        elif signature.algorithm == 13:  # ECDSA P-256
            return validate_ecdsa_256r1(dnskey.public_key, signature.signature, hash_result.as_ref())
        elif signature.algorithm == 14:  # ECDSA P-384
            return validate_ecdsa_384r1(dnskey.public_key, signature.signature, hash_result.as_ref())
        else:
            raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM,
                                f"Algorithm {signature.algorithm} not supported")
    
    # No matching key found
    return False


def verify_rr_set(signatures: List[RRSig], validated_dnskeys: List[DnsKey], 
                  records: List[Record]) -> RRSig:
    """
    Verify a set of RRSig signatures against validated DNSKEYs
    
    Args:
        signatures: List of RRSig records to try
        validated_dnskeys: List of validated DNSKEY records
        records: List of records that should be covered
        
    Returns:
        The first valid RRSig found
        
    Raises:
        ValidationError: If no valid signature is found
    """
    found_unsupported_alg = False
    
    for sig in signatures:
        # Check if we have a matching validated key
        if not any(key.key_tag() == sig.key_tag for key in validated_dnskeys):
            # Some DNS servers include spurious RRSig records. Ignore them.
            continue
        
        try:
            if verify_rrsig(sig, validated_dnskeys, records):
                return sig
        except ValidationError as e:
            if e.error_type == ValidationError.ErrorType.UNSUPPORTED_ALGORITHM:
                # There may be redundant signatures by different keys, where one we don't
                # support and another we do. Ignore ones we don't support.
                found_unsupported_alg = True
            elif e.error_type == ValidationError.ErrorType.INVALID:
                # If a signature is invalid, immediately fail to avoid KeyTrap issues
                raise e
            else:
                raise e
    
    if found_unsupported_alg:
        raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM)
    else:
        raise ValidationError(ValidationError.ErrorType.INVALID, "No valid signature found")


def verify_rr_stream(rr_stream: List[Record]) -> VerifiedRRStream:
    """
    Verify a stream of DNS records using DNSSEC
    
    This is the main entry point for DNSSEC validation. It takes a list of DNS records
    (typically from an RFC 9102 proof) and validates them using DNSSEC signatures.
    
    Args:
        rr_stream: List of DNS resource records to validate
        
    Returns:
        VerifiedRRStream containing the validated records and timing information
        
    Raises:
        ValidationError: If validation fails
    """
    # Separate records by type
    dnskeys: List[DnsKey] = []
    ds_records: List[DS] = []
    rrsigs: List[RRSig] = []
    other_records: List[Record] = []
    
    for record in rr_stream:
        if isinstance(record, DnsKey):
            dnskeys.append(record)
        elif isinstance(record, DS):
            ds_records.append(record)
        elif isinstance(record, RRSig):
            rrsigs.append(record)
        else:
            other_records.append(record)
    
    # Start with root trust anchors
    trusted_ds_records = root_hints()
    validated_records: List[Record] = []
    
    # Track timing information
    earliest_expiration = float('inf')
    latest_inception = 0
    min_original_ttl = float('inf')
    
    validation_steps = 0
    
    # Validate chain of trust
    while validation_steps < MAX_PROOF_STEPS:
        validation_steps += 1
        
        made_progress = False
        
        # Try to validate DNSKEYs using DS records
        for ds in trusted_ds_records:
            # Find DNSKEYs for this zone
            zone_dnskeys = [k for k in dnskeys if k.name == ds.name]
            if not zone_dnskeys:
                continue
            
            # Find matching DNSKEY for this DS
            for dnskey in zone_dnskeys:
                if (dnskey.key_tag() == ds.key_tag and 
                    dnskey.algorithm == ds.algorithm):
                    
                    # Verify the DS digest
                    if ds.digest_type == 2:  # SHA-256
                        hasher = Hasher.sha256()
                    elif ds.digest_type == 1:  # SHA-1
                        hasher = Hasher.sha1()
                    else:
                        continue  # Unsupported digest type
                    
                    # Hash the DNSKEY
                    name_buf = BytesIO()
                    write_name(name_buf, str(dnskey.name))
                    hasher.update(name_buf.getvalue())
                    
                    key_data_buf = BytesIO()
                    dnskey.write_data(key_data_buf)
                    hasher.update(key_data_buf.getvalue())
                    
                    computed_digest = hasher.finish()
                    
                    if computed_digest.as_ref() == ds.digest:
                        # This DNSKEY is validated by the DS
                        if dnskey not in validated_records:
                            validated_records.append(dnskey)
                            made_progress = True
        
        # Try to validate other records using validated DNSKEYs
        validated_dnskeys = [r for r in validated_records if isinstance(r, DnsKey)]
        
        # Group RRSigs by what they sign
        rrsig_groups: Dict[Tuple[str, int], List[RRSig]] = {}
        for rrsig in rrsigs:
            key = (str(rrsig.name), rrsig.type_covered)
            if key not in rrsig_groups:
                rrsig_groups[key] = []
            rrsig_groups[key].append(rrsig)
        
        # Try to validate record sets
        for (name_str, record_type), signatures in rrsig_groups.items():
            name = Name(name_str)
            
            # Find records of this type at this name
            matching_records = [r for r in other_records + dnskeys + ds_records 
                              if r.name == name and r.type_code == record_type]
            
            if not matching_records:
                continue
            
            # Skip if already validated
            if all(r in validated_records for r in matching_records):
                continue
            
            try:
                valid_rrsig = verify_rr_set(signatures, validated_dnskeys, matching_records)
                
                # Add these records as validated
                for record in matching_records:
                    if record not in validated_records:
                        validated_records.append(record)
                        made_progress = True
                
                # Update timing information
                earliest_expiration = min(earliest_expiration, resolve_time(valid_rrsig.expiration))
                latest_inception = max(latest_inception, resolve_time(valid_rrsig.inception))
                min_original_ttl = min(min_original_ttl, valid_rrsig.original_ttl)
                
                # If we validated DS records, add them to trusted set
                for record in matching_records:
                    if isinstance(record, DS) and record not in trusted_ds_records:
                        trusted_ds_records.append(record)
                        
            except ValidationError:
                # This record set couldn't be validated, continue with others
                continue
        
        if not made_progress:
            break
    
    # Filter out DNSSEC infrastructure records from the final result
    final_records = [r for r in validated_records 
                    if not isinstance(r, (DnsKey, DS, RRSig))]
    
    return VerifiedRRStream(
        verified_rrs=final_records,
        valid_from=latest_inception,
        expires=int(earliest_expiration) if earliest_expiration != float('inf') else 0,
        max_cache_ttl=int(min_original_ttl) if min_original_ttl != float('inf') else 0
    ) 


def verify_byte_stream(stream: bytes, name_to_resolve: str) -> str:
    """
    Verifies an RFC 9102-formatted proof and returns verified records matching the given name
    (resolving any C/DNAMEs as required).
    
    This function matches the UniFFI interface from the Rust implementation.
    
    Args:
        stream: RFC 9102-formatted proof as bytes
        name_to_resolve: Domain name to resolve
        
    Returns:
        JSON string with verification results or error
    """
    try:
        name = Name(name_to_resolve)
    except ValueError:
        return '{"error":"Bad name to resolve"}'
    
    try:
        return _do_verify_byte_stream(stream, name)
    except ValidationError as e:
        return f'{{"error":"{e.error_type.value}"}}'
    except Exception as e:
        return f'{{"error":"Invalid: {str(e)}"}}'


def _do_verify_byte_stream(stream: bytes, name_to_resolve: Name) -> str:
    """
    Internal implementation of verify_byte_stream that can raise exceptions.
    """
    try:
        from . import rr
    except ImportError:
        import rr
    
    # Parse RR stream from bytes
    rrs = rr.parse_rr_stream(stream)
    
    # Verify the RR stream  
    verified_rrs = verify_rr_stream(rrs)
    
    # Resolve the name (following CNAMEs/DNAMEs)
    resolved_rrs = verified_rrs.resolve_name(name_to_resolve)
    
    # Format as JSON
    import json
    
    verified_rrs_json = []
    for record in resolved_rrs:
        # Convert record to JSON (assuming records have a to_json method)
        if hasattr(record, 'to_json'):
            verified_rrs_json.append(json.loads(record.to_json()))
        else:
            # Fallback for records without to_json method
            verified_rrs_json.append({
                "type": type(record).__name__.lower(),
                "name": str(record.name)
            })
    
    result = {
        "valid_from": verified_rrs.valid_from,
        "expires": verified_rrs.expires, 
        "max_cache_ttl": verified_rrs.max_cache_ttl,
        "verified_rrs": verified_rrs_json
    }
    
    return json.dumps(result) 