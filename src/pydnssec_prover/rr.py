"""
Resource Records - the fundamental type in DNS

This module holds classes and utilities for the Resource Records supported by this library,
ported from the Rust implementation for DNSSEC validation.
"""

from typing import List, Dict, Any, Optional, Tuple, Union
from abc import ABC, abstractmethod
import struct
import json
from io import BytesIO

try:
    from . import ser
    from .ser import SerializationError
except ImportError:
    # Handle direct script execution
    import ser
    from ser import SerializationError


class Name:
    """
    A valid domain name.
    
    It must end with a ".", be no longer than 255 bytes, consist of only printable ASCII
    characters and each label may be no longer than 63 bytes.
    """
    
    def __init__(self, name: str):
        self._name = self._validate_and_normalize(name)
    
    @staticmethod
    def _validate_and_normalize(name: str) -> str:
        """Validate and normalize a domain name"""
        if not name:
            raise ValueError("Name cannot be empty")
        
        if not name.endswith('.'):
            raise ValueError("Name must end with '.'")
        
        if len(name.encode('utf-8')) > 255:
            raise ValueError("Name too long (max 255 bytes)")
        
        # Check for printable ASCII characters (excluding quote)
        for char in name:
            if not (char.isprintable() and ord(char) < 128) or char == '"':
                raise ValueError("Name contains invalid characters")
        
        # Check label lengths
        labels = name.split('.')
        for label in labels[:-1]:  # Skip the empty label from trailing dot
            if len(label.encode('utf-8')) > 63:
                raise ValueError("Label too long (max 63 bytes)")
        
        return name.lower()
    
    @property
    def name(self) -> str:
        """Get the underlying domain name string"""
        return self._name
    
    def labels(self) -> int:
        """Get the number of labels in this name"""
        if self._name == ".":
            return 0
        return self._name.count('.')
    
    def trailing_n_labels(self, n: int) -> Optional[str]:
        """Get a string containing the last n labels in this Name"""
        current_labels = self.labels()
        if n > current_labels:
            return None
        elif n == current_labels:
            return self._name
        elif n == 0:
            return "."
        else:
            parts = self._name.split('.')
            # Take the last n non-empty parts plus the empty trailing part
            return '.'.join(parts[-(n+1):])
    
    def __str__(self) -> str:
        return self._name
    
    def __repr__(self) -> str:
        return f"Name('{self._name}')"
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Name):
            return self._name == other._name
        elif isinstance(other, str):
            try:
                return self._name == self._validate_and_normalize(other)
            except ValueError:
                return False
        return False
    
    def __hash__(self) -> int:
        return hash(self._name)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, Name):
            return self._name < other._name
        return NotImplemented


class NSecTypeMask:
    """
    A mask used in NSec and NSec3 records which indicates the resource record types which
    exist at the (hash of the) name described in Record.name.
    """
    
    def __init__(self, flags: Optional[bytes] = None):
        """Initialize with optional flags bytes (8192 bytes)"""
        if flags is None:
            self._flags = bytearray(8192)
        else:
            if len(flags) != 8192:
                raise ValueError("NSecTypeMask flags must be exactly 8192 bytes")
            self._flags = bytearray(flags)
    
    @classmethod
    def new(cls) -> 'NSecTypeMask':
        """Constructs a new, empty, type mask."""
        return cls()
    
    @classmethod
    def from_types(cls, types: List[int]) -> 'NSecTypeMask':
        """Builds a new type mask with the given types set"""
        flags = bytearray(8192)
        for t in types:
            flags[t >> 3] |= 1 << (7 - (t % 8))
        return cls(flags)
    
    def contains_type(self, ty: int) -> bool:
        """Checks if the given type is set, indicating a record of this type exists."""
        f = self._flags[ty >> 3]
        # DNSSEC's bit fields are in wire order, so the high bit is type 0, etc.
        return (f & (1 << (7 - (ty % 8)))) != 0
    
    def as_bytes(self) -> bytes:
        """Get the raw flags as bytes"""
        return bytes(self._flags)
    
    def __eq__(self, other) -> bool:
        return isinstance(other, NSecTypeMask) and self._flags == other._flags
    
    def __hash__(self) -> int:
        return hash(bytes(self._flags))


class Record(ABC):
    """Abstract base class for DNS resource records"""
    
    @property
    @abstractmethod
    def name(self) -> Name:
        """Get the name this record refers to"""
        pass
    
    @property
    @abstractmethod
    def type_code(self) -> int:
        """Get the DNS type code for this record"""
        pass
    
    @abstractmethod
    def to_json(self) -> str:
        """Get a JSON representation of this record"""
        pass
    
    @classmethod
    @abstractmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'Record':
        """Parse this record type from wire format data"""
        pass
    
    @abstractmethod
    def write_data(self, out: BytesIO):
        """Write this record's data in wire format (without name/type/class/ttl header)"""
        pass
    
    def data_len(self) -> int:
        """Calculate the wire format length of this record's data"""
        buf = BytesIO()
        self.write_data(buf)
        return len(buf.getvalue())


class A(Record):
    """An IPv4 address resource record"""
    
    TYPE = 1
    
    def __init__(self, name: Name, address: str):
        self._name = name
        # Parse IPv4 address
        parts = address.split('.')
        if len(parts) != 4:
            raise ValueError("Invalid IPv4 address")
        try:
            self.address_bytes = bytes(int(part) for part in parts)
        except ValueError:
            raise ValueError("Invalid IPv4 address")
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    @property
    def address(self) -> str:
        """Get the IPv4 address as a string"""
        return '.'.join(str(b) for b in self.address_bytes)
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "a",
            "name": str(self._name),
            "address": self.address
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'A':
        if len(data) != 4:
            raise SerializationError("A record must be exactly 4 bytes")
        address = '.'.join(str(b) for b in data)
        return cls(name, address)
    
    def write_data(self, out: BytesIO):
        out.write(self.address_bytes)
    
    def __eq__(self, other) -> bool:
        return isinstance(other, A) and self._name == other._name and self.address_bytes == other.address_bytes
    
    def __lt__(self, other) -> bool:
        if isinstance(other, A):
            return (self._name, self.address_bytes) < (other._name, other.address_bytes)
        return NotImplemented


class AAAA(Record):
    """An IPv6 address resource record"""
    
    TYPE = 28
    
    def __init__(self, name: Name, address: str):
        self._name = name
        # Parse IPv6 address - simplified version
        import ipaddress
        try:
            addr = ipaddress.IPv6Address(address)
            self.address_bytes = addr.packed
        except ValueError:
            raise ValueError("Invalid IPv6 address")
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    @property
    def address(self) -> str:
        """Get the IPv6 address as a string"""
        import ipaddress
        return str(ipaddress.IPv6Address(self.address_bytes))
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "aaaa",
            "name": str(self._name),
            "address": self.address
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'AAAA':
        if len(data) != 16:
            raise SerializationError("AAAA record must be exactly 16 bytes")
        import ipaddress
        address = str(ipaddress.IPv6Address(data))
        return cls(name, address)
    
    def write_data(self, out: BytesIO):
        out.write(self.address_bytes)
    
    def __eq__(self, other) -> bool:
        return isinstance(other, AAAA) and self._name == other._name and self.address_bytes == other.address_bytes
    
    def __lt__(self, other) -> bool:
        if isinstance(other, AAAA):
            return (self._name, self.address_bytes) < (other._name, other.address_bytes)
        return NotImplemented


class NS(Record):
    """A name server resource record"""
    
    TYPE = 2
    
    def __init__(self, name: Name, target: Name):
        self._name = name
        self.target = target
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "ns",
            "name": str(self._name),
            "target": str(self.target)
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'NS':
        target_name, _ = ser.read_wire_packet_name(data, 0, wire_packet)
        return cls(name, Name(target_name))
    
    def write_data(self, out: BytesIO):
        ser.write_name(out, str(self.target))
    
    def __eq__(self, other) -> bool:
        return isinstance(other, NS) and self._name == other._name and self.target == other.target
    
    def __lt__(self, other) -> bool:
        if isinstance(other, NS):
            return (self._name, self.target) < (other._name, other.target)
        return NotImplemented


class Txt(Record):
    """A text resource record, containing arbitrary text data"""
    
    TYPE = 16
    
    def __init__(self, name: Name, data: bytes):
        self._name = name
        # Store as chunks like the Rust implementation for exact wire format compatibility
        self.data_chunks = self._split_into_chunks(data)
    
    @staticmethod
    def _split_into_chunks(data: bytes) -> List[bytes]:
        """Split data into 255-byte chunks like the Rust TxtBytes"""
        if len(data) > 255 * 255 + 254:
            raise ValueError("TXT data too long")
        
        chunks = []
        offset = 0
        while offset < len(data):
            chunk_size = min(255, len(data) - offset)
            chunks.append(data[offset:offset + chunk_size])
            offset += chunk_size
        return chunks
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    @property
    def data(self) -> bytes:
        """Get the text data as bytes"""
        return b''.join(self.data_chunks)
    
    def to_json(self) -> str:
        data = self.data
        if all(0x20 <= b <= 0x7e for b in data):
            # All printable ASCII
            try:
                content = data.decode('utf-8')
                return json.dumps({
                    "type": "txt",
                    "name": str(self._name),
                    "contents": content
                })
            except UnicodeDecodeError:
                pass
        
        # Non-printable data, return as array of bytes
        return json.dumps({
            "type": "txt",
            "name": str(self._name),
            "contents": list(data)
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'Txt':
        # Parse TXT data according to DNS wire format (length-prefixed strings)
        chunks = []
        offset = 0
        
        while offset < len(data):
            if offset >= len(data):
                raise SerializationError("Incomplete TXT record")
            
            length = data[offset]
            offset += 1
            
            if length == 0:
                raise SerializationError("Empty TXT chunk not allowed")
            
            if offset + length > len(data):
                raise SerializationError("TXT chunk extends beyond record")
            
            chunks.append(data[offset:offset + length])
            offset += length
        
        # Reconstruct the original data
        full_data = b''.join(chunks)
        return cls(name, full_data)
    
    def write_data(self, out: BytesIO):
        for chunk in self.data_chunks:
            out.write(struct.pack('B', len(chunk)))
            out.write(chunk)
    
    def __eq__(self, other) -> bool:
        return isinstance(other, Txt) and self._name == other._name and self.data == other.data
    
    def __lt__(self, other) -> bool:
        if isinstance(other, Txt):
            # Compare in wire encoding form like the Rust implementation
            if self._name != other._name:
                return self._name < other._name
            
            # Compare chunks
            for i, chunk in enumerate(self.data_chunks):
                if i >= len(other.data_chunks):
                    return False  # self has more chunks
                other_chunk = other.data_chunks[i]
                if len(chunk) != len(other_chunk):
                    return len(chunk) < len(other_chunk)
                if chunk != other_chunk:
                    return chunk < other_chunk
            
            return len(self.data_chunks) < len(other.data_chunks)
        
        return NotImplemented


class TLSA(Record):
    """A TLS Certificate Association resource record"""
    
    TYPE = 52
    
    def __init__(self, name: Name, cert_usage: int, selector: int, data_type: int, data: bytes):
        self._name = name
        self.cert_usage = cert_usage
        self.selector = selector
        self.data_type = data_type
        self.cert_data = data
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "tlsa",
            "name": str(self._name),
            "usage": self.cert_usage,
            "selector": self.selector,
            "data_type": self.data_type,
            "data": self.cert_data.hex().upper()
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'TLSA':
        if len(data) < 3:
            raise SerializationError("TLSA record too short")
        
        cert_usage = data[0]
        selector = data[1]
        data_type = data[2]
        cert_data = data[3:]
        
        return cls(name, cert_usage, selector, data_type, cert_data)
    
    def write_data(self, out: BytesIO):
        out.write(struct.pack('B', self.cert_usage))
        out.write(struct.pack('B', self.selector))
        out.write(struct.pack('B', self.data_type))
        out.write(self.cert_data)
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, TLSA) and 
                self._name == other._name and 
                self.cert_usage == other.cert_usage and
                self.selector == other.selector and
                self.data_type == other.data_type and
                self.cert_data == other.cert_data)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, TLSA):
            return ((self._name, self.cert_usage, self.selector, self.data_type, self.cert_data) < 
                    (other._name, other.cert_usage, other.selector, other.data_type, other.cert_data))
        return NotImplemented


class CName(Record):
    """A Canonical Name resource record, referring all queries for this name to another name."""
    
    TYPE = 5
    
    def __init__(self, name: Name, canonical_name: Name):
        self._name = name
        self.canonical_name = canonical_name
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "cname",
            "name": str(self._name),
            "canonical_name": str(self.canonical_name)
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'CName':
        canonical_name_str, _ = ser.read_wire_packet_name(data, 0, wire_packet)
        return cls(name, Name(canonical_name_str))
    
    def write_data(self, out: BytesIO):
        ser.write_name(out, str(self.canonical_name))
    
    def __eq__(self, other) -> bool:
        return isinstance(other, CName) and self._name == other._name and self.canonical_name == other.canonical_name
    
    def __lt__(self, other) -> bool:
        if isinstance(other, CName):
            return (self._name, self.canonical_name) < (other._name, other.canonical_name)
        return NotImplemented


class DName(Record):
    """A Delegation Name resource record, referring all queries for subdomains of this name to another subtree of the DNS."""
    
    TYPE = 39
    
    def __init__(self, name: Name, delegation_name: Name):
        self._name = name
        self.delegation_name = delegation_name
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "dname",
            "name": str(self._name),
            "delegation_name": str(self.delegation_name)
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'DName':
        delegation_name_str, _ = ser.read_wire_packet_name(data, 0, wire_packet)
        return cls(name, Name(delegation_name_str))
    
    def write_data(self, out: BytesIO):
        ser.write_name(out, str(self.delegation_name))
    
    def __eq__(self, other) -> bool:
        return isinstance(other, DName) and self._name == other._name and self.delegation_name == other.delegation_name
    
    def __lt__(self, other) -> bool:
        if isinstance(other, DName):
            return (self._name, self.delegation_name) < (other._name, other.delegation_name)
        return NotImplemented


class DnsKey(Record):
    """A public key resource record which can be used to validate RRSigs"""
    
    TYPE = 48
    
    def __init__(self, name: Name, flags: int, protocol: int, algorithm: int, public_key: bytes):
        self._name = name
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.public_key = public_key
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def key_tag(self) -> int:
        """Calculate the key tag for this DNSKEY"""
        # RFC 4034 Appendix B
        total = self.flags
        total += (self.protocol << 8)
        total += self.algorithm
        
        for i, byte in enumerate(self.public_key):
            if i % 2 == 0:
                total += byte << 8
            else:
                total += byte
        
        total += (total >> 16) & 0xffff
        return total & 0xffff
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "dnskey",
            "name": str(self._name),
            "flags": self.flags,
            "protocol": self.protocol,
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex().upper()
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'DnsKey':
        if len(data) < 4:
            raise SerializationError("DNSKEY record too short")
        
        flags = struct.unpack('>H', data[0:2])[0]
        protocol = data[2]
        algorithm = data[3]
        public_key = data[4:]
        
        return cls(name, flags, protocol, algorithm, public_key)
    
    def write_data(self, out: BytesIO):
        out.write(struct.pack('>H', self.flags))
        out.write(struct.pack('B', self.protocol))
        out.write(struct.pack('B', self.algorithm))
        out.write(self.public_key)
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, DnsKey) and 
                self._name == other._name and 
                self.flags == other.flags and
                self.protocol == other.protocol and
                self.algorithm == other.algorithm and
                self.public_key == other.public_key)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, DnsKey):
            return ((self._name, self.flags, self.protocol, self.algorithm, self.public_key) < 
                    (other._name, other.flags, other.protocol, other.algorithm, other.public_key))
        return NotImplemented


class DS(Record):
    """A Delegation Signer resource record"""
    
    TYPE = 43
    
    def __init__(self, name: Name, key_tag: int, algorithm: int, digest_type: int, digest: bytes):
        self._name = name
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "ds",
            "name": str(self._name),
            "key_tag": self.key_tag,
            "algorithm": self.algorithm,
            "digest_type": self.digest_type,
            "digest": self.digest.hex().upper()
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'DS':
        if len(data) < 4:
            raise SerializationError("DS record too short")
        
        key_tag = struct.unpack('>H', data[0:2])[0]
        algorithm = data[2]
        digest_type = data[3]
        digest = data[4:]
        
        return cls(name, key_tag, algorithm, digest_type, digest)
    
    def write_data(self, out: BytesIO):
        out.write(struct.pack('>H', self.key_tag))
        out.write(struct.pack('B', self.algorithm))
        out.write(struct.pack('B', self.digest_type))
        out.write(self.digest)
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, DS) and 
                self._name == other._name and 
                self.key_tag == other.key_tag and
                self.algorithm == other.algorithm and
                self.digest_type == other.digest_type and
                self.digest == other.digest)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, DS):
            return ((self._name, self.key_tag, self.algorithm, self.digest_type, self.digest) < 
                    (other._name, other.key_tag, other.algorithm, other.digest_type, other.digest))
        return NotImplemented


class RRSig(Record):
    """A Resource Record (set) Signature record"""
    
    TYPE = 46
    
    def __init__(self, name: Name, type_covered: int, algorithm: int, labels: int, 
                 original_ttl: int, expiration: int, inception: int, key_tag: int, 
                 signer_name: Name, signature: bytes):
        self._name = name
        self.type_covered = type_covered
        self.algorithm = algorithm
        self.labels = labels
        self.original_ttl = original_ttl
        self.expiration = expiration
        self.inception = inception
        self.key_tag = key_tag
        self.signer_name = signer_name
        self.signature = signature
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        return json.dumps({
            "type": "rrsig",
            "name": str(self._name),
            "type_covered": self.type_covered,
            "algorithm": self.algorithm,
            "labels": self.labels,
            "original_ttl": self.original_ttl,
            "expiration": self.expiration,
            "inception": self.inception,
            "key_tag": self.key_tag,
            "signer_name": str(self.signer_name),
            "signature": self.signature.hex().upper()
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'RRSig':
        if len(data) < 18:  # Minimum size without signer name and signature
            raise SerializationError("RRSIG record too short")
        
        offset = 0
        type_covered = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        algorithm = data[offset]
        offset += 1
        labels = data[offset]
        offset += 1
        original_ttl = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        expiration = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        inception = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        key_tag = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        signer_name_str, offset = ser.read_wire_packet_name(data, offset, wire_packet)
        signer_name = Name(signer_name_str)
        signature = data[offset:]
        
        return cls(name, type_covered, algorithm, labels, original_ttl, 
                  expiration, inception, key_tag, signer_name, signature)
    
    def write_data(self, out: BytesIO):
        out.write(struct.pack('>H', self.type_covered))
        out.write(struct.pack('B', self.algorithm))
        out.write(struct.pack('B', self.labels))
        out.write(struct.pack('>I', self.original_ttl))
        out.write(struct.pack('>I', self.expiration))
        out.write(struct.pack('>I', self.inception))
        out.write(struct.pack('>H', self.key_tag))
        ser.write_name(out, str(self.signer_name))
        out.write(self.signature)
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, RRSig) and 
                self._name == other._name and 
                self.type_covered == other.type_covered and
                self.algorithm == other.algorithm and
                self.labels == other.labels and
                self.original_ttl == other.original_ttl and
                self.expiration == other.expiration and
                self.inception == other.inception and
                self.key_tag == other.key_tag and
                self.signer_name == other.signer_name and
                self.signature == other.signature)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, RRSig):
            return ((self._name, self.type_covered, self.algorithm, self.labels, self.original_ttl,
                    self.expiration, self.inception, self.key_tag, self.signer_name, self.signature) < 
                   (other._name, other.type_covered, other.algorithm, other.labels, other.original_ttl,
                    other.expiration, other.inception, other.key_tag, other.signer_name, other.signature))
        return NotImplemented


class NSec(Record):
    """A Next Secure Record resource record. This indicates a range of possible names for which there is no such record."""
    
    TYPE = 47
    
    def __init__(self, name: Name, next_name: Name, types: NSecTypeMask):
        self._name = name
        self.next_name = next_name
        self.types = types
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        # Simple representation for types
        types_list = []
        for i in range(8192 * 8):
            if self.types.contains_type(i):
                types_list.append(i)
        
        return json.dumps({
            "type": "nsec",
            "name": str(self._name),
            "next_name": str(self.next_name),
            "types": types_list
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'NSec':
        next_name_str, offset = ser.read_wire_packet_name(data, 0, wire_packet)
        next_name = Name(next_name_str)
        
        # Read NSEC types bitmap
        types_data, _ = ser.read_nsec_types_bitmap(data, offset, len(data) - offset)
        types = NSecTypeMask(types_data)
        
        return cls(name, next_name, types)
    
    def write_data(self, out: BytesIO):
        # Write next name
        ser.write_name(out, str(self.next_name))
        
        # Write types bitmap
        ser.write_nsec_types_bitmap(out, self.types.as_bytes())
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, NSec) and 
                self._name == other._name and 
                self.next_name == other.next_name and
                self.types == other.types)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, NSec):
            return ((self._name, self.next_name, self.types.as_bytes()) < 
                    (other._name, other.next_name, other.types.as_bytes()))
        return NotImplemented


class NSec3(Record):
    """A Next Secure Record version 3 resource record. This indicates a range of possible names for which there is no such record."""
    
    TYPE = 50
    
    def __init__(self, name: Name, hash_algorithm: int, flags: int, hash_iterations: int, 
                 salt: bytes, next_name_hash: bytes, types: NSecTypeMask):
        self._name = name
        self.hash_algorithm = hash_algorithm
        self.flags = flags
        self.hash_iterations = hash_iterations
        self.salt = salt
        self.next_name_hash = next_name_hash
        self.types = types
    
    @property
    def name(self) -> Name:
        return self._name
    
    @property
    def type_code(self) -> int:
        return self.TYPE
    
    def to_json(self) -> str:
        # Simple representation for types
        types_list = []
        for i in range(8192 * 8):
            if self.types.contains_type(i):
                types_list.append(i)
        
        return json.dumps({
            "type": "nsec3",
            "name": str(self._name),
            "hash_algorithm": self.hash_algorithm,
            "flags": self.flags,
            "hash_iterations": self.hash_iterations,
            "salt": self.salt.hex().upper(),
            "next_name_hash": self.next_name_hash.hex().upper(),
            "types": types_list
        })
    
    @classmethod
    def from_wire_data(cls, name: Name, data: bytes, wire_packet: Optional[bytes] = None) -> 'NSec3':
        if len(data) < 5:
            raise SerializationError("NSEC3 record too short")
        
        offset = 0
        hash_algorithm = data[offset]
        offset += 1
        flags = data[offset]
        offset += 1
        hash_iterations = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # Read salt
        salt, offset = ser.read_u8_len_prefixed_bytes(data, offset)
        
        # Read next name hash
        next_name_hash, offset = ser.read_u8_len_prefixed_bytes(data, offset)
        
        # Read NSEC types bitmap
        types_data, _ = ser.read_nsec_types_bitmap(data, offset, len(data) - offset)
        types = NSecTypeMask(types_data)
        
        return cls(name, hash_algorithm, flags, hash_iterations, salt, next_name_hash, types)
    
    def write_data(self, out: BytesIO):
        out.write(struct.pack('B', self.hash_algorithm))
        out.write(struct.pack('B', self.flags))
        out.write(struct.pack('>H', self.hash_iterations))
        
        # Write salt with length prefix
        out.write(struct.pack('B', len(self.salt)))
        out.write(self.salt)
        
        # Write next name hash with length prefix
        out.write(struct.pack('B', len(self.next_name_hash)))
        out.write(self.next_name_hash)
        
        # Write types bitmap
        ser.write_nsec_types_bitmap(out, self.types.as_bytes())
    
    def __eq__(self, other) -> bool:
        return (isinstance(other, NSec3) and 
                self._name == other._name and 
                self.hash_algorithm == other.hash_algorithm and
                self.flags == other.flags and
                self.hash_iterations == other.hash_iterations and
                self.salt == other.salt and
                self.next_name_hash == other.next_name_hash and
                self.types == other.types)
    
    def __lt__(self, other) -> bool:
        if isinstance(other, NSec3):
            return ((self._name, self.hash_algorithm, self.flags, self.hash_iterations, 
                    self.salt, self.next_name_hash, self.types.as_bytes()) < 
                   (other._name, other.hash_algorithm, other.flags, other.hash_iterations,
                    other.salt, other.next_name_hash, other.types.as_bytes()))
        return NotImplemented


# Record type registry
RECORD_TYPES = {
    A.TYPE: A,
    AAAA.TYPE: AAAA,
    NS.TYPE: NS,
    Txt.TYPE: Txt,
    TLSA.TYPE: TLSA,
    CName.TYPE: CName,
    DName.TYPE: DName,
    DnsKey.TYPE: DnsKey,
    DS.TYPE: DS,
    RRSig.TYPE: RRSig,
    NSec.TYPE: NSec,
    NSec3.TYPE: NSec3,
}


def parse_rr_stream(data: bytes) -> List[Record]:
    """
    Parse a stream of resource records from RFC 9102 format
    
    Args:
        data: Wire format resource record stream
        
    Returns:
        List of parsed resource records
    """
    records = []
    offset = 0
    
    while offset < len(data):
        # Parse record header
        name_str, offset = ser.read_wire_packet_name(data, offset)
        name = Name(name_str)
        
        if offset + 10 > len(data):
            raise SerializationError("Incomplete record header")
        
        rr_type = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        rr_class = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        ttl = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        rdlength = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        if rr_class != 1:  # Only support Internet class
            raise SerializationError("Unsupported record class")
        
        if offset + rdlength > len(data):
            raise SerializationError("Record data extends beyond packet")
        
        record_data = data[offset:offset + rdlength]
        offset += rdlength
        
        # Parse record based on type
        if rr_type in RECORD_TYPES:
            record = RECORD_TYPES[rr_type].from_wire_data(name, record_data, data)
            records.append(record)
        else:
            # Skip unknown record types
            continue
    
    return records


def write_rr(record: Record, ttl: int, out: BytesIO):
    """
    Write a resource record in wire format
    
    Args:
        record: The resource record to write
        ttl: Time to live value
        out: Output stream
    """
    # Write name
    ser.write_name(out, str(record.name))
    
    # Write type, class, TTL
    out.write(struct.pack('>H', record.type_code))
    out.write(struct.pack('>H', 1))  # Internet class
    out.write(struct.pack('>I', ttl))
    
    # Write data length and data
    data_buf = BytesIO()
    record.write_data(data_buf)
    data = data_buf.getvalue()
    
    out.write(struct.pack('>H', len(data)))
    out.write(data) 