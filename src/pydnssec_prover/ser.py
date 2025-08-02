"""
Logic to read and write resource record (streams) from DNS wire format

This module provides functions to parse DNS records from RFC 9102 format and 
serialize them back to wire format.
"""

from typing import List, Tuple, Optional, Union
import struct
from io import BytesIO


class SerializationError(Exception):
    """Error during serialization/deserialization"""
    pass


def read_u8(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u8 from bytes at offset, return (value, new_offset)"""
    if offset >= len(data):
        raise SerializationError("Not enough data for u8")
    return data[offset], offset + 1


def read_u16(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u16 from bytes at offset in big-endian format"""
    if offset + 1 >= len(data):
        raise SerializationError("Not enough data for u16")
    return struct.unpack('>H', data[offset:offset + 2])[0], offset + 2


def read_u32(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u32 from bytes at offset in big-endian format"""
    if offset + 3 >= len(data):
        raise SerializationError("Not enough data for u32")
    return struct.unpack('>I', data[offset:offset + 4])[0], offset + 4


def read_u8_len_prefixed_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read length-prefixed bytes where length is a u8"""
    if offset >= len(data):
        raise SerializationError("Not enough data for length byte")
    length = data[offset]
    offset += 1
    if offset + length > len(data):
        raise SerializationError("Not enough data for prefixed bytes")
    return data[offset:offset + length], offset + length


def write_nsec_types_bitmap(out: BytesIO, types: bytes):
    """Write NSEC types bitmap to output stream"""
    if len(types) != 8192:
        raise SerializationError("NSEC types bitmap must be 8192 bytes")
    
    # Process in 32-byte chunks (windows)
    for idx in range(0, len(types), 32):
        chunk = types[idx:idx + 32]
        # Find last non-zero byte in this window
        last_nonzero_idx = None
        for i in range(len(chunk) - 1, -1, -1):
            if chunk[i] != 0:
                last_nonzero_idx = i
                break
        
        if last_nonzero_idx is not None:
            window_block = idx // 32
            bitmap_length = last_nonzero_idx + 1
            out.write(struct.pack('B', window_block))
            out.write(struct.pack('B', bitmap_length))
            out.write(chunk[:bitmap_length])


def nsec_types_bitmap_len(types: bytes) -> int:
    """Calculate the serialized length of an NSEC types bitmap"""
    if len(types) != 8192:
        raise SerializationError("NSEC types bitmap must be 8192 bytes")
    
    total_len = 0
    for idx in range(0, len(types), 32):
        chunk = types[idx:idx + 32]
        # Find last non-zero byte in this window  
        last_nonzero_idx = None
        for i in range(len(chunk) - 1, -1, -1):
            if chunk[i] != 0:
                last_nonzero_idx = i
                break
        
        if last_nonzero_idx is not None:
            total_len += 2 + last_nonzero_idx + 1  # window_block + length + data
    
    return total_len


def read_nsec_types_bitmap(data: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    """Read NSEC types bitmap from wire format"""
    types = bytearray(8192)
    end_offset = offset + length
    
    while offset < end_offset:
        if offset + 1 >= end_offset:
            raise SerializationError("Incomplete NSEC bitmap window header")
        
        window_block = data[offset]
        bitmap_length = data[offset + 1]
        offset += 2
        
        if offset + bitmap_length > end_offset:
            raise SerializationError("NSEC bitmap window extends beyond available data")
        
        start_idx = window_block * 32
        if start_idx + bitmap_length > 8192:
            raise SerializationError("NSEC bitmap window exceeds maximum size")
        
        types[start_idx:start_idx + bitmap_length] = data[offset:offset + bitmap_length]
        offset += bitmap_length
    
    return bytes(types), offset


def read_wire_packet_name(data: bytes, offset: int, wire_packet: Optional[bytes] = None) -> Tuple[str, int]:
    """
    Read a DNS name from wire format, handling compression if wire_packet is provided
    
    Returns (name_string, new_offset)
    """
    if wire_packet is None:
        wire_packet = data
    
    name_parts = []
    original_offset = offset
    jumped = False
    
    while True:
        if offset >= len(data):
            raise SerializationError("Unexpected end of data while reading name")
        
        length = data[offset]
        offset += 1
        
        if length == 0:
            # End of name
            break
        elif length >= 0xc0:
            # Compression pointer
            if offset >= len(data):
                raise SerializationError("Incomplete compression pointer")
            
            pointer_offset = ((length & 0x3f) << 8) | data[offset]
            offset += 1
            
            if not jumped:
                original_offset = offset
                jumped = True
            
            if pointer_offset >= len(wire_packet):
                raise SerializationError("Compression pointer beyond packet bounds")
            
            offset = pointer_offset
            data = wire_packet
        else:
            # Regular label
            if offset + length > len(data):
                raise SerializationError("Label extends beyond available data")
            
            try:
                label = data[offset:offset + length].decode('utf-8')
            except UnicodeDecodeError:
                raise SerializationError("Invalid UTF-8 in DNS label")
            
            name_parts.append(label)
            offset += length
    
    if jumped:
        offset = original_offset
    
    if not name_parts:
        name = "."
    else:
        name = ".".join(name_parts) + "."
    
    return name, offset


def write_name(out: BytesIO, name: str):
    """Write a DNS name in wire format"""
    canonical_name = name.lower()
    if canonical_name == ".":
        out.write(b'\x00')
    else:
        # Remove trailing dot if present for processing
        if canonical_name.endswith('.'):
            canonical_name = canonical_name[:-1]
        
        for label in canonical_name.split('.'):
            label_bytes = label.encode('utf-8')
            if len(label_bytes) > 63:
                raise SerializationError("DNS label too long")
            out.write(struct.pack('B', len(label_bytes)))
            out.write(label_bytes)
        out.write(b'\x00')  # End of name


def name_len(name: str) -> int:
    """Calculate the wire format length of a DNS name"""
    canonical_name = name.lower()
    if canonical_name == ".":
        return 1
    else:
        if canonical_name.endswith('.'):
            canonical_name = canonical_name[:-1]
        
        total_len = 1  # Final null byte
        for label in canonical_name.split('.'):
            total_len += 1 + len(label.encode('utf-8'))  # Length byte + label
        return total_len 