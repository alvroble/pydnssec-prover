"""
Base32 encoding and decoding using RFC4648 "extended hex" format

This is a port of the base32 implementation from the Rust code,
which itself was adapted from https://crates.io/crates/base32
"""

from typing import List


# RFC4648 "extended hex" encoding table
RFC4648_ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"

# RFC4648 "extended hex" decoding table
# Maps from ASCII value - ord('0') to decoded value, -1 for invalid
RFC4648_INV_ALPHABET = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
]


def encode(data: bytes) -> str:
    """
    Encode bytes into a base32 string using RFC4648 extended hex format
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base32 encoded string
    """
    # output_length is calculated as follows:
    # / 5 divides the data length by the number of bits per chunk (5),
    # * 8 multiplies the result by the number of characters per chunk (8).
    # + 4 rounds up to the nearest character.
    output_length = (len(data) * 8 + 4) // 5
    
    encoded = encode_data(data, RFC4648_ALPHABET)
    
    # Truncate to actual output length (no padding)
    return encoded[:output_length].decode('ascii')


def decode(data: str) -> bytes:
    """
    Decode a base32 string into bytes using RFC4648 extended hex format
    
    Args:
        data: Base32 string to decode
        
    Returns:
        Decoded bytes
        
    Raises:
        ValueError: If the string is invalid base32
    """
    data_bytes = data.encode('ascii')
    
    # If the string has more characters than are required to encode the number of bytes
    # decodable, treat the string as invalid.
    remainder = len(data_bytes) % 8
    if remainder in (1, 3, 6):
        raise ValueError("Invalid base32 string length")
    
    return decode_data(data_bytes, RFC4648_INV_ALPHABET)


def encode_data(data: bytes, alphabet: bytes) -> bytes:
    """
    Encode byte data using the given alphabet
    
    Args:
        data: Input bytes
        alphabet: 32-byte encoding alphabet
        
    Returns:
        Encoded bytes
    """
    # cap is calculated as follows:
    # / 5 divides the data length by the number of bits per chunk (5),
    # * 8 multiplies the result by the number of characters per chunk (8).
    # + 4 rounds up to the nearest character.
    cap = (len(data) + 4) // 5 * 8
    result = bytearray()
    
    # Process data in 5-byte chunks
    for i in range(0, len(data), 5):
        chunk = data[i:i + 5]
        
        # Pad chunk to 5 bytes with zeros
        buf = bytearray(5)
        buf[:len(chunk)] = chunk
        
        # Encode 5 bytes into 8 base32 characters
        result.append(alphabet[(buf[0] & 0xF8) >> 3])
        result.append(alphabet[((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)])
        result.append(alphabet[(buf[1] & 0x3E) >> 1])
        result.append(alphabet[((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)])
        result.append(alphabet[((buf[2] & 0x0F) << 1) | (buf[3] >> 7)])
        result.append(alphabet[(buf[3] & 0x7C) >> 2])
        result.append(alphabet[((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)])
        result.append(alphabet[buf[4] & 0x1F])
    
    return bytes(result)


def decode_data(data: bytes, alphabet: List[int]) -> bytes:
    """
    Decode base32 data using the given inverse alphabet
    
    Args:
        data: Encoded bytes
        alphabet: Inverse alphabet mapping
        
    Returns:
        Decoded bytes
        
    Raises:
        ValueError: If data contains invalid characters
    """
    # cap is calculated as follows:
    # / 8 divides the data length by the number of characters per chunk (8),
    # * 5 multiplies the result by the number of bits per chunk (5),
    # + 7 rounds up to the nearest byte.
    cap = (len(data) + 7) // 8 * 5
    result = bytearray()
    
    # Process data in 8-character chunks  
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        
        # Decode each character
        buf = bytearray(8)
        for j, c in enumerate(chunk):
            # Convert character to table index
            table_idx = c - ord('0')
            if table_idx < 0 or table_idx >= len(alphabet):
                raise ValueError(f"Invalid base32 character: {chr(c)}")
            
            value = alphabet[table_idx]
            if value == -1:
                raise ValueError(f"Invalid base32 character: {chr(c)}")
            
            buf[j] = value
        
        # Decode 8 base32 characters into 5 bytes
        result.append(((buf[0] << 3) | (buf[1] >> 2)) & 0xFF)
        result.append(((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4)) & 0xFF)
        result.append(((buf[3] << 4) | (buf[4] >> 1)) & 0xFF)
        result.append(((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3)) & 0xFF)
        result.append(((buf[6] << 5) | buf[7]) & 0xFF)
    
    # Calculate the actual output length and trim excess
    output_length = len(data) * 5 // 8
    
    # Check that trimmed bytes are all zeros (proper padding)
    for i in range(output_length, len(result)):
        if result[i] != 0:
            raise ValueError("Invalid padding in base32 string")
    
    return bytes(result[:output_length]) 