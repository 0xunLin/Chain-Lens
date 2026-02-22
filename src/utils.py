import struct
import hashlib
from pathlib import Path

MAINNET_MAGIC = b'\xf9\xbe\xb4\xd9'

class ByteStreamReader:
    def __init__(self, data: bytes):
        self._b = data
        self._pos = 0

    def read_bytes(self, n: int) -> bytes:
        if self._pos + n > len(self._b):
            raise EOFError("unexpected end of stream")
        out = self._b[self._pos:self._pos + n]
        self._pos += n
        return out

    def read_uint8(self) -> int:
        if self._pos + 1 > len(self._b): raise EOFError()
        out = self._b[self._pos]
        self._pos += 1
        return out

    def read_uint16(self) -> int:
        if self._pos + 2 > len(self._b): raise EOFError()
        out = int.from_bytes(self._b[self._pos:self._pos+2], 'little')
        self._pos += 2
        return out

    def read_uint32(self) -> int:
        if self._pos + 4 > len(self._b): raise EOFError()
        out = int.from_bytes(self._b[self._pos:self._pos+4], 'little')
        self._pos += 4
        return out

    def read_uint64(self) -> int:
        if self._pos + 8 > len(self._b): raise EOFError()
        out = int.from_bytes(self._b[self._pos:self._pos+8], 'little')
        self._pos += 8
        return out

    def read_varint(self) -> int:
        first = self.read_uint8()
        if first < 0xfd:
            return first
        elif first == 0xfd:
            return self.read_uint16()
        elif first == 0xfe:
            return self.read_uint32()
        else:
            return self.read_uint64()

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_id_hex(data: bytes) -> str:
    return double_sha256(data)[::-1].hex()

def xor_decode(input_path: str, xor_key_path: str, output_path: str | None = None) -> bytes | None:
    key_file = Path(xor_key_path)
    key = key_file.read_bytes()

    if len(key) != 8:
        raise ValueError("xor.dat must contain exactly 8 bytes")

    key_len = len(key)
    chunk_size = 1024 * 1024
    global_offset = 0

    # Explicitly separate the write-to-disk vs keep-in-memory logic 
    # to perfectly satisfy the static type checker.
    
    if output_path is not None:
        with open(output_path, "wb") as out_f:
            with open(input_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    extended_key = (key * ((len(chunk) // key_len) + 1))[:len(chunk)]
                    # Adjust alignment based on global_offset
                    offset_in_key = global_offset % key_len
                    aligned_key = extended_key[offset_in_key:] + extended_key[:offset_in_key]
                    aligned_key = (aligned_key * ((len(chunk) // len(aligned_key)) + 1))[:len(chunk)]
                    
                    data_int = int.from_bytes(chunk, 'little')
                    key_int = int.from_bytes(aligned_key, 'little')
                    decoded_chunk = (data_int ^ key_int).to_bytes(len(chunk), 'little')
                    
                    global_offset += len(chunk)
                    out_f.write(decoded_chunk)

        with open(output_path, "rb") as vf:
            if vf.read(4) != MAINNET_MAGIC:
                raise ValueError("Decoded file does not start with Bitcoin mainnet magic bytes")
        return None

    else:
        with open(input_path, "rb") as f:
            data = f.read()
        if not data:
            return b""
        
        extended_key = (key * ((len(data) // key_len) + 1))[:len(data)]
        data_int = int.from_bytes(data, 'little')
        key_int = int.from_bytes(extended_key, 'little')
        decoded_data = (data_int ^ key_int).to_bytes(len(data), 'little')

        if decoded_data[:4] != MAINNET_MAGIC:
            raise ValueError("Decoded file does not start with Bitcoin mainnet magic bytes")
        return decoded_data