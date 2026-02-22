from .utils import ByteStreamReader
from .script import classify_script

def decompress_amount(x: int) -> int:
    if x == 0: return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x * 10 + 9
    return n * (10 ** e)

def decompress_pubkey(nSize: int, x_bytes: bytes) -> bytes:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(x_bytes, 'big')
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    is_even = (y % 2 == 0)
    
    if (nSize in (2, 4) and not is_even) or (nSize in (3, 5) and is_even):
        y = p - y
        
    if nSize in (2, 3):
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x_bytes
    else:
        return b'\x04' + x_bytes + y.to_bytes(32, 'big')

def parse_compressed_txout(reader: ByteStreamReader) -> dict:
    nCode = reader.read_varint()
    height = nCode >> 1
    is_coinbase = bool(nCode & 1)
    
    compressed_value = reader.read_varint()
    value = decompress_amount(compressed_value)
    
    nSize = reader.read_varint()

    if nSize == 0:
        h160 = reader.read_bytes(20)
        script = b'\x76\xa9\x14' + h160 + b'\x88\xac'
    elif nSize == 1:
        h160 = reader.read_bytes(20)
        script = b'\xa9\x14' + h160 + b'\x87'
    elif nSize in (2, 3, 4, 5):
        x_bytes = reader.read_bytes(32)
        pubkey = decompress_pubkey(nSize, x_bytes)
        script = bytes([len(pubkey)]) + pubkey + b'\xac'
    else:
        raw_len = nSize - 6
        script = reader.read_bytes(raw_len)

    return {
        "value": value,
        "scriptpubkey": script.hex(),
        "height": height,
        "is_coinbase": is_coinbase
    }

def parse_undo_record(reader: ByteStreamReader) -> list:
    """Parses a raw CBlockUndo payload into a structured list of inputs."""
    num_txs_with_undo = reader.read_varint()
    record = []
    
    for _ in range(num_txs_with_undo):
        num_inputs_for_tx = reader.read_varint()
        tx_undo = []
        for _ in range(num_inputs_for_tx):
            prevout = parse_compressed_txout(reader)
            tx_undo.append(prevout)
        record.append(tx_undo)
        
    return record