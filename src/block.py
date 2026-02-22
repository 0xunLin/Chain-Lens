from typing import List
from .utils import ByteStreamReader, MAINNET_MAGIC, double_sha256, get_id_hex
from .transaction import parse_input, parse_output, serialize_transaction

def parse_block_header(reader: ByteStreamReader) -> dict:
    header = reader.read_bytes(80)
    version = int.from_bytes(header[0:4], byteorder='little', signed=False)
    prev_block_hash = header[4:36][::-1].hex()
    merkle_root = header[36:68][::-1].hex()
    timestamp = int.from_bytes(header[68:72], byteorder='little', signed=False)
    bits_int = int.from_bytes(header[72:76], byteorder='little', signed=False)
    bits = f"{bits_int:08x}"
    nonce = int.from_bytes(header[76:80], byteorder='little', signed=False)
    block_hash = get_id_hex(header)
    return {
        "version": version,
        "prev_block_hash": prev_block_hash,
        "merkle_root": merkle_root,
        "timestamp": timestamp,
        "bits": bits,
        "nonce": nonce,
        "block_hash": block_hash
    }

def parse_transaction_from_reader(reader: ByteStreamReader) -> dict:
    version = reader.read_uint32()
    is_segwit = False
    next_byte = reader.read_bytes(1)
    if next_byte == b'\x00':
        flag = reader.read_bytes(1)
        if flag == b'\x01': is_segwit = True
        else: raise ValueError("Invalid segwit flag byte")
    else:
        reader._pos -= 1

    input_count = reader.read_varint()
    vin = [parse_input(reader) for _ in range(input_count)]

    output_count = reader.read_varint()
    vout = [parse_output(reader, index=i) for i in range(output_count)]

    if is_segwit:
        for i in range(len(vin)):
            item_count = reader.read_varint()
            witness_items = []
            for _ in range(item_count):
                item_len = reader.read_varint()
                item = reader.read_bytes(item_len).hex()
                witness_items.append(item)
            vin[i]["witness"] = witness_items

    locktime = reader.read_uint32()
    return {
        "version": version,
        "vin": vin,
        "vout": vout,
        "locktime": locktime
    }

def compute_merkle_root(txid_bytes_list: List[bytes]) -> bytes:
    if not txid_bytes_list: return b''
    current = txid_bytes_list[:]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        next_level = []
        for i in range(0, len(current), 2):
            combined = current[i] + current[i + 1]
            next_level.append(double_sha256(combined))
        current = next_level
    return current[0]

def verify_merkle_root(computed_root_bytes: bytes, header_merkle_display_hex: str) -> bool:
    header_merkle_internal = bytes.fromhex(header_merkle_display_hex)[::-1]
    return computed_root_bytes == header_merkle_internal

def parse_block(reader: ByteStreamReader) -> dict:
    magic = reader.read_bytes(4)
    if magic != MAINNET_MAGIC:
        raise ValueError(f"Unexpected magic bytes: {magic.hex()}")

    block_size = reader.read_uint32()
    payload_start = reader._pos
    header = parse_block_header(reader)
    tx_count = reader.read_varint()

    transactions = []
    txid_bytes_list = []

    for _ in range(tx_count):
        tx_obj = parse_transaction_from_reader(reader)
        transactions.append(tx_obj)
        serialized_no_witness = serialize_transaction(tx_obj, include_witness=False)
        txid_bytes = double_sha256(serialized_no_witness)
        txid_bytes_list.append(txid_bytes)
        # Cache for later:
        tx_obj["_base_size"] = len(serialized_no_witness)
        tx_obj["_txid"] = txid_bytes[::-1].hex()
        if any("witness" in vin for vin in tx_obj["vin"]):
            serialized_witness = serialize_transaction(tx_obj, include_witness=True)
            tx_obj["_total_size"] = len(serialized_witness)
            tx_obj["_wtxid"] = double_sha256(serialized_witness)[::-1].hex()
        else:
            tx_obj["_total_size"] = tx_obj["_base_size"]
            tx_obj["_wtxid"] = None

    payload_consumed = reader._pos - payload_start
    if payload_consumed > block_size:
        raise ValueError(f"Parsed beyond block_size: consumed={payload_consumed} block_size={block_size}")

    computed_root = compute_merkle_root(txid_bytes_list)
    merkle_valid = verify_merkle_root(computed_root, header["merkle_root"])

    return {
        "block_hash": header["block_hash"],
        "header": header,
        "tx_count": tx_count,
        "transactions": transactions,
        "merkle_valid": merkle_valid
    }