import struct
import math
from .utils import ByteStreamReader, get_id_hex

def parse_input(reader: ByteStreamReader) -> dict:
    prev_tx_hash_raw = reader.read_bytes(32)
    txid = prev_tx_hash_raw[::-1].hex()
    vout = reader.read_uint32()
    script_length = reader.read_varint()
    script_sig = reader.read_bytes(script_length)
    scriptsig = script_sig.hex()
    sequence = reader.read_uint32()
    return {
        "txid": txid,
        "vout": vout,
        "scriptsig": script_sig.hex(),
        "scriptsig_bytes": script_sig,
        "sequence": sequence
    }

def parse_output(reader: ByteStreamReader, index: int | None = None) -> dict:
    value_sats = reader.read_uint64()
    script_len = reader.read_varint()
    script_pubkey_bytes = reader.read_bytes(script_len)
    script_pubkey_hex = script_pubkey_bytes.hex()
    out = {
        "value": value_sats,
        "scriptpubkey": script_pubkey_hex,
        "scriptpubkey_bytes": script_pubkey_bytes
    }
    if index is not None:
        out["n"] = index
    return out

def parse_transaction(hex_string: str) -> dict:
    raw_bytes = bytes.fromhex(hex_string)
    reader = ByteStreamReader(raw_bytes)
    version = reader.read_uint32()
    
    is_segwit = False
    next_byte = reader.read_bytes(1)
    if next_byte == b'\x00':
        flag = reader.read_bytes(1)
        if flag == b'\x01':
            is_segwit = True
        else:
            raise ValueError("Invalid SegWit flag byte")
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

def serialize_varint(value: int) -> bytes:
    if value < 0xfd: return struct.pack('<B', value)
    elif value <= 0xffff: return b'\xfd' + struct.pack('<H', value)
    elif value <= 0xffffffff: return b'\xfe' + struct.pack('<I', value)
    else: return b'\xff' + struct.pack('<Q', value)

def serialize_input(txin: dict) -> bytes:
    parts = []
    parts.append(bytes.fromhex(txin["txid"])[::-1])
    parts.append(struct.pack('<I', txin["vout"]))
    script_bytes = txin["scriptsig_bytes"]
    parts.append(serialize_varint(len(script_bytes)))
    parts.append(script_bytes)
    parts.append(struct.pack('<I', txin["sequence"]))
    return b''.join(parts)

def serialize_output(txout: dict) -> bytes:
    parts = []
    parts.append(struct.pack('<Q', txout["value"]))
    script_bytes = txout["scriptpubkey_bytes"]
    parts.append(serialize_varint(len(script_bytes)))
    parts.append(script_bytes)
    return b''.join(parts)

def serialize_transaction(tx_obj: dict, include_witness: bool = True) -> bytes:
    parts = []
    parts.append(struct.pack('<I', tx_obj["version"]))
    has_witness = include_witness and any("witness" in vin for vin in tx_obj["vin"])
    
    if has_witness:
        parts.append(b'\x00\x01')
        
    parts.append(serialize_varint(len(tx_obj["vin"])))
    for txin in tx_obj["vin"]:
        parts.append(serialize_input(txin))
        
    parts.append(serialize_varint(len(tx_obj["vout"])))
    for txout in tx_obj["vout"]:
        parts.append(serialize_output(txout))
        
    if has_witness:
        for txin in tx_obj["vin"]:
            witness_items = txin.get("witness", [])
            parts.append(serialize_varint(len(witness_items)))
            for item_hex in witness_items:
                item_bytes = bytes.fromhex(item_hex)
                parts.append(serialize_varint(len(item_bytes)))
                parts.append(item_bytes)
                
    parts.append(struct.pack('<I', tx_obj["locktime"]))
    return b''.join(parts)

def calculate_txid(tx_obj: dict) -> str:
    if "_txid" in tx_obj: return tx_obj["_txid"]
    serialized = serialize_transaction(tx_obj, include_witness=False)
    return get_id_hex(serialized)

def calculate_wtxid(tx_obj: dict) -> str:
    if "_wtxid" in tx_obj: return tx_obj["_wtxid"]
    serialized = serialize_transaction(tx_obj, include_witness=True)
    return get_id_hex(serialized)

def get_transaction_stats(tx_obj: dict) -> dict:
    if "_base_size" in tx_obj:
        base_size = tx_obj["_base_size"]
        total_size = tx_obj["_total_size"]
    else:
        base_size = len(serialize_transaction(tx_obj, include_witness=False))
        total_size = len(serialize_transaction(tx_obj, include_witness=True))
    is_segwit = any("witness" in vin for vin in tx_obj["vin"])
    
    weight = (base_size * 3) + total_size
    vsize = math.ceil(weight / 4)
    
    if is_segwit:
        witness_bytes = total_size - base_size
        non_witness_bytes = base_size
        weight_if_legacy = total_size * 4
        savings = 1 - (weight / weight_if_legacy)
        savings_pct = round(savings * 100, 2)
        
        segwit_savings = {
            "witness_bytes": witness_bytes,
            "non_witness_bytes": non_witness_bytes,
            "total_bytes": total_size,
            "weight_actual": weight,
            "weight_if_legacy": weight_if_legacy,
            "savings_pct": savings_pct
        }
    else:
        segwit_savings = None
        
    return {
        "size": total_size,
        "vsize": vsize,
        "weight": weight,
        "segwit_savings": segwit_savings
    }