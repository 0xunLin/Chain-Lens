import sys
import json
import os
import math
import traceback

from src.utils import xor_decode, ByteStreamReader
from src.block import parse_block
from src.story import detect_rbf
from src.transaction import parse_transaction, calculate_txid, calculate_wtxid, get_transaction_stats
from src.script import classify_script, classify_input, disassemble_script

# ---------------------------------------------------------
# NEW: Base-128 VarInt Decoder for Undo Payload Data
# ---------------------------------------------------------
def read_b128_varint(reader: ByteStreamReader) -> int:
    n = 0
    while True:
        # Read exactly 1 byte
        ch = reader.read_bytes(1)[0]
        
        # Shift the current number left by 7 bits, and add the bottom 7 bits of the new byte
        n = (n << 7) | (ch & 0x7F)
        
        # Check the 8th bit (0x80). If it's a 1, we continue reading.
        if ch & 0x80:
            n += 1  # <-- THIS IS BITCOIN'S UNIQUE QUIRK!
        else:
            return n

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
    nCode = read_b128_varint(reader)
    height = nCode >> 1
    is_coinbase = bool(nCode & 1)
    
    # 🚨 THE GHOST FIELD FIX! 🚨
    # Old versions stored the tx version here. If height > 0, we must 
    # consume and discard the next varint to stay byte-aligned.
    if height > 0:
        _ = read_b128_varint(reader) 
        
    compressed_value = read_b128_varint(reader)
    value = decompress_amount(compressed_value)
    
    nSize = read_b128_varint(reader)

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
    # Vector lengths use standard CompactSize!
    num_txs_with_undo = reader.read_varint() 
    record = []
    
    for _ in range(num_txs_with_undo):
        num_inputs_for_tx = reader.read_varint()
        tx_undo = []
        for _ in range(num_inputs_for_tx):
            tx_undo.append(parse_compressed_txout(reader))
        record.append(tx_undo)
    return record

# ---------------------------------------------------------
# Formatting and Parsing Core
# ---------------------------------------------------------
def parse_relative_timelock(sequence: int) -> dict:
    if sequence & (1 << 31): return {"enabled": False}
    value = sequence & 0xffff
    if sequence & (1 << 22): return {"enabled": True, "type": "time", "value": value * 512}
    else: return {"enabled": True, "type": "blocks", "value": value}

def format_tx(tx_obj, is_coinbase=False, prevout_map=None):
    txid = calculate_txid(tx_obj)
    is_segwit = any("witness" in vin for vin in tx_obj["vin"])
    wtxid = calculate_wtxid(tx_obj) if is_segwit else None
    
    total_input_sats = 0
    formatted_vin = []
    
    for vin in tx_obj["vin"]:
        if is_coinbase:
            formatted_vin.append({
                "txid": vin["txid"], "vout": vin["vout"], "sequence": vin["sequence"],
                "script_sig_hex": vin["scriptsig"], "script_asm": disassemble_script(vin["scriptsig_bytes"]),
                "witness": vin.get("witness", []), "script_type": "unknown", "address": None,
                "prevout": None, "relative_timelock": parse_relative_timelock(vin["sequence"])
            })
        else:
            if prevout_map:
                p = prevout_map[f"{vin['txid']}:{vin['vout']}"]
                val = p["value_sats"]
                script_hex = p["script_pubkey_hex"]
                script_bytes = bytes.fromhex(script_hex)
            else:
                p = vin["prevout"]
                val = p["value"]
                script_hex = p["scriptpubkey"]
                script_bytes = p.get("scriptpubkey_bytes", bytes.fromhex(script_hex))
                
            total_input_sats += val
            class_info = classify_input(vin, script_bytes)
            spend_type = class_info["script_type"]
            witness_data = vin.get("witness", [])
            
            input_obj = {
                "txid": vin["txid"], "vout": vin["vout"], "sequence": vin["sequence"],
                "script_sig_hex": vin["scriptsig"], "script_asm": disassemble_script(vin["scriptsig_bytes"]),
                "witness": witness_data, "script_type": spend_type, "address": class_info.get("address"),
                "prevout": {"value_sats": val, "script_pubkey_hex": script_hex},
                "relative_timelock": parse_relative_timelock(vin["sequence"])
            }
            if spend_type in ("p2wsh", "p2sh-p2wsh") and len(witness_data) > 0:
                input_obj["witness_script_asm"] = disassemble_script(bytes.fromhex(witness_data[-1]))
            formatted_vin.append(input_obj)

    total_output_sats = 0
    formatted_vout = []
    dust_warning = unknown_script_warning = False
    
    for vout in tx_obj["vout"]:
        total_output_sats += vout["value"]
        class_info = classify_script(vout["scriptpubkey_bytes"])
        script_type = class_info["type"]
        
        out_obj = {
            "n": vout.get("n", 0), "value_sats": vout["value"], "script_pubkey_hex": vout["scriptpubkey"],
            "script_asm": disassemble_script(vout["scriptpubkey_bytes"]), "script_type": script_type,
            "address": class_info.get("address")
        }

        if script_type == "op_return":
            out_obj["op_return_data_hex"] = class_info.get("op_return_data_hex")
            out_obj["op_return_data_utf8"] = class_info.get("op_return_data_utf8")
            out_obj["op_return_protocol"] = class_info.get("op_return_protocol")
        else:
            if vout["value"] < 546: dust_warning = True
                
        if script_type == "unknown": unknown_script_warning = True
        formatted_vout.append(out_obj)

    fee_sats = 0
    fee_rate = 0
    stats = get_transaction_stats(tx_obj)
    vbytes = stats["vsize"]
    
    if not is_coinbase:
        fee_sats = total_input_sats - total_output_sats
        fee_rate = fee_sats / vbytes if vbytes > 0 else 0

    locktime = tx_obj["locktime"]
    locktime_type = "none" if locktime == 0 else "block_height" if locktime < 500000000 else "unix_timestamp"

    rbf_signaling = detect_rbf(tx_obj)
    warnings = []
    if rbf_signaling: warnings.append({"code": "RBF_SIGNALING"})
    if fee_sats > 1_000_000 or fee_rate > 200: warnings.append({"code": "HIGH_FEE"})
    if dust_warning: warnings.append({"code": "DUST_OUTPUT"})
    if unknown_script_warning: warnings.append({"code": "UNKNOWN_OUTPUT_SCRIPT"})

    return {
        "ok": True, "network": "mainnet", "segwit": is_segwit, "txid": txid, "wtxid": wtxid,
        "version": tx_obj["version"], "locktime": locktime, "size_bytes": stats["size"],
        "weight": stats["weight"], "vbytes": vbytes, "total_input_sats": total_input_sats,
        "total_output_sats": total_output_sats, "fee_sats": fee_sats, "fee_rate_sat_vb": round(fee_rate, 2),
        "rbf_signaling": rbf_signaling, "locktime_type": locktime_type, "locktime_value": locktime,
        "segwit_savings": stats["segwit_savings"], "vin": formatted_vin, "vout": formatted_vout, "warnings": warnings
    }

def format_block_report(block_obj: dict) -> dict:
    header = block_obj["header"]
    cb_tx = block_obj["transactions"][0]
    cb_script = bytes.fromhex(cb_tx["vin"][0]["scriptsig"])
    
    bip34_height = 0
    if len(cb_script) > 0 and cb_script[0] <= 7 and len(cb_script) >= 1 + cb_script[0]:
        bip34_height = int.from_bytes(cb_script[1:1+cb_script[0]], 'little')
        
    cb_out_sats = sum(v["value"] for v in cb_tx["vout"])
    
    formatted_txs = []
    total_fees = total_weight = 0
    total_weight_actual = total_weight_if_legacy = 0
    script_counts = {"p2wpkh": 0, "p2tr": 0, "p2sh": 0, "p2pkh": 0, "p2wsh": 0, "op_return": 0, "unknown": 0}
    
    for i, tx in enumerate(block_obj["transactions"]):
        is_cb = (i == 0)
        tx_rep = format_tx(tx, is_cb)
        formatted_txs.append(tx_rep)
        
        total_weight += tx_rep["weight"]
        if tx_rep.get("segwit_savings"):
            total_weight_actual += tx_rep["segwit_savings"]["weight_actual"]
            total_weight_if_legacy += tx_rep["segwit_savings"]["weight_if_legacy"]
        else:
            total_weight_actual += tx_rep["weight"]
            total_weight_if_legacy += tx_rep["weight"]
            
        if not is_cb: total_fees += tx_rep["fee_sats"]
        
        for vout in tx_rep["vout"]:
            stype = vout["script_type"]
            script_counts[stype] = script_counts.get(stype, 0) + 1
                
    total_vbytes = math.ceil(total_weight / 4)
    
    has_segwit = total_weight_actual > 0 and total_weight_if_legacy > total_weight_actual
    segwit_savings = None
    if has_segwit:
        savings = 1 - (total_weight_actual / total_weight_if_legacy)
        savings_pct = round(savings * 100, 2)
        segwit_savings = {
            "weight_actual": total_weight_actual,
            "weight_if_legacy": total_weight_if_legacy,
            "savings_pct": savings_pct
        }
    
    return {
        "ok": True, "mode": "block",
        "segwit": has_segwit,
        "segwit_savings": segwit_savings,
        "block_header": {
            "version": header["version"], "prev_block_hash": header["prev_block_hash"],
            "merkle_root": header["merkle_root"], "merkle_root_valid": block_obj["merkle_valid"],
            "timestamp": header["timestamp"], "bits": header["bits"], "nonce": header["nonce"],
            "block_hash": header["block_hash"]
        },
        "tx_count": block_obj["tx_count"],
        "coinbase": {"bip34_height": bip34_height, "coinbase_script_hex": cb_tx["vin"][0]["scriptsig"], "total_output_sats": cb_out_sats},
        "transactions": formatted_txs,
        "block_stats": {
            "total_fees_sats": total_fees, "total_weight": total_weight,
            "avg_fee_rate_sat_vb": round(total_fees / total_vbytes if total_vbytes > 0 else 0, 2),
            "script_type_summary": script_counts
        }
    }

def _format_and_save_wrapper(b_obj):
    try:
        report = format_block_report(b_obj)
        os.makedirs("out", exist_ok=True)
        with open(f"out/{report['block_header']['block_hash']}.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
    except Exception as e:
        print(json.dumps({"ok": False, "error": {"code": "BLOCK_FORMAT_ERROR", "message": str(e)}}))
        pass

def run_single_mode(fixture_path: str):
    try:
        with open(fixture_path, 'r') as f: fixture = json.load(f)
        tx_obj = parse_transaction(fixture.get("raw_tx"))
        prevout_map = {f"{p['txid']}:{p['vout']}": p for p in fixture.get("prevouts", [])}

        report = format_tx(tx_obj, is_coinbase=False, prevout_map=prevout_map)
        os.makedirs("out", exist_ok=True)
        with open(f"out/{report['txid']}.json", "w") as f: json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"ok": False, "error": {"code": "INVALID_TX", "message": str(e)}}, indent=2))
        sys.exit(1)

def run_block_mode(block_path: str, undo_path: str, xor_path: str):
    import gc
    gc.disable()
    try:
        os.makedirs("out", exist_ok=True)
        
        decoded_block_file = xor_decode(block_path, xor_path)
        if decoded_block_file is None:
            raise ValueError("Failed to decode block file.")
            
        decoded_undo_file = xor_decode(undo_path, xor_path)
        if decoded_undo_file is None:
            raise ValueError("Failed to decode undo file.")

        # 1. READ ALL UNDO RECORDS INTO MEMORY FIRST
        undo_reader = ByteStreamReader(decoded_undo_file)
        undo_map = {}
        
        while undo_reader._pos < len(undo_reader._b):
            if undo_reader._pos + 8 > len(undo_reader._b): break
            if undo_reader.read_bytes(4) == b'\x00\x00\x00\x00': break
            
            undo_size = undo_reader.read_uint32()
            
            try:
                # Perfectly grab the isolated undo chunk
                record = parse_undo_record(ByteStreamReader(undo_reader.read_bytes(undo_size)))
                
                fingerprint = tuple(len(tx_undo) for tx_undo in record)
                if fingerprint not in undo_map: undo_map[fingerprint] = []
                undo_map[fingerprint].append(record)
            except Exception as e:
                raise ValueError(f"CRITICAL FAULT in Undo Parser: {str(e)}")
                
            undo_reader.read_bytes(32) # Skip checksum

        # 2. MATCH BLOCKS TO THEIR UNDO DATA
        block_reader = ByteStreamReader(decoded_block_file)
        blocks_to_format = []
        while block_reader._pos < len(block_reader._b) and undo_map:
            if block_reader._pos + 4 > len(block_reader._b): break
            if block_reader._b[block_reader._pos : block_reader._pos+4] == b'\x00\x00\x00\x00': break

            block_obj = parse_block(block_reader)
            if not block_obj.get("merkle_valid", True):
                print(json.dumps({"ok": False, "error": {"code": "INVALID_MERKLE_ROOT", "message": "Bad Merkle"}}))
                sys.exit(1)

            txs = block_obj["transactions"]
            fingerprint = tuple(len(tx["vin"]) for tx in txs[1:])
            
            if fingerprint not in undo_map or len(undo_map[fingerprint]) == 0:
                raise ValueError(f"No undo data matched fingerprint {fingerprint[:5]}...")
                
            matched_record = undo_map[fingerprint].pop(0)

            # 3. ATTACH PREVOUTS
            for tx_idx, tx in enumerate(txs[1:]):
                for vin_idx, vin in enumerate(tx["vin"]):
                    vin["prevout"] = matched_record[tx_idx][vin_idx]

            blocks_to_format.append(block_obj)
            break # ONLY DO 1

        for b_obj in blocks_to_format:
            _format_and_save_wrapper(b_obj)

    except Exception as e:
        error_msg = traceback.format_exc().replace('\n', ' | ')
        print(json.dumps({"ok": False, "error": {"code": "BLOCK_PARSE_ERROR", "message": error_msg}}))
        sys.exit(1)
        
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    if sys.argv[1] == "--block":
        if len(sys.argv) != 5: sys.exit(1)
        run_block_mode(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        run_single_mode(sys.argv[1])