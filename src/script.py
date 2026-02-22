import hashlib

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def base58_encode(b: bytes) -> str:
    num = int.from_bytes(b, 'big')
    if num == 0:
        return "1" * len(b)
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(chars))

def base58check_encode(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

def bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        if b & 1: chk ^= 0x3b6a57b2
        if b & 2: chk ^= 0x26508e6d
        if b & 4: chk ^= 0x1ea119fa
        if b & 8: chk ^= 0x3d4233dd
        if b & 16: chk ^= 0x2a1462b3
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec="bech32"):
    const = 1 if spec == "bech32" else 0x2bc830a3
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ const
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def encode_segwit_address(hrp, witver, witprog):
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + convertbits(witprog, 8, 5)
    checksum = bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)

def classify_op_return(script: bytes) -> dict:
    i = 1
    payload = b''
    while i < len(script):
        opcode = script[i]
        i += 1
        if 1 <= opcode <= 75:
            data_len = opcode
        elif opcode == 76:
            data_len = script[i]
            i += 1
        elif opcode == 77:
            data_len = int.from_bytes(script[i:i+2], 'little')
            i += 2
        elif opcode == 78:
            data_len = int.from_bytes(script[i:i+4], 'little')
            i += 4
        else:
            break
        payload += script[i:i+data_len]
        i += data_len
    hex_data = payload.hex()
    try:
        utf8_data = payload.decode("utf-8")
    except:
        utf8_data = None
    if hex_data.startswith("6f6d6e69"):
        protocol = "omni"
    elif hex_data.startswith("0109f91102"):
        protocol = "opentimestamps"
    else:
        protocol = "unknown"
    return {
        "type": "op_return",
        "address": None,
        "op_return_data_hex": hex_data,
        "op_return_data_utf8": utf8_data,
        "op_return_protocol": protocol
    }

def classify_script(script: bytes) -> dict:
    if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[-2] == 0x88 and script[-1] == 0xac:
        h160 = script[3:23]
        return {"type": "p2pkh", "hash": h160.hex(), "address": base58check_encode(b'\x00', h160)}
    if len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[-1] == 0x87:
        h160 = script[2:22]
        return {"type": "p2sh", "hash": h160.hex(), "address": base58check_encode(b'\x05', h160)}
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        prog = script[2:]
        return {"type": "p2wpkh", "hash": prog.hex(), "address": encode_segwit_address("bc", 0, prog)}
    if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
        prog = script[2:]
        return {"type": "p2wsh", "hash": prog.hex(), "address": encode_segwit_address("bc", 0, prog)}
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        pubkey = script[2:]
        return {"type": "p2tr", "hash": pubkey.hex(), "address": encode_segwit_address("bc", 1, pubkey)}
    if len(script) >= 1 and script[0] == 0x6a:
        return classify_op_return(script)
    return {"type": "unknown", "hash": None, "address": None}

def classify_input(txin: dict, prevout_script_bytes: bytes) -> dict:
    script_info = classify_script(prevout_script_bytes)
    script_type = script_info["type"]
    address = script_info.get("address")
    has_witness = "witness" in txin

    spend_type = "unknown"
    if script_type == "p2pkh": spend_type = "p2pkh"
    elif script_type == "p2sh" and has_witness:
        redeem = bytes.fromhex(txin["scriptsig"])[-22:]
        if redeem.startswith(b'\x00\x14'): spend_type = "p2sh-p2wpkh"
        elif redeem.startswith(b'\x00\x20'): spend_type = "p2sh-p2wsh"
    elif script_type == "p2wpkh": spend_type = "p2wpkh"
    elif script_type == "p2wsh": spend_type = "p2wsh"
    elif script_type == "p2tr" and has_witness:
        spend_type = "p2tr_keypath" if len(txin["witness"]) == 1 else "p2tr_scriptpath"

    return {"script_type": spend_type, "address": address}

    # ----------------------------------------------------------------------
# OPCODE DISASSEMBLER
# ----------------------------------------------------------------------

OPCODE_NAMES = {
    0x00: "OP_0",
    0x4f: "OP_1NEGATE",
    0x51: "OP_1", 0x52: "OP_2", 0x53: "OP_3", 0x54: "OP_4",
    0x55: "OP_5", 0x56: "OP_6", 0x57: "OP_7", 0x58: "OP_8",
    0x59: "OP_9", 0x5a: "OP_10", 0x5b: "OP_11", 0x5c: "OP_12",
    0x5d: "OP_13", 0x5e: "OP_14", 0x5f: "OP_15", 0x60: "OP_16",
    0x61: "OP_NOP",
    0x6a: "OP_RETURN",
    0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK", 0x6d: "OP_2DROP",
    0x6e: "OP_2DUP", 0x6f: "OP_3DUP", 0x70: "OP_2OVER", 0x71: "OP_2ROT",
    0x72: "OP_2SWAP", 0x73: "OP_IFDUP", 0x74: "OP_DEPTH", 0x75: "OP_DROP",
    0x76: "OP_DUP", 0x77: "OP_NIP", 0x78: "OP_OVER", 0x79: "OP_PICK",
    0x7a: "OP_ROLL", 0x7b: "OP_ROT", 0x7c: "OP_SWAP", 0x7d: "OP_TUCK",
    0x7e: "OP_CAT", 0x7f: "OP_SUBSTR", 0x80: "OP_LEFT", 0x81: "OP_RIGHT",
    0x82: "OP_SIZE", 0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1", 0x8a: "OP_RESERVED2",
    0x8b: "OP_1ADD", 0x8c: "OP_1SUB", 0x8d: "OP_2MUL", 0x8e: "OP_2DIV",
    0x8f: "OP_NEGATE", 0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD", 0x94: "OP_SUB", 0x95: "OP_MUL", 0x96: "OP_DIV",
    0x97: "OP_MOD", 0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT", 0x9a: "OP_BOOLAND",
    0x9b: "OP_BOOLOR", 0x9c: "OP_NUMEQUAL", 0x9d: "OP_NUMEQUALVERIFY",
    0x9e: "OP_NUMNOTEQUAL", 0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
    0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
    0xa3: "OP_MIN", 0xa4: "OP_MAX", 0xa5: "OP_WITHIN",
    0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1", 0xa8: "OP_SHA256", 0xa9: "OP_HASH160",
    0xaa: "OP_HASH256", 0xab: "OP_CODESEPARATOR", 0xac: "OP_CHECKSIG",
    0xad: "OP_CHECKSIGVERIFY", 0xae: "OP_CHECKMULTISIG",
    0xaf: "OP_CHECKMULTISIGVERIFY",
    0xb0: "OP_NOP1", 0xb1: "OP_CHECKLOCKTIMEVERIFY", 0xb2: "OP_CHECKSEQUENCEVERIFY",
    0xb3: "OP_NOP4", 0xb4: "OP_NOP5", 0xb5: "OP_NOP6", 0xb6: "OP_NOP7",
    0xb7: "OP_NOP8", 0xb8: "OP_NOP9", 0xb9: "OP_NOP10",
    0xba: "OP_CHECKSIGADD", # Taproot
}

def disassemble_script(script: bytes) -> str:
    """
    Parses a hex script into a human-readable assembly string.
    Follows strictly defined output formatting for the Week 1 Spec.
    """
    if not script:
        return ""

    i = 0
    tokens = []
    script_len = len(script)

    while i < script_len:
        opcode = script[i]
        i += 1

        # OP_0
        if opcode == 0x00:
            tokens.append("OP_0")
            
        # Direct Data Pushes (OP_PUSHBYTES_1 to OP_PUSHBYTES_75)
        elif 1 <= opcode <= 75:
            data_len = opcode
            data = script[i:i+data_len]
            tokens.append(f"OP_PUSHBYTES_{data_len} {data.hex()}")
            i += data_len
            
        # OP_PUSHDATA1 (76)
        elif opcode == 76:
            if i >= script_len: break
            data_len = script[i]
            i += 1
            data = script[i:i+data_len]
            tokens.append(f"OP_PUSHDATA1 {data.hex()}")
            i += data_len
            
        # OP_PUSHDATA2 (77)
        elif opcode == 77:
            if i + 1 >= script_len: break
            data_len = int.from_bytes(script[i:i+2], 'little')
            i += 2
            data = script[i:i+data_len]
            tokens.append(f"OP_PUSHDATA2 {data.hex()}")
            i += data_len
            
        # OP_PUSHDATA4 (78)
        elif opcode == 78:
            if i + 3 >= script_len: break
            data_len = int.from_bytes(script[i:i+4], 'little')
            i += 4
            data = script[i:i+data_len]
            tokens.append(f"OP_PUSHDATA4 {data.hex()}")
            i += data_len
            
        # Standard Opcodes
        else:
            name = OPCODE_NAMES.get(opcode, f"OP_UNKNOWN_0x{opcode:02x}")
            tokens.append(name)

    return " ".join(tokens)