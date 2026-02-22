from .transaction import get_transaction_stats

def btc_from_sats(sats: int) -> float:
    return sats / 100_000_000

def detect_rbf(tx: dict) -> bool:
    for vin in tx["vin"]:
        if vin.get("sequence", 0xffffffff) < 0xfffffffe:
            return True
    return False

def detect_timelock(tx: dict) -> bool:
    return tx["locktime"] != 0

def detect_multisig(tx: dict) -> bool:
    for vout in tx["vout"]:
        if vout.get("script_type") in ("p2sh", "p2wsh"):
            return True
    return False

def enrich_transaction(tx: dict) -> None:
    if len(tx["vin"]) > 0 and "prevout" not in tx["vin"][0]:
        tx["input_total"] = 0
        tx["output_total"] = sum(v["value"] for v in tx["vout"])
        tx["fee"] = 0
        tx["fee_rate"] = 0
        tx["story"] = {
            "type": "Coinbase",
            "description": "Block reward transaction creating new BTC.",
            "features": []
        }
        return

    input_total = sum(vin["prevout"]["value"] for vin in tx["vin"])
    output_total = sum(v["value"] for v in tx["vout"])
    fee = input_total - output_total

    stats = get_transaction_stats(tx)
    vsize = stats["vsize"]
    fee_rate = fee / vsize if vsize > 0 else 0
    is_segwit = stats["segwit_savings"] is not None
    savings_pct = stats["segwit_savings"]["savings_pct"] if is_segwit else 0.0

    features = []
    if detect_rbf(tx): features.append("RBF Enabled")
    if detect_timelock(tx): features.append("Timelocked")
    if detect_multisig(tx): features.append("Script-Based Spend")
    if is_segwit: features.append("SegWit")

    description = (
        f"Moved {btc_from_sats(output_total):.8f} BTC "
        f"with a fee of {btc_from_sats(fee):.8f} BTC "
        f"({fee_rate:.2f} sat/vB)."
    )

    if is_segwit:
        description += f" Saved {savings_pct:.2f}% via SegWit discount."

    tx["input_total"] = input_total
    tx["output_total"] = output_total
    tx["fee"] = fee
    tx["fee_rate"] = round(fee_rate, 2)
    tx["story"] = {
        "type": "SegWit Payment" if is_segwit else "Legacy Payment",
        "description": description,
        "features": features
    }

def generate_story_mode(block_obj: dict) -> None:
    total_fees = 0
    for tx in block_obj["transactions"]:
        enrich_transaction(tx)
        total_fees += tx.get("fee", 0)

    block_obj["block_summary"] = {
        "block_hash": block_obj["block_hash"],
        "tx_count": block_obj["tx_count"],
        "total_fees_btc": btc_from_sats(total_fees),
        "merkle_valid": block_obj["merkle_valid"]
    }