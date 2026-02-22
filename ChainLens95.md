# Chain Lens 95

Welcome to **Chain Lens 95**, affectionately named for its retro, Windows 95-inspired aesthetic!

This project is a dual-interface block and transaction visualizer for the Bitcoin blockchain. It features a robust Python-based CLI analyzer that dissects raw Bitcoin data to produce machine-readable JSON reports, alongside an interactive, user-friendly Web UI perfect for both technical inspection and educational exploration. 


Whether you want to deeply inspect the witness stack of a SegWit transaction or simply want a visual story explaining who paid whom and what the fees were, Chain Lens 95 has you covered.

## Features

- **CLI Analyzer**: Parses single transactions (from JSON fixtures) or entire raw blocks (`blk*.dat`, `rev*.dat`, `xor.dat`). Computes TxIDs/wTxIDs, fees, witness savings, script classifications, and more, strictly according to Bitcoin consensus rules.
- **Web Visualizer**: A rich, single-page application that translates complex transaction data into a plain-English "story". Includes interactive diagrams, color-coding, and tooltips to explain concepts like inputs, outputs, SegWit, and OP_RETURNs to non-technical users.
- **Local & Private**: No external API calls are made. Everything is parsed and analyzed locally on your machine.

---

## Installation 

To run Chain Lens 95 locally, you must have **Python 3** installed on your system. 

1. **Clone the repository** (or download the source code):
   ```bash
   git clone <repository-url>
   cd 2026-developer-challenge-1-chain-lens-0xunLin
   ```

2. **Run the setup script**:
   The project includes a `setup.sh` script to decompress necessary block fixtures.
   ```bash
   ./setup.sh
   ```
   *(Note: This might take a briefly moment depending on the size of the block data files included in the `fixtures/blocks/` directory).*

---

## Running the Program

You can interact with Chain Lens 95 either through its Command Line Interface (CLI) or its Web Visualizer.

### 1. Using the Web Visualizer (Recommended)

The Web Visualizer offers the most user-friendly experience, providing interactive graphs and explanations.

1. Start the web server:
   ```bash
   ./web.sh
   ```
2. The script will output a URL, typically `http://127.0.0.1:3000`. 
3. Open a web browser and navigate to that URL. 
4. From the UI, you can select example fixtures, paste raw transaction hex, or upload block `.dat` files directly into the analyzer.

To stop the web server, simply press `CTRL+C` in your terminal.

### 2. Using the CLI Analyzer

If you prefer terminal output or need machine-readable JSON reports, use `cli.sh`. 

**For a single transaction:**
```bash
# Example using a provided legacy P2PKH fixture
./cli.sh fixtures/transactions/tx_legacy_p2pkh.json
```
This will print the full JSON report to the console, and also save it to `out/<txid>.json`.

**For parsing entire blocks:**
```bash
# Example using provided block fixtures
./cli.sh --block fixtures/blocks/blk04330.dat fixtures/blocks/rev04330.dat fixtures/blocks/xor.dat
```
In block mode, the analyzer won't print to the console. Instead, it processes every transaction in the block and writes a detailed JSON report to `out/<block_hash>.json`.

---

Enjoy exploring the blockchain with Chain Lens 95!
