const API_URL = '/api/analyze';

function toggleMode() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    if (mode === 'tx') {
        document.getElementById('tx-input-group').style.display = 'flex';
        document.getElementById('block-input-group').style.display = 'none';
        document.getElementById('tx-json-input').focus();
    } else {
        document.getElementById('tx-input-group').style.display = 'none';
        document.getElementById('block-input-group').style.display = 'flex';
    }
}

async function analyze() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    setLoading(true);
    setStatus("CONNECTING TO NODE...");

    try {
        let response;
        if (mode === 'tx') {
            const jsonText = document.getElementById('tx-json-input').value.trim();
            if (!jsonText) return alert("Please paste TX JSON array or object!");

            response = await fetch('/api/analyze/tx', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonText
            });
        } else {
            const blkFile = document.getElementById('file-blk').files[0];
            const revFile = document.getElementById('file-rev').files[0];
            const xorFile = document.getElementById('file-xor').files[0];

            if (!blkFile || !revFile || !xorFile) return alert("Please select blk, rev, and xor files!");

            const formData = new FormData();
            formData.append('blk_file', blkFile);
            formData.append('rev_file', revFile);
            formData.append('xor_file', xorFile);

            response = await fetch('/api/analyze/block', {
                method: 'POST',
                body: formData
            });
        }

        const data = await response.json();

        if (!data.ok) {
            throw new Error(data.error ? data.error.message : "Unknown Error");
        }

        renderResult(data);
        setStatus("DATA RECEIVED OK.");
    } catch (e) {
        setStatus("ERROR: " + e.message);
        alert("CRITICAL ERROR:\n" + e.message);
    } finally {
        setLoading(false);
    }
}

function renderResult(data) {
    document.getElementById('results-area').classList.remove('hidden');

    document.getElementById('story-panel').classList.add('hidden');
    document.getElementById('segwit-panel').classList.add('hidden');
    document.getElementById('flow-panel').classList.add('hidden');
    document.getElementById('advanced-features-panel').classList.add('hidden');
    document.getElementById('block-overview-panel').classList.add('hidden');

    if (data.mode === 'block') {
        renderBlockResult(data);
    } else {
        renderTxResult(data);
    }

    document.getElementById('hex-view').value = JSON.stringify(data, null, 2);
}

function renderBlockResult(data) {
    document.getElementById('block-overview-panel').classList.remove('hidden');

    const statusCrt = document.getElementById('status-display');
    statusCrt.innerHTML = `
        <p>TYPE: BLOCK</p>
        <p>HASH: ${data.block_header.block_hash.substring(0, 16) + "..."}</p>
        <p>TX COUNT: ${data.tx_count}</p>
        <p>WEIGHT: ${data.block_stats.total_weight} WU</p>
        <p style="color:var(--term-green)">VALIDATION: PASS</p>
    `;

    // Make sure Story Panel is visible for Block Mode as well to teach beginners
    document.getElementById('story-panel').classList.remove('hidden');
    const storyDiv = document.getElementById('story-content');
    storyDiv.innerHTML = `
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">📦</span> 
            <b>THE BLOCK:</b> A massive page in the global ledger.
            <p class="story-help-text">A block isn't just one payment; it's a bundled payload of exactly ${data.tx_count} confirmed transactions that were waiting in line.</p>
        </div>
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">⛏️</span> 
            <b>THE MINER:</b> The accountant who validated this.
            <p class="story-help-text">The network solver (miner) structured this block mathematically. For doing this critical work, they collected ${data.block_stats.total_fees_sats} sats in transaction fees as a tip, plus the block subsidy!</p>
        </div>
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">⚖️</span> 
            <b>THE WEIGHT:</b> Block space is strictly limited.
            <p class="story-help-text">This block consumed ${data.block_stats.total_weight} Weight Units. Bitcoin strictly limits how massive these blocks can be to ensure anyone with a basic laptop can still run a node and verify the system.</p>
        </div>
    `;

    const warningsContainer = document.getElementById('warnings-container');
    warningsContainer.innerHTML = "";

    const statsDiv = document.getElementById('block-stats');
    statsDiv.innerHTML = `
        <div style="margin-bottom: 10px;">
            <b>TOTAL FEES:</b> ${data.block_stats.total_fees_sats} sats<br>
            <b>AVG FEE RATE:</b> ${data.block_stats.avg_fee_rate_sat_vb} s/vB<br>
        </div>
        <b>SCRIPT TYPES:</b><br>
        ${Object.entries(data.block_stats.script_type_summary).map(([k, v]) => `${k.toUpperCase()}: ${v}`).join(', ')}
    `;

    const listDiv = document.getElementById('block-tx-list');
    listDiv.innerHTML = "";

    data.transactions.forEach((tx, idx) => {
        const div = document.createElement('div');
        div.style.borderBottom = "1px solid #ccc";
        div.style.padding = "5px";
        div.innerHTML = `
            <div style="cursor: pointer; font-weight: bold; font-family: monospace;" onclick="this.nextElementSibling.classList.toggle('hidden')">
                [+] TX ${idx}: ${tx.txid.substring(0, 16)}... | Fee: ${tx.fee_sats} sats
            </div>
            <div class="hidden" style="margin-top: 5px; padding-left: 10px; font-size: 12px; font-family: monospace;">
                Inputs: ${tx.vin.length} | Outputs: ${tx.vout.length} <br>
                Weight: ${tx.weight} WU | Fee Rate: ${tx.fee_rate_sat_vb} s/vB <br>
                Output Types: ${tx.vout.map(v => v.script_type.toUpperCase()).join(', ')}
            </div>
        `;
        listDiv.appendChild(div);
    });

    const segwitPanel = document.getElementById('segwit-panel');
    if (data.segwit && data.segwit_savings) {
        segwitPanel.classList.remove('hidden');
        const actBar = document.getElementById('actual-weight-bar');
        const legBar = document.getElementById('legacy-weight-bar');
        const savingsText = document.getElementById('savings-text');

        const actW = data.segwit_savings.weight_actual;
        const legW = data.segwit_savings.weight_if_legacy;

        actBar.style.width = `${(actW / legW) * 100}%`;
        legBar.style.width = '100%';
        savingsText.innerText = `SAVED ${data.segwit_savings.savings_pct}% SPACE IN BLOCK TOTAL`;
    } else {
        segwitPanel.classList.add('hidden');
    }
}

function renderTxResult(data) {
    document.getElementById('story-panel').classList.remove('hidden');
    document.getElementById('flow-panel').classList.remove('hidden');

    const statusCrt = document.getElementById('status-display');
    statusCrt.innerHTML = `
        <p>TYPE: TRANSACTION</p>
        <p>ID: ${data.txid ? data.txid.substring(0, 16) + "..." : "N/A"}</p>
        <p>SIZE: ${data.size_bytes || 0} BYTES</p>
        <p>WEIGHT: ${data.weight || 0} WU</p>
        <p style="color:var(--term-green)">VALIDATION: PASS</p>
    `;

    const warningsContainer = document.getElementById('warnings-container');
    warningsContainer.innerHTML = "";
    if (data.warnings && data.warnings.length > 0) {
        data.warnings.forEach(w => {
            warningsContainer.innerHTML += `<div class="warning-badge">⚠️ NOTE: ${w.code}</div>`;
        });
    }

    const storyDiv = document.getElementById('story-content');
    const desc = `Moved ${(data.total_output_sats / 1e8).toFixed(8)} BTC.`;
    const features = [];
    if (data.segwit) features.push("Modern Discount (SegWit)");
    if (data.rbf_signaling) features.push("Changeable (RBF)");
    if (data.locktime_type !== "none") features.push(`Timelock (${data.locktime_type})`);

    const changeText = data.vout.length > 1 ?
        "Since Bitcoin is like a digital piggy bank, the sender had to break their 'coins' and send the leftover change back to themselves." :
        "This was a 'clean sweep'—every bit of the original coin was used up!";

    const uniqueScripts = new Set();
    let hasMultisig = false;
    let hasTimelock = data.locktime_type && data.locktime_type !== "none";
    let hasRBF = !!data.rbf_signaling;

    if (data.vin) data.vin.forEach(v => {
        if (v.script_type && v.script_type !== 'unknown' && v.script_type !== 'coinbase') uniqueScripts.add(v.script_type);
        if (v.script_type === 'p2sh' || v.script_type === 'p2wsh' || v.script_type === 'p2sh-p2wsh') hasMultisig = true;
    });
    if (data.vout) data.vout.forEach(v => {
        if (v.script_type && v.script_type !== 'unknown') uniqueScripts.add(v.script_type);
        if (v.script_type === 'p2sh' || v.script_type === 'p2wsh' || v.script_type === 'p2sh-p2wsh') hasMultisig = true;
    });

    let mechanicsHtml = "";
    if (uniqueScripts.size > 0 || hasMultisig || hasTimelock || hasRBF || data.segwit) {
        let items = Array.from(uniqueScripts).map(type => {
            const types = {
                "p2pkh": "<b>Legacy (P2PKH):</b> The original way to send Bitcoin. It locks funds to a public key hash.",
                "p2sh": "<b>Pay-to-Script-Hash (P2SH):</b> Locks funds to a custom script (like a shared bank account), keeping rules hidden until spent.",
                "p2wpkh": "<b>Native SegWit (P2WPKH):</b> A cheaper modern standard that separates the signature data to save block space.",
                "p2wsh": "<b>SegWit Script (P2WSH):</b> Uses the cheaper SegWit standard for advanced rules like multi-signature setups.",
                "p2tr": "<b>Taproot (P2TR):</b> The ultimate privacy upgrade. Complex smart contracts look exactly like standard, normal transfers!",
                "op_return": "<b>OP_RETURN:</b> An unspendable output that burns exact sats to etch a permanent public message or file into the blockchain.",
                "p2sh-p2wpkh": "<b>Nested SegWit:</b> A clever workaround that wrapped cheaper SegWit structures inside older legacy addresses.",
                "p2sh-p2wsh": "<b>Nested SegWit Script:</b> Wrapped advanced SegWit contracts inside legacy formats for older wallets."
            };
            return types[type] ? `<li style="margin-bottom: 4px;">${types[type]}</li>` : "";
        });

        if (hasMultisig) items.push(`<li style="margin-bottom: 4px;"><b>Complex Contracts (P2SH/P2WSH):</b> This transaction uses script-based conditions, heavily utilized for Multi-Signature wallets requiring multiple approvals to spend!</li>`);
        if (hasTimelock) items.push(`<li style="margin-bottom: 4px;"><b>Timelocked:</b> This includes a time restriction, meaning it couldn't be mined before a certain block height or timestamp was reached.</li>`);
        if (hasRBF) items.push(`<li style="margin-bottom: 4px;"><b>Replace-By-Fee (RBF):</b> The sender flagged it as replaceable, allowing them to bump the fee mid-flight to clear it faster if it got stuck.</li>`);
        if (data.segwit) items.push(`<li style="margin-bottom: 4px;"><b>Segregated Witness:</b> The transaction leverages the SegWit scaling upgrade, pulling signatures into a separate discount structure.</li>`);

        const mechanicsText = items.filter(x => x).join("");

        if (mechanicsText) {
            mechanicsHtml = `
                <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
                    <span class="story-icon">⚙️</span> 
                    <b>UNDER THE HOOD:</b> The raw mechanics.
                    <p class="story-help-text" style="margin-top:5px;">This transaction interacts with the following Bitcoin technologies:</p>
                    <ul style="margin-top: 5px; margin-bottom: 5px; opacity: 0.9; font-size: 0.9em; padding-left: 20px;">
                        ${mechanicsText}
                    </ul>
                </div>
            `;
        }
    }

    storyDiv.innerHTML = `
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">👤</span> 
            <b>THE INTENT:</b> ${desc}
            <p class="story-help-text">Think of this like writing a check. The sender is telling the world: "I don't own these coins anymore; they now belong to this new person."</p>
        </div>
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">📉</span> 
            <b>THE COST:</b> Network fee was ${data.fee_sats} sats (${data.fee_rate_sat_vb} sat/vB).
            <p class="story-help-text">The network is like a busy post office. To get the mailman (the miner) to pick up your letter first, you attached a small tip. You paid ${data.fee_rate_sat_vb} sats for every tiny bit of 'weight' this letter added to the mail bag.</p>
        </div>
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">🔒</span> 
            <b>FEATURES:</b> ${features.join(", ") || "Standard Transfer"}
            <p class="story-help-text">Some transactions have "Special Instructions." This might include a discount for using newer technology (SegWit) or a "Do Not Open Until Christmas" timer (Timelock).</p>
        </div>
        ${mechanicsHtml}
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">♻️</span> 
            <b>THE CHANGE:</b> Handling the leftovers.
            <p class="story-help-text">${changeText}</p>
        </div>
        <div class="story-step" style="font-family: 'VT323', 'Courier New', monospace;">
            <span class="story-icon">✍️</span> 
            <b>THE RECEIPT:</b> Digital Proof.
            <p class="story-help-text">The sender used a unique digital key to sign this. It's like a wax seal on an envelope that proves it wasn't tampered with, without the sender having to reveal their real identity.</p>
        </div>
    `;

    const segwitPanel = document.getElementById('segwit-panel');
    if (data.segwit && data.segwit_savings) {
        segwitPanel.classList.remove('hidden');
        const actBar = document.getElementById('actual-weight-bar');
        const legBar = document.getElementById('legacy-weight-bar');
        const savingsText = document.getElementById('savings-text');

        const actW = data.segwit_savings.weight_actual;
        const legW = data.segwit_savings.weight_if_legacy;

        actBar.style.width = `${(actW / legW) * 100}%`;
        legBar.style.width = '100%';
        savingsText.innerText = `SAVED ${data.segwit_savings.savings_pct}% SPACE`;
    } else {
        segwitPanel.classList.add('hidden');
    }

    const inputsList = document.getElementById('inputs-list');
    const outputsList = document.getElementById('outputs-list');

    inputsList.innerHTML = "<b>INPUTS (SENDER)</b>";
    outputsList.innerHTML = "<b>OUTPUTS (RECEIVER)</b>";

    let isCoinbase = false;

    if (data.vin) {
        data.vin.forEach(vin => {
            const div = document.createElement('div');
            div.className = 'utxo-box';

            if (vin.prevout) {
                const addrStr = vin.address ? `\nAddr: ${vin.address.substring(0, 8)}...` : "";
                div.innerText = `${vin.prevout.value_sats} sats\n[${vin.script_type.toUpperCase()}]${addrStr}`;
            } else {
                isCoinbase = true;
                div.innerText = `Newly Minted\n[COINBASE]`;
            }
            inputsList.appendChild(div);
        });
    }

    if (data.vout) {
        data.vout.forEach(vout => {
            const div = document.createElement('div');
            div.className = 'utxo-box';
            const addrStr = vout.address ? `\nAddr: ${vout.address.substring(0, 8)}...` : "";
            div.innerText = `${vout.value_sats} sats\n[${vout.script_type.toUpperCase()}]${addrStr}`;
            outputsList.appendChild(div);
        });
    }

    const feeBadge = document.getElementById('fee-badge');
    if (isCoinbase) {
        feeBadge.innerText = `SUBSIDY + FEES\n(Creates New Coins)`;
        feeBadge.style = "";
    } else {
        feeBadge.innerText = `NETWORK FEE: ${data.fee_sats || 0} sats\n(${data.fee_rate_sat_vb || 0} s/vB)`;
        feeBadge.style = "";
    }

    const advPanel = document.getElementById('advanced-features-panel');
    const advContent = document.getElementById('advanced-features-content');

    let hasRelativeTimelocks = false;
    let relativeTimelockHtml = "";

    if (data.vin) {
        data.vin.forEach((vin, i) => {
            if (vin.relative_timelock && vin.relative_timelock.enabled) {
                hasRelativeTimelocks = true;
                const typeStr = vin.relative_timelock.type === "time" ? "seconds" : "blocks";
                relativeTimelockHtml += `<div>&nbsp;&nbsp;Input ${i}: Delayed by ${vin.relative_timelock.value} ${typeStr}</div>`;
            }
        });
    }

    if (hasRBF || hasTimelock || hasRelativeTimelocks) {
        advPanel.classList.remove('hidden');
        let html = "";

        html += `<div style="margin-bottom: 8px;">`;
        html += `<b>Replace-By-Fee (RBF):</b> ${hasRBF ? '<span style="color:var(--term-green)">ENABLED</span>' : 'DISABLED'}`;
        html += `</div>`;

        html += `<div style="margin-bottom: 8px;">`;
        if (hasTimelock) {
            html += `<b>Absolute Timelock:</b> <span style="color:var(--term-green)">ACTIVE</span><br>`;
            html += `&nbsp;&nbsp;Type: ${data.locktime_type}<br>`;
            html += `&nbsp;&nbsp;Value: ${data.locktime_value}`;
        } else {
            html += `<b>Absolute Timelock:</b> INACTIVE`;
        }
        html += `</div>`;

        html += `<div>`;
        if (hasRelativeTimelocks) {
            html += `<b>Relative Timelocks (BIP68):</b> <span style="color:var(--term-green)">ACTIVE</span><br>`;
            html += relativeTimelockHtml;
        } else {
            html += `<b>Relative Timelocks (BIP68):</b> INACTIVE`;
        }
        html += `</div>`;

        advContent.innerHTML = html;
    } else {
        advPanel.classList.add('hidden');
    }
}

function setLoading(isLoading) {
    const overlay = document.getElementById('loading-overlay');
    if (isLoading) overlay.classList.remove('hidden');
    else overlay.classList.add('hidden');
}

function setStatus(msg) {
    document.getElementById('footer-msg').innerText = "STATUS: " + msg;
    const crt = document.getElementById('status-display');
    crt.innerHTML += `<p>> ${msg}</p>`;
    crt.scrollTop = crt.scrollHeight;
}

function showHelp() {
    alert("INSTRUCTIONS:\n1. Select TX JSON and paste a JSON fixture array/object.\n2. Or select Block Upload and attach blk.dat, rev.dat, and xor.dat.\n3. Click DEMO to load a demo fixture(s).\n4. Click EXPLORE.");
}

async function loadDemo() {
    document.querySelector('input[name="mode"][value="tx"]').checked = true;
    toggleMode();
    const area = document.getElementById('tx-json-input');
    area.value = "LOADING DEMO FIXTURE...";
    try {
        const response = await fetch('/api/demo');
        if (!response.ok) throw new Error("Could not load demo file");
        const text = await response.text();
        area.value = text;
    } catch (e) {
        area.value = "ERROR: " + e.message;
    }
}

async function loadDemoBlock() {
    document.querySelector('input[name="mode"][value="block"]').checked = true;
    toggleMode();

    setLoading(true);
    setStatus("TRIGGERING EXPERIMENTAL BLOCK MODE DEMO...");

    try {
        const response = await fetch('/api/demo/block');
        const data = await response.json();

        if (!data.ok) {
            throw new Error(data.error ? data.error.message : "Unknown Error");
        }

        renderResult(data);
        setStatus("BLOCK DEMO LOADED OK.");
    } catch (e) {
        setStatus("ERROR: " + e.message);
        alert("CRITICAL ERROR:\n" + e.message);
    } finally {
        setLoading(false);
    }
}
