#!/usr/bin/env python3
"""
local-terminal.py — self-contained POS terminal for the payment-network lab.

Single-file Python app. Runs an HTTP server on localhost (default port 47823)
that serves a POS-style page. When you click "Tap card", the server arms a
USB NFC reader via PC/SC, waits up to 30 s for a card, reads the NDEF text
payload (<bank_id>|<card_number>), and POSTs the charge through
bu-banking-cf's /api/terminal/charge endpoint, which forwards into the
payment network with the instructor bank's stored api_key.

No WebUSB, no Zadig, no keyboard wedge, no extra services. Works with any
PC/SC reader pyscard can see (ACR122U, ACR1252U, NC001, etc.) on any OS
with a PC/SC stack — that means macOS, Linux, and Windows.

================================ INSTALL ===================================

  Python 3.9+ on the machine. Then:

    pip install pyscard

  macOS:   pyscard builds against Apple's PCSC framework — comes with macOS,
           no extra setup. Plug in any USB NFC reader, it just works.
  Linux:   pcscd must be installed and running.  e.g. on Debian/Ubuntu:
             sudo apt install pcscd libpcsclite-dev
             sudo systemctl start pcscd
  Windows: Smart Card service (SCardSvr) must be running. Default Windows
           CCID drivers cover ACR122U/ACR1252U/etc. If a reader was ever
           Zadig'd to WinUSB, revert it (see DOCS.md).

================================ CONFIG ====================================

  Environment variables (all optional):
    TERMINAL_URL   POST target. Default: https://bu-banking-cf.pages.dev/api/terminal/charge
    ADMIN_KEY      Basic-Auth password for the terminal endpoint.
                   Default: "dupachuj" (the lab's current admin key).
    PORT           HTTP listen port. Default: 47823.
    TAP_TIMEOUT    Seconds to wait for a card after Tap. Default: 30.

================================  RUN  =====================================

    python local-terminal.py

  Then open http://localhost:47823 in any browser on the same machine.
  Pick a reader from the dropdown, type an amount, hit Tap card.
"""
from __future__ import annotations

import base64
import http.server
import json
import os
import re
import socketserver
import sys
import time
import urllib.error
import urllib.request
from typing import Optional, Tuple

# Force UTF-8 on stdio so card payloads and log lines never crash on Windows
# (default code page is cp1252, which can't encode common chars like arrows).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import NoCardException, CardConnectionException
    from smartcard.util import toHexString
except ImportError:
    print("pyscard not installed. Run: pip install pyscard", file=sys.stderr)
    sys.exit(1)


TERMINAL_URL = os.environ.get(
    "TERMINAL_URL",
    "https://bu-banking-cf.pages.dev/api/terminal/charge",
)
# Fall back to "dupachuj" (the lab's current admin key) when the env var
# isn't propagated; saves a debugging round-trip if the launcher quirks.
ADMIN_KEY = os.environ.get("ADMIN_KEY") or "dupachuj"
LISTEN_PORT = int(os.environ.get("PORT", "47823"))
TAP_TIMEOUT = float(os.environ.get("TAP_TIMEOUT", "30"))


# ---------- NFC plumbing -------------------------------------------------

def _read_block(connection, block: int) -> bytes:
    data, sw1, sw2 = connection.transmit([0xFF, 0xB0, 0x00, block, 0x04])
    if (sw1, sw2) != (0x90, 0x00):
        raise IOError(f"block {block}: status {sw1:02X}{sw2:02X}")
    return bytes(data)


def _write_block(connection, block: int, data: bytes) -> None:
    if len(data) != 4:
        raise ValueError("NTAG block write must be exactly 4 bytes")
    cmd = [0xFF, 0xD6, 0x00, block, 0x04] + list(data)
    _, sw1, sw2 = connection.transmit(cmd)
    if (sw1, sw2) != (0x90, 0x00):
        raise IOError(f"block {block}: status {sw1:02X}{sw2:02X}")


def _build_ndef_text_payload(text: str) -> bytes:
    """Build an NDEF Text record wrapped in TLV, padded to 4-byte blocks."""
    body = text.encode("utf-8")
    lang = b"en"
    # Text record payload: status byte (UTF-8, lang length in low bits) + lang + text
    payload = bytes([len(lang) & 0x3F]) + lang + body
    type_field = b"T"
    # Record header: MB=1 ME=1 CF=0 SR=1 IL=0 TNF=001 (well-known)
    if len(payload) > 255:
        raise ValueError("payload too large for short record")
    record = bytes([0xD1, len(type_field), len(payload)]) + type_field + payload
    if len(record) < 0xFF:
        tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    else:
        tlv = bytes([0x03, 0xFF, (len(record) >> 8) & 0xFF, len(record) & 0xFF]) + record + bytes([0xFE])
    pad = (-len(tlv)) % 4
    return tlv + b"\x00" * pad


def _walk_ndef_text(raw: bytes) -> Optional[str]:
    i = 0
    while i < len(raw):
        t = raw[i]
        if t == 0x00:
            i += 1
            continue
        if t == 0xFE:
            return None
        if t == 0x03:  # NDEF Message TLV
            i += 1
            if i >= len(raw):
                return None
            if raw[i] == 0xFF and i + 2 < len(raw):
                length = (raw[i + 1] << 8) | raw[i + 2]
                i += 3
            else:
                length = raw[i]
                i += 1
            msg = raw[i:i + length]
            for j in range(len(msg) - 2):
                if msg[j] == 0x54:  # Text record
                    lang_len = msg[j + 1] & 0x3F
                    blob = msg[j + 2 + lang_len:]
                    blob = blob.split(b"\xFE", 1)[0].rstrip(b"\x00")
                    return blob.decode("utf-8", "replace")
            return None
        # unknown TLV — try to skip
        i += 2
    return None


SELECTED_READER_INDEX = 0  # global; changed via POST /reader


def list_readers_safe() -> list:
    try:
        return readers()
    except Exception:
        return []


def wait_for_tap(timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """Block until a card is tapped or timeout. Return (payload, error)."""
    rs = list_readers_safe()
    if not rs:
        return None, "no PC/SC reader connected"
    idx = SELECTED_READER_INDEX if 0 <= SELECTED_READER_INDEX < len(rs) else 0
    r = rs[idx]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = r.createConnection()
            c.connect(CardConnection.T1_protocol)
            try:
                atr = c.getATR()
                raw = bytearray()
                for blk in range(4, 40):
                    try:
                        raw.extend(_read_block(c, blk))
                    except IOError:
                        break
                text = _walk_ndef_text(bytes(raw))
            finally:
                c.disconnect()
            if text:
                return text, None
            return None, f"no NDEF text record on tag {toHexString(atr)}"
        except (NoCardException, CardConnectionException):
            time.sleep(0.4)
    return None, "no card tapped within timeout"


def wait_for_program(text: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """Block until a card is tapped, then write `text` as an NDEF Text record.

    Returns (verified_text, error). On success `verified_text` is what we
    re-read from the tag after writing.
    """
    rs = list_readers_safe()
    if not rs:
        return None, "no PC/SC reader connected"
    idx = SELECTED_READER_INDEX if 0 <= SELECTED_READER_INDEX < len(rs) else 0
    r = rs[idx]
    try:
        ndef = _build_ndef_text_payload(text)
    except ValueError as e:
        return None, f"payload error: {e}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = r.createConnection()
            c.connect(CardConnection.T1_protocol)
            try:
                atr = c.getATR()
                # Write 4-byte blocks starting at block 4 (NTAG2xx user memory).
                for i in range(0, len(ndef), 4):
                    _write_block(c, 4 + i // 4, ndef[i:i + 4])
                # Read back to verify.
                raw = bytearray()
                for blk in range(4, 4 + (len(ndef) // 4) + 4):
                    try:
                        raw.extend(_read_block(c, blk))
                    except IOError:
                        break
                verified = _walk_ndef_text(bytes(raw))
            finally:
                c.disconnect()
            if verified is None:
                return None, f"wrote tag {toHexString(atr)} but could not verify NDEF read-back"
            return verified, None
        except (NoCardException, CardConnectionException):
            time.sleep(0.4)
        except IOError as e:
            return None, f"write failed: {e}"
    return None, "no card tapped within timeout"


# ---------- HTTP plumbing ------------------------------------------------

def _post_charge(amount: float, merchant_id: str, payload: str) -> Tuple[int, dict]:
    parts = payload.split("|")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return 400, {"error": f"invalid card payload: {payload[:80]}"}
    issuing_bank_id, card_number = parts[0], parts[1]

    body = json.dumps({
        "amount": amount,
        "card_number": card_number,
        "merchant_id": merchant_id,
        "issuing_bank_id": issuing_bank_id,
    }).encode()

    headers = {
        "Content-Type": "application/json",
        # Cloudflare bot management blocks the default Python-urllib User-Agent
        # with "error code: 1010". Use a normal-looking UA.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 ps-local-terminal/1.0",
    }
    if ADMIN_KEY:
        token = base64.b64encode(f"x:{ADMIN_KEY}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"

    req = urllib.request.Request(TERMINAL_URL, data=body, headers=headers, method="POST")
    print(f"[charge] POST {TERMINAL_URL} (auth={'set' if ADMIN_KEY else 'unset'})")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {
                "error": str(e),
                "body": raw.decode("utf-8", errors="replace")[:300],
                "auth_sent": bool(ADMIN_KEY),
            }
    except Exception as e:
        return 502, {"error": f"network error: {e}"}


HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local NFC Terminal</title>
<style>
  :root { --bg:#0b1020; --card:#141a30; --accent:#5eead4; --muted:#94a3b8; --good:#22c55e; --bad:#ef4444; --warn:#fbbf24; --text:#e5e7eb; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; min-height:100vh; }
  header { padding:12px 20px; background:#0f1630; border-bottom:1px solid #1f2747; display:flex; align-items:center; justify-content:space-between; }
  header h1 { margin:0; font-size:14px; letter-spacing:.5px; font-weight:500; }
  header small { color:var(--muted); font-size:11px; }
  main { padding:20px; max-width:480px; margin:0 auto; display:flex; flex-direction:column; gap:14px; }
  .amount-display { background:#0f1630; border:2px solid #1f2747; border-radius:12px; padding:24px; text-align:center; font-size:56px; font-weight:300; font-variant-numeric:tabular-nums; color:var(--accent); }
  .amount-display small { font-size:20px; color:var(--muted); margin-right:4px; }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .row label { color:var(--muted); font-size:13px; white-space:nowrap; }
  select, input, button { font:inherit; border-radius:8px; border:1px solid #1f2747; background:var(--card); color:var(--text); padding:10px 12px; }
  select { flex:1 1 auto; }
  .keypad { display:grid; grid-template-columns:repeat(3, 1fr); gap:8px; }
  .key { background:var(--card); border:1px solid #1f2747; border-radius:10px; padding:18px 0; font-size:22px; font-weight:500; text-align:center; cursor:pointer; user-select:none; }
  .key:active { background:#1f2747; }
  .key.clear { color:var(--warn); }
  .key.back  { color:var(--muted); }
  .actions button { width:100%; padding:16px; font-size:16px; font-weight:600; background:var(--accent); color:#0b1020; border:none; cursor:pointer; border-radius:8px; }
  .actions button:disabled { opacity:.5; cursor:not-allowed; }
  .status { padding:14px; border-radius:12px; text-align:center; font-size:14px; display:none; }
  .status.show { display:block; }
  .status.waiting  { background:#1f1a0e; color:var(--warn); border:1px solid var(--warn); }
  .status.approved { background:#0a2b2a; color:var(--good); border:1px solid var(--good); font-size:18px; font-weight:600; }
  .status.declined { background:#2b0a0a; color:var(--bad); border:1px solid var(--bad); font-size:18px; font-weight:600; }
  .status small { display:block; margin-top:4px; font-size:11px; color:var(--muted); font-weight:400; }
</style></head><body>
<header>
  <h1>Local NFC Terminal</h1>
  <div style="display:flex;gap:12px;align-items:center">
    <a href="#" onclick="openProgram();return false" style="color:var(--accent);font-size:12px;text-decoration:none">Program card →</a>
    <small id="cfg">localhost</small>
  </div>
</header>
<main>
  <div class="amount-display"><small>£</small><span id="amount">0.00</span></div>
  <div class="row">
    <label for="reader">Reader:</label>
    <select id="reader" onchange="setReader()"><option>(loading...)</option></select>
    <button onclick="loadReaders()" title="Refresh reader list" style="padding:8px 12px">⟳</button>
  </div>
  <div class="row">
    <label for="merchant">Credit to:</label>
    <select id="merchant">
      <option>Team1</option><option>Team2</option><option>Team3</option><option>Team4</option>
      <option>Team5</option><option>Team6</option><option>Team7</option><option selected>TestTeam</option>
    </select>
  </div>
  <div class="keypad">
    <div class="key" data-key="1">1</div><div class="key" data-key="2">2</div><div class="key" data-key="3">3</div>
    <div class="key" data-key="4">4</div><div class="key" data-key="5">5</div><div class="key" data-key="6">6</div>
    <div class="key" data-key="7">7</div><div class="key" data-key="8">8</div><div class="key" data-key="9">9</div>
    <div class="key clear" data-key="C">CLR</div><div class="key" data-key="0">0</div><div class="key back" data-key="B">⌫</div>
  </div>
  <div class="actions"><button id="tap" onclick="charge()">Tap card</button></div>
  <div id="status" class="status"></div>
</main>
<script>
const $ = id => document.getElementById(id);
let amount = 0;
function openProgram(){ window.open('/program', 'program-card', 'width=460,height=620'); }
function render(){ $('amount').textContent = (amount/100).toFixed(2); }
document.querySelectorAll('.key').forEach(k => k.addEventListener('click', () => {
  const v = k.dataset.key;
  if (v === 'C') amount = 0;
  else if (v === 'B') amount = Math.floor(amount/10);
  else amount = Math.min(amount*10 + parseInt(v,10), 99999999);
  render();
  setStatus('','');
}));
function setStatus(kind, html){ const s = $('status'); s.className = 'status' + (kind ? ' show '+kind : ''); s.innerHTML = html; }
function escape(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function loadReaders(){
  const sel = $('reader');
  try {
    const r = await fetch('/readers');
    const body = await r.json();
    const rs = body.readers || [];
    sel.innerHTML = '';
    if (!rs.length){
      const opt = document.createElement('option');
      opt.textContent = '(no readers detected)';
      opt.disabled = true;
      sel.appendChild(opt);
      return;
    }
    rs.forEach((name, i) => {
      const opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = i + ': ' + name;
      if (i === body.selected) opt.selected = true;
      sel.appendChild(opt);
    });
  } catch (e) {
    sel.innerHTML = '<option disabled>error: ' + escape(e.message) + '</option>';
  }
}

async function setReader(){
  const idx = parseInt($('reader').value, 10);
  if (!Number.isFinite(idx)) return;
  try {
    const r = await fetch('/reader', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({index: idx}) });
    if (!r.ok) {
      const b = await r.json().catch(()=>({}));
      alert('Failed: ' + (b.error || r.status));
    }
  } catch (e) { alert('Error: ' + e.message); }
}

async function charge(){
  const amt = amount/100;
  if (amt <= 0){ alert('Enter an amount first.'); return; }
  const merchant = $('merchant').value;
  $('tap').disabled = true;
  setStatus('waiting', 'Tap a card on the reader…<br><small>£'+amt.toFixed(2)+' → '+merchant+'</small>');
  try {
    const r = await fetch('/charge', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({amount: amt, merchant_id: merchant})});
    const body = await r.json();
    if (!r.ok) {
      setStatus('declined', 'Error<br><small>' + escape(body.error || r.status) + '</small>');
      return;
    }
    const result = body.result || {};
    if (result.status === 'authorized') {
      setStatus('approved', 'APPROVED · £' + amt.toFixed(2) + '<br><small>auth ' + (result.authorization_code || '—') + ' · tx ' + (result.transaction_id || '').slice(0,8) + '</small>');
      amount = 0; render();
    } else if (result.status === 'pending') {
      setStatus('waiting', 'Authorization pending — student bank not responding<br><small>tx ' + (result.transaction_id || '').slice(0,8) + '</small>');
    } else {
      const code = result.response_code ? ' (code ' + result.response_code + ')' : '';
      setStatus('declined', 'Declined' + code + '<br><small>' + escape(result.message || result.error || '') + '</small>');
    }
  } catch (e) {
    setStatus('declined', 'Local error<br><small>' + escape(e.message) + '</small>');
  } finally {
    $('tap').disabled = false;
  }
}
render();
loadReaders();
</script></body></html>
"""


PROGRAM_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Program card</title>
<style>
  :root { --bg:#0b1020; --card:#141a30; --accent:#5eead4; --muted:#94a3b8; --good:#22c55e; --bad:#ef4444; --warn:#fbbf24; --text:#e5e7eb; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; min-height:100vh; }
  header { padding:12px 20px; background:#0f1630; border-bottom:1px solid #1f2747; }
  header h1 { margin:0; font-size:14px; letter-spacing:.5px; font-weight:500; }
  main { padding:20px; max-width:460px; margin:0 auto; display:flex; flex-direction:column; gap:14px; }
  label { display:block; color:var(--muted); font-size:12px; margin-bottom:4px; letter-spacing:.3px; text-transform:uppercase; }
  input, select, button { font:inherit; border-radius:8px; border:1px solid #1f2747; background:var(--card); color:var(--text); padding:10px 12px; width:100%; }
  input.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .preview { background:#0f1630; border:1px dashed #1f2747; border-radius:8px; padding:10px 12px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; color:var(--muted); word-break:break-all; }
  button.primary { background:var(--accent); color:#0b1020; border:none; cursor:pointer; padding:14px; font-weight:600; font-size:15px; }
  button.primary:disabled { opacity:.5; cursor:not-allowed; }
  .status { padding:14px; border-radius:12px; text-align:center; font-size:14px; display:none; }
  .status.show { display:block; }
  .status.waiting  { background:#1f1a0e; color:var(--warn); border:1px solid var(--warn); }
  .status.ok       { background:#0a2b2a; color:var(--good); border:1px solid var(--good); font-weight:600; }
  .status.err      { background:#2b0a0a; color:var(--bad);  border:1px solid var(--bad);  font-weight:600; }
  .status small { display:block; margin-top:4px; font-size:11px; color:var(--muted); font-weight:400; word-break:break-all; }
  .help { font-size:11px; color:var(--muted); margin-top:4px; }
</style></head><body>
<header><h1>Program card</h1></header>
<main>
  <div>
    <label for="bank">Bank ID</label>
    <input id="bank" class="mono" placeholder="29329eb1-4fc0-4db4-bd92-debdb81f81c6" autocomplete="off" spellcheck="false">
    <div class="help">Paste the issuing bank's UUID.</div>
  </div>
  <div>
    <label for="acct">Account number</label>
    <input id="acct" class="mono" placeholder="0000000000000001" autocomplete="off" inputmode="numeric" maxlength="16">
    <div class="help">16-digit account number.</div>
  </div>
  <div>
    <label>Will write</label>
    <div class="preview" id="preview">—</div>
  </div>
  <button class="primary" id="write" onclick="program()">Tap card to write</button>
  <div id="status" class="status"></div>
</main>
<script>
const $ = id => document.getElementById(id);
function escape(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function setStatus(kind, html){ const s = $('status'); s.className = 'status' + (kind ? ' show '+kind : ''); s.innerHTML = html; }
function refreshPreview(){
  const b = $('bank').value.trim();
  const a = $('acct').value.trim();
  $('preview').textContent = (b && a) ? (b + '|' + a) : '—';
}
$('bank').addEventListener('input', refreshPreview);
$('acct').addEventListener('input', refreshPreview);

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

async function program(){
  const bank = $('bank').value.trim();
  const acct = $('acct').value.trim();
  if (!UUID_RE.test(bank)){ setStatus('err', 'Bank ID must be a UUID'); return; }
  if (!/^\\d{1,16}$/.test(acct)){ setStatus('err', 'Account number must be up to 16 digits'); return; }
  const padded = acct.padStart(16, '0');
  $('write').disabled = true;
  setStatus('waiting', 'Tap a card on the reader to write…<br><small>' + escape(bank + '|' + padded) + '</small>');
  try {
    const r = await fetch('/program', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({bank_id: bank, account_number: padded})
    });
    const body = await r.json();
    if (!r.ok) {
      setStatus('err', 'Write failed<br><small>' + escape(body.error || r.status) + '</small>');
      return;
    }
    setStatus('ok', 'Card programmed<br><small>verified: ' + escape(body.verified || '') + '</small>');
  } catch (e) {
    setStatus('err', 'Local error<br><small>' + escape(e.message) + '</small>');
  } finally {
    $('write').disabled = false;
  }
}
refreshPreview();
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: ARG002
        # Mute the default access log; print taps explicitly instead.
        return

    def _reply(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            data = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/program":
            data = PROGRAM_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/readers":
            rs = [str(r) for r in list_readers_safe()]
            self._reply(200, {"readers": rs, "selected": SELECTED_READER_INDEX})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path == "/reader":
            global SELECTED_READER_INDEX
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length).decode() or "{}")
            except json.JSONDecodeError:
                self._reply(400, {"error": "invalid json"})
                return
            idx = body.get("index")
            rs = list_readers_safe()
            if not isinstance(idx, int) or idx < 0 or idx >= len(rs):
                self._reply(400, {"error": "index out of range",
                                  "available": [str(r) for r in rs]})
                return
            SELECTED_READER_INDEX = idx
            print(f"[reader] selected #{idx}: {rs[idx]}")
            self._reply(200, {"selected": idx, "name": str(rs[idx])})
            return

        if self.path == "/program":
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length).decode() or "{}")
            except json.JSONDecodeError:
                self._reply(400, {"error": "invalid json"})
                return
            bank_id = (body.get("bank_id") or "").strip()
            account_number = (body.get("account_number") or "").strip()
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", bank_id):
                self._reply(400, {"error": "bank_id must be a UUID"})
                return
            if not re.match(r"^\d{1,16}$", account_number):
                self._reply(400, {"error": "account_number must be up to 16 digits"})
                return
            account_number = account_number.zfill(16)
            payload = f"{bank_id}|{account_number}"
            print(f"[program] arming reader, payload={payload} ...")
            verified, err = wait_for_program(payload, TAP_TIMEOUT)
            if err:
                print(f"[program] failed: {err}")
                self._reply(400, {"error": err})
                return
            print(f"[program] wrote and verified: {verified}")
            self._reply(200, {"verified": verified, "payload": payload})
            return

        if self.path != "/charge":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            self._reply(400, {"error": "invalid json"})
            return

        amount = body.get("amount")
        merchant_id = body.get("merchant_id") or "TestTeam"
        if not isinstance(amount, (int, float)) or amount <= 0:
            self._reply(400, {"error": "amount must be a positive number"})
            return

        print(f"[charge] arming reader, amount={amount} -> {merchant_id} ...")
        payload, err = wait_for_tap(TAP_TIMEOUT)
        if err:
            print(f"[charge] no tap: {err}")
            self._reply(400, {"error": err})
            return

        print(f"[tap] {payload}")
        status, result = _post_charge(float(amount), merchant_id, payload)
        print(f"[charge] {status} {result}")
        self._reply(status, {"card": payload, "result": result})


class ReusableTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    rs = list_readers_safe()
    if not rs:
        print("WARNING: no PC/SC readers visible right now.")
        print("         Plug in a reader; refresh /readers in the page once it's ready.")
    else:
        for i, r in enumerate(rs):
            print(f"Reader {i}: {r}{' (selected)' if i == SELECTED_READER_INDEX else ''}")
    print(f"Remote terminal: {TERMINAL_URL}")
    if not ADMIN_KEY:
        print("WARNING: ADMIN_KEY env var not set. The remote endpoint may reject calls.")
        print("         Set it via: ADMIN_KEY=<your-pw> python local-terminal.py")
    addr = ("127.0.0.1", LISTEN_PORT)
    print(f"\nServing UI on http://{addr[0]}:{addr[1]}  (Ctrl-C to stop)\n")
    ReusableTCPServer(addr, Handler).serve_forever()


if __name__ == "__main__":
    main()
