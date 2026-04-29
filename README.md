# tools/ — local NFC terminal

A single-file Python POS terminal. Reads tapped cards via a USB NFC reader
(PC/SC) and submits charges to the payment-network lab. Runs on macOS,
Linux, and Windows with the same script.

## Quickstart

```bash
# 1. Create and activate a virtualenv
python3 -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate

# 2. Install the only dependency
pip install -r requirements.txt

# 3. Run
python local-terminal.py

# 4. Open the UI (same machine)
#    http://localhost:47823
```

That's it.

## Per-OS setup notes

- **macOS** — nothing else. PC/SC ships with the OS. Plug a USB reader in,
  it appears in the dropdown.
- **Linux** — `sudo apt install pcscd libpcsclite-dev && sudo systemctl
  start pcscd` (or your distro's equivalent).
- **Windows** — Smart Card service (`SCardSvr`) must be running (it usually
  is by default). If you previously ran Zadig on a reader, revert that
  reader's driver to `Microsoft Usbccid Smartcard Reader (WUDF)` first;
  WinUSB-bound readers don't show up in PC/SC.

## Config (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `TERMINAL_URL` | `https://bu-banking-cf.pages.dev/api/terminal/charge` | Where to POST the charge |
| `ADMIN_KEY` | `dupachuj` | HTTP Basic Auth password for the terminal endpoint |
| `PORT` | `47823` | Local HTTP listen port |
| `TAP_TIMEOUT` | `30` | Seconds to wait for a tap after clicking the button |

Override on the command line, e.g.:

```bash
PORT=8765 ADMIN_KEY=hunter2 python local-terminal.py
```

## What's where

- `local-terminal.py` — the whole app (server + embedded HTML/JS).
- `acr122u-bridge.py` — older keyboard-emulation helper for the
  `/api/webterminal` flow. Only useful if you want the web-hosted terminal
  page to receive taps via simulated keystrokes; otherwise ignore.
- `launch-local-terminal.ps1` — Windows launcher that detaches the
  Python server from the SSH session via WMI. Not needed on macOS/Linux —
  just run the script directly.

## Endpoints exposed

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/`              | the UI |
| GET    | `/readers`       | list connected PC/SC readers, plus current selection |
| POST   | `/reader`        | `{ "index": N }` — pick which reader to use |
| POST   | `/charge`        | `{ "amount": float, "merchant_id": "TeamX" }` — arms reader, on tap submits the charge |
