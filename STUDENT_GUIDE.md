# Local NFC Terminal — student guide (v2 cards)

Tiny POS terminal you run on your own laptop. Two things it can do:

1. **Register + program a card** — pick an amount, tap a blank NFC tag, tag is registered with the network and written with the right NDEF payload in one step.
2. **Take a payment** — type an amount, tap a programmed card, network checks the card's remaining balance, replies APPROVED / DECLINED.

You don't need to re-register your bank. **Use the bank you registered last session** — its `bank_id` and `api_key` carry over (the instructor copied them into the v2 system and gave you a fresh `api_key`).

## What you need

- A laptop running **macOS, Linux, or Windows**
- **Python 3.9+** (`python --version` to check)
- A **USB NFC reader** that pyscard can see (ACR122U, ACR1252U, NC001, etc.)
- The two files: `local-terminal.py` and `requirements.txt`

## One-time setup

Open a terminal in the folder where you saved the files.

```
pip install -r requirements.txt
```

Then OS-specific bits:

- **macOS** — nothing. PC/SC ships with the OS. Plug a reader in.
- **Linux** —
  ```
  sudo apt install pcscd libpcsclite-dev
  sudo systemctl start pcscd
  ```
- **Windows** — `SCardSvr` is on by default. If a previous session ran Zadig on the reader, revert it to `Microsoft Usbccid Smartcard Reader (WUDF)` in Device Manager first.

## Start the terminal

```
python local-terminal.py
```

You'll see something like:

```
Reader 0: ACS ACR122U PICC Interface (selected)
Payment network: https://paymentsystem-cards-cf.pages.dev
Serving UI on http://127.0.0.1:47823  (Ctrl-C to stop)
```

Leave that window open. In any browser on the same machine open **http://localhost:47823**.

## Page layout

Two tabs along the top:

- **Charge** — what you use during the live tap-and-pay demo (amount keypad, "Tap card", APPROVED/DECLINED).
- **Register card** — what you use *first*, to set up cards for your team.

## Register + program a card (this is the new bit)

The local terminal does **all three** of these in one click:

1. Picks the next 16-digit card number for your bank.
2. Calls `POST /api/cards/register` on the payment network with your `X-API-Key`, registering the card with the amount you chose.
3. Reads the blank NFC tag you tap and writes `<bank_id>|<card_number>` to it (as an NDEF Text record).

Steps:

1. Click the **Register card** tab.
2. **Bank** dropdown — pick your team's bank by name (the instructor's list of banks loads automatically). The first time, also paste your **Issuer API key** in the "API key (X-API-Key)" field. The terminal caches it locally per bank in `~/.bu-banking-terminal/config.json`, so next time the field is pre-filled when you pick the bank.
3. **Amount** — between £0.01 and £10. (£100 budget per bank, max £10 per card.)
4. Click **Register + tap card to write**. Status flips to "Registering on v2, then tap a card to write…".
5. Tap a **blank** NFC tag on the reader within 30 s.
6. You'll see `WRITTEN <bank_id>|<card_number>` (green) when it succeeds.

That tag now exists in the payment system with the amount you chose, and is physically programmed with the right payload. Hand it to the instructor, or use it on the **Charge** tab to test.

If you tap a tag that's already programmed, the terminal will overwrite it.

## Take a payment

Same as last session — but balances live entirely on the payment network now, so your bank doesn't need to be running for charges to work.

1. Click the **Charge** tab.
2. Pick your reader from the dropdown (click ⟳ if you plugged it in after the page loaded).
3. Pick the **Credit to** team — where the money should land.
4. Type an amount on the keypad.
5. Click **Tap card**, tap a programmed card.
6. APPROVED (green) with auth code, or Declined (red) with one of:
   - **14 — Card not registered**: this tag's `card_number` doesn't exist on the issuer's bank. Use the Register card tab to register and program it first.
   - **51 — Card balance insufficient**: this card has been spent. Either pick another card or ask the instructor to reset it.

## How balances work

Every charge on a card decrements:

- That card's balance on the network (cap = the amount you chose at registration, max £10).
- The issuing bank's balance on the network (cap = £100, the bank's total budget).

When a card hits £0 the network declines further charges with code 51. Your bank's overall £100 keeps draining until cards are reset or new ones issued.

You can show your bank's live state in your team's banking app by calling:

```
curl -H "X-API-Key: <your api_key>" \
  https://paymentsystem-cards-cf.pages.dev/api/cards/me
```

Returns your bank's budget summary plus every card with current balance. Drop that into your UI.

## Optional config (env vars)

```
PORT=8765 \
PAYMENT_NETWORK_URL=https://paymentsystem-cards-cf.pages.dev \
ACQUIRER_API_KEY=sk_... \
python local-terminal.py
```

| Var | Default | What |
|---|---|---|
| `PORT` | `47823` | Port the local web UI listens on |
| `PAYMENT_NETWORK_URL` | v2 base URL | The payment system to talk to |
| `ACQUIRER_API_KEY` | unset | The acquirer's `X-API-Key` for charges. Without this, charges fail. The Register-card flow uses the issuer's key from the form, not this. |
| `TAP_TIMEOUT` | `30` | Seconds to wait for a tap |

## Stopping it

Ctrl-C in the terminal window where the script is running.

## Troubleshooting

- **"no PC/SC reader connected"** — reader isn't plugged in, or (Linux) `pcscd` isn't running, or (Windows) the reader is on a WinUSB driver from Zadig — revert it.
- **Dropdown says "(no readers detected)"** — same as above; click ⟳ after fixing.
- **"no NDEF text record on tag"** — the tag hasn't been programmed yet. Use the Register card tab.
- **"no card tapped within timeout"** — too slow; click the button again.
- **Register-card returns 403 "registration_key required"** — that's the bank-level error; you tried to register a *bank* without a key. For *cards* you only need the bank's `api_key`.
- **Register-card returns 400 "amount cannot exceed £10"** — pick £10 or less.
- **Register-card returns 400 "insufficient bank budget"** — your bank has already issued £100 worth of cards. Reset some via the instructor, or use one of the cards you've already issued.
- **Charge shows "Card not registered" (code 14)** — the tag's `card_number` doesn't exist on the issuer. Re-register and re-program from the Register card tab.

## Quick reference

| | |
|---|---|
| Local UI | `http://localhost:47823` |
| Network base URL | `https://paymentsystem-cards-cf.pages.dev` |
| See your cards | `GET /api/cards/me` (with `X-API-Key`) |
| See one card | `GET /api/cards/<bank_id>/<card_number>` (no auth) |
| Live overview (instructor view) | `https://paymentsystem-cards-cf.pages.dev/overview` |
