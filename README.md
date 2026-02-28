# AINFT Auto-Registration Bot

This script automates the creation of TRON wallets, registration, generating CSRF/Session tokens, claiming signup bonuses (1,000,000 credits), and creating API keys for `chat.ainft.com`. Uniquely, the bot fully simulates frontend encryption mechanisms (CryptoJS AES and custom XOR Base64 `x-ainft-chat-auth` headers).

All successfully registered accounts are saved into an Excel file (`accounts.xlsx`).

## Features
- **Wallet Generator**: Automatically generates TRON wallets and mnemonics (eth_account + Base58Check generation).
- **Custom Signature Logic**: Generates Ethereum-style SIWE messages and signs them correctly for the TRON network callback.
- **Frontend Reverse-Engineering**:
  - Automatically encrypts payloads using CryptoJS AES logic bypassing static keys from the JS bundles.
  - Automatically forms the XOR Base64 `x-ainft-chat-auth` header used by trpc endpoints.
- **Proxy Support**: Connects through proxies via `curl_cffi` to mimic real Chrome browser fingerprints (JA3/HTTP2).
- **Data Export**: Generates `accounts.xlsx` mapping TRON addresses, mnemonics, private keys, and API keys.

## Installation

1. Make sure you have Python 3.9+ installed.
2. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install the dependencies:
   ```bash
   pip install curl_cffi eth-account base58 pycryptodome openpyxl
   ```

## Usage

You can run the script directly:
```bash
python main.py
```

### Command-line Arguments
- `-n` or `--iterations`: Specify the number of accounts to register. Default is 1.

Example for generating 5 accounts in one run:
```bash
python main.py -n 5
```

### Proxy Support
To use proxies, create a `proxies.txt` file in the same directory as `main.py`. Add one proxy per line.
The bot will iterate through them across account generation.

Example `proxies.txt`:
```
http://user:pass@192.168.1.1:8080
http://10.0.0.1:80
```
If you specify more iterations than available proxies, the bot will automatically loop through the proxy list from the beginning.

## Output
Upon successful registration, the script will append a new row to `accounts.xlsx` containing:
- Address (TRON TRC20 Wallet)
- Mnemonic (Seed Phrase)
- Private Key (Hex)
- API Key (e.g. `sk-...` generated from the chat settings)
