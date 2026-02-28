import os
import time
import json
import random
import string
import base64
import sys
import argparse
from datetime import datetime, timedelta, timezone

from curl_cffi import requests

from eth_account import Account
from eth_keys import keys
from eth_utils import keccak
import base58
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import pad

import warnings
warnings.filterwarnings("ignore")
import hashlib
import openpyxl

Account.enable_unaudited_hdwallet_features()

def generate_wallet():
    acct, mnemonic = Account.create_with_mnemonic()
    priv = acct.key.hex()
    
    eth_address_bytes = bytes.fromhex(acct.address[2:])
    tron_address_bytes = b'\x41' + eth_address_bytes
    
    hash0 = hashlib.sha256(tron_address_bytes).digest()
    hash1 = hashlib.sha256(hash0).digest()
    checksum = hash1[:4]
    address_base58 = base58.b58encode(tron_address_bytes + checksum).decode('utf-8')
    
    return acct.key.hex() if hasattr(acct.key, "hex") else getattr(acct, "key").hex(), address_base58, mnemonic

def sign_message(priv_hex: str, message: str) -> str:
    priv_bytes = bytes.fromhex(priv_hex[2:] if priv_hex.startswith("0x") else priv_hex)
    message_bytes = message.encode('utf-8')
    prefix = f'\x19TRON Signed Message:\n{len(message_bytes)}'.encode('utf-8')
    hash_bytes = keccak(prefix + message_bytes)
    
    pk = keys.PrivateKey(priv_bytes)
    signature = pk.sign_msg_hash(hash_bytes)
    
    v = signature.v + 27
    sig_bytes = signature.r.to_bytes(32, 'big') + signature.s.to_bytes(32, 'big') + bytes([v])
    return "0x" + sig_bytes.hex()

def generate_nonce():
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    timestamp = str(int(time.time() * 1000))
    return f"{random_str}{timestamp}"

def encrypt_cryptojs_aes(plaintext, password="1wT1r7z8bZxDHVmZKAs6VFYSXOxmyh0lLByiw5TmF0="):
    salt = bytes([random.randint(0, 255) for _ in range(8)])
    password_bytes = password.encode("utf-8")
    key_iv = b""
    hash_block = b""
    while len(key_iv) < 48:
        hasher = MD5.new()
        hasher.update(hash_block + password_bytes + salt)
        hash_block = hasher.digest()
        key_iv += hash_block

    key = key_iv[:32]
    iv = key_iv[32:48]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode("utf-8"), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(b"Salted__" + salt + encrypted).decode("utf-8")

def generate_ainft_auth(user_id):
    payload = {
        "accessCode": "",
        "userId": user_id,
        "runtimeProvider": "openai"
    }
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    key_bytes = "LobeHub \xb7 LobeHub".encode('utf-8')
    
    result = bytearray()
    for i, b in enumerate(payload_bytes):
        result.append(b ^ key_bytes[i % len(key_bytes)])
        
    return base64.b64encode(result).decode('utf-8')

class AinftBot:
    def __init__(self, proxy=None):
        self.session = requests.Session(impersonate="chrome")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            
        self.priv, self.address, self.mnemonic = generate_wallet()
        print(f"Generated Wallet: {self.address}")
        
    def get_csrf(self):
        url = 'https://chat.ainft.com/api/auth/csrf'
        headers = {
            'accept': '*/*',
            'content-type': 'application/json',
            'referer': 'https://chat.ainft.com/purchase',
        }
        resp = self.session.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"CRSF Error {resp.status_code}: {resp.text}")
        return resp.json().get('csrfToken')

    def login(self):
        csrf = self.get_csrf()
        print(f"CSRF Token: {csrf}")
        
        expiration = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
        nonce = generate_nonce()
        chain_id = "0x2b6653dc"
        
        message = (
            f"Welcome to AINFT !\n"
            f"https://chat.ainft.com wants you to sign in with your TRON account:\n"
            f"{self.address}\n\n"
            f"Chain ID: {chain_id}\n"
            f"Expiration Time: {expiration}\n"
            f"Nonce: {nonce}"
        )
        
        signature = sign_message(self.priv, message)
        
        url = 'https://chat.ainft.com/api/auth/callback/tronlink?'
        data = {
            'message': message,
            'signature': signature,
            'version': '2',
            'csrfToken': csrf,
            'callbackUrl': 'https://chat.ainft.com/purchase'
        }
        
        headers = {
            'accept': '*/*',
            'origin': 'https://chat.ainft.com',
            'referer': 'https://chat.ainft.com/purchase',
            'x-auth-return-redirect': '1'
        }
        
        resp = self.session.post(url, data=data, headers=headers)
        print(f"Callback Status: {resp.status_code}")
        try:
            print("Callback JSON:", resp.json())
        except Exception:
            print("Callback TEXT:", resp.text)
        
        session_url = 'https://chat.ainft.com/api/auth/session'
        resp_session = self.session.get(session_url, headers={'accept': 'application/json'})
        print(f"Session Status: {resp_session.status_code}")
        try:
            js = resp_session.json()
            if "user" in js and js["user"]:
                print("Session established for:", js["user"]["name"])
            else:
                print("Session empty.", js)
        except Exception:
            print("Session TEXT:", resp_session.text)
            
        return True

    def claim_credits(self):
        nonce = generate_nonce()
        chain_id = "0x2b6653dc"
        
        message = (
            f"AINFT welcome gift-claim\n"
            f"Account:\n"
            f"{self.address}\n"
            f"Chain ID: {chain_id}\n"
            f"Nonce: {nonce}"
        )
        
        signature = sign_message(self.priv, message)
        
        timestamp_ms = str(int(time.time() * 1000))
        plaintext = f"AINFT welcome gift-claim|{timestamp_ms}"
        encrypted_token = encrypt_cryptojs_aes(plaintext)
        
        payload = {
            "0": {
                "json": {
                    "encryptedToken": encrypted_token,
                    "message": message,
                    "signature": signature,
                    "version": "2"
                }
            }
        }
        
        headers = {
            'accept': '*/*',
            'content-type': 'application/json',
            'origin': 'https://chat.ainft.com',
            'referer': 'https://chat.ainft.com/purchase',
            'x-ainft-chat-auth': generate_ainft_auth(self.address)
        }
        
        url = 'https://chat.ainft.com/trpc/lambda/user.claimSignupBonus?batch=1'
        resp = self.session.post(url, json=payload, headers=headers)
        print("Claim response:", resp.text)
        return resp.json()

    def create_api_key(self):
        headers = {
            'accept': '*/*',
            'content-type': 'application/json',
            'origin': 'https://chat.ainft.com',
            'referer': 'https://chat.ainft.com/key',
            'x-ainft-chat-auth': generate_ainft_auth(self.address)
        }
        
        random_name = f"Key {''.join(random.choices(string.ascii_letters + string.digits, k=6))}"
        payload = {
            "0": {
                "json": {
                    "name": random_name
                }
            }
        }
        
        url = 'https://chat.ainft.com/trpc/lambda/apiKey.createApiKey?batch=1'
        resp = self.session.post(url, json=payload, headers=headers)
        
        try:
            data = resp.json()
            api_key = data[0]["result"]["data"]["json"]["key"]
            print(f"Created API Key [{random_name}]: {api_key}")
            return api_key
        except Exception as e:
            print("API Key Creation Error:", resp.status_code, resp.text)
            return "ERROR_GENERATING_KEY"

    def save_account(self, api_key: str, filename: str = "accounts.xlsx"):
        file_exists = os.path.isfile(filename)
        if file_exists:
            wb = openpyxl.load_workbook(filename)
            ws = wb.active
        else:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.append(["Address", "Mnemonic", "Private Key", "API Key"])

        ws.append([self.address, self.mnemonic, self.priv, api_key])
        wb.save(filename)
        print(f"Saved account to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AINFT Auto-Registration Bot")
    parser.add_argument("-n", "--iterations", type=int, default=1, help="Number of accounts to register")
    args = parser.parse_args()
    
    proxies = []
    if os.path.exists("proxies.txt"):
        with open("proxies.txt", "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
            
    if proxies:
        if len(proxies) < args.iterations:
            print(f"[WARNING] Found {len(proxies)} proxies for {args.iterations} iterations. Proxies will be reused!")
        else:
            print(f"Loaded {len(proxies)} proxies.")
    else:
        print("[WARNING] No proxies.txt found or file is empty. Running without proxies.")

    for i in range(args.iterations):
        print(f"\n--- Starting iteration {i+1}/{args.iterations} ---")
        proxy = proxies[i % len(proxies)] if proxies else None
        if proxy:
            # simple format check, assuming format ip:port or user:pass@ip:port
            if "://" not in proxy:
                proxy = f"http://{proxy}"
            print(f"Using proxy: {proxy}")
            
        bot = AinftBot(proxy=proxy)
        if bot.login():
            bot.claim_credits()
            api_key = bot.create_api_key()
            bot.save_account(api_key=api_key)
        
        if i < args.iterations - 1:
            time.sleep(1) # simple delay between iterations
