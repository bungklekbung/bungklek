import requests
from datetime import datetime, timezone
from eth_account import Account
from eth_account.messages import encode_defunct
import os
import json
import random
import time
import threading
from colorama import init, Fore, Style

# Inisialisasi warna terminal
init(autoreset=True)
Account.enable_unaudited_hdwallet_features()

# === Konstanta dan Endpoint ===
DOMAIN = "faucet-miniapp.monad.xyz"
BASE_URL = f"https://{DOMAIN}"
CHAIN_ID = 10

GET_NONCE_ENDPOINT = f"{BASE_URL}/api/auth"
POST_AUTH_ENDPOINT = f"{BASE_URL}/api/auth"
POST_CLAIM_ENDPOINT = f"{BASE_URL}/api/claim"
PROXY_CHECK_URL = "http://httpbin.org/ip"

# === Konfigurasi ===
MAX_ATTEMPTS = 3
ACCOUNTS_PER_BATCH = 5
lock = threading.Lock()

# === Logging Waktu ===
def log(msg):
    now = datetime.now().strftime("[%H:%M:%S]")
    with lock:
        print(f"{now} {msg}")

# === Proxy Handler ===
def get_proxies(proxy_file="proxy.txt"):
    if not os.path.exists(proxy_file):
        log(f"❌ File `{proxy_file}` tidak ditemukan.")
        return []
    with open(proxy_file, "r") as f:
        return [line.strip() for line in f if line.strip()]

def rotate_proxy(proxy_list, bad_proxy_set):
    available = [p for p in proxy_list if p not in bad_proxy_set]
    return random.choice(available) if available else None

def get_external_ip(proxy):
    try:
        res = requests.get(PROXY_CHECK_URL, proxies={"http": proxy, "https": proxy}, timeout=10)
        return res.json().get("origin")
    except:
        return None

# === Loader Akun ===
def load_accounts_from_json(json_file="data.json"):
    if not os.path.exists(json_file):
        log(f"❌ File `{json_file}` tidak ditemukan.")
        return []
    with open(json_file, "r") as f:
        data = json.load(f)
        return [
            {
                "wallet_address": acc["wallet_address"].strip(),
                "private_key": acc["private_key"].strip(),
                "fid": int(acc["fid"])
            }
            for acc in data
            if all(k in acc for k in ["wallet_address", "private_key", "fid"]) and acc["fid"]
        ]

# === Auth & Claim ===
def fetch_nonce(fid, proxy):
    try:
        res = requests.get(f"{GET_NONCE_ENDPOINT}?fid={fid}", proxies={"http": proxy, "https": proxy}, timeout=15)
        return res.json().get("nonce")
    except:
        return None

def build_siwe_message(wallet, fid, nonce, issued_at):
    return (
        f"{DOMAIN} wants you to sign in with your Ethereum account:\n"
        f"{wallet}\n\n"
        f"Farcaster Auth\n\n"
        f"URI: https://{DOMAIN}/\n"
        f"Version: 1\n"
        f"Chain ID: {CHAIN_ID}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Resources:\n"
        f"- farcaster://fid/{fid}"
    )

def sign_message(message, pk):
    encoded = encode_defunct(text=message)
    signed = Account.sign_message(encoded, pk)
    return "0x" + signed.signature.hex()

def authenticate(wallet_address, fid, private_key, proxy):
    nonce = fetch_nonce(fid, proxy)
    if not nonce:
        return None
    issued_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    message = build_siwe_message(wallet_address, fid, nonce, issued_at)
    signature = sign_message(message, private_key)
    payload = {
        "message": message,
        "signature": signature,
        "nonce": nonce,
        "fid": fid
    }
    headers = {"Content-Type": "application/json"}
    try:
        res = requests.post(POST_AUTH_ENDPOINT, headers=headers, json=payload, proxies={"http": proxy, "https": proxy}, timeout=30)
        return res.json().get("token")
    except:
        return None

def claim_faucet(token, wallet_address, proxy):
    payload = {"address": wallet_address}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        res = requests.post(POST_CLAIM_ENDPOINT, headers=headers, json=payload, proxies={"http": proxy, "https": proxy}, timeout=30)
        result = res.json()
        if "txHash" in result:
            return "already_claimed"
        return "claimed"
    except:
        return "failed"

# === Proses Satu Akun ===
def run_account(acc, proxy_list, bad_proxy_set):
    wallet = acc["wallet_address"]
    fid = acc["fid"]
    pk = acc["private_key"]

    for attempt in range(1, MAX_ATTEMPTS + 1):
        proxy = rotate_proxy(proxy_list, bad_proxy_set)
        if not proxy:
            log(f"❌ {wallet} - Semua proxy gagal dipakai.")
            return

        ip = get_external_ip(proxy)
        if not ip:
            bad_proxy_set.add(proxy)
            continue

        try:
            signer = Account.from_key(pk)
            if signer.address.lower() != wallet.lower():
                log(f"❌ {wallet} - Private key tidak cocok.")
                return
        except:
            log(f"❌ {wallet} - Private key tidak valid.")
            return

        token = authenticate(wallet, fid, pk, proxy)
        if not token:
            log(f"⚠️ {wallet} - Gagal auth, ganti proxy (percobaan {attempt}).")
            bad_proxy_set.add(proxy)
            continue

        result = claim_faucet(token, wallet, proxy)
        if result == "claimed":
            log(f"{Fore.GREEN}🎉 {wallet} - Berhasil klaim.")
            return
        elif result == "already_claimed":
            log(f"{Fore.YELLOW}✅ {wallet} - Sudah pernah klaim.")
            return
        else:
            log(f"⚠️ {wallet} - Gagal klaim, coba lagi (percobaan {attempt}).")
            bad_proxy_set.add(proxy)

        time.sleep(2)

    log(f"{Fore.RED}❌ {wallet} - Gagal klaim setelah {MAX_ATTEMPTS} percobaan.")

# === Dashboard / Header ===
def print_dashboard(title):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{title.center(60)}")
    print(f"{Fore.CYAN}{'='*60}\n")

# === Main Loop ===
def main_loop():
    try:
        while True:
            all_accounts = load_accounts_from_json()
            proxy_list = get_proxies()
            bad_proxy_set = set()

            if not all_accounts or not proxy_list:
                log("❌ Tidak ada akun atau proxy.")
                break

            batch_num = 1
            total = len(all_accounts)
            print_dashboard("🧪 AUTO CLAIM MONAD FAUCET DASHBOARD")
            log(f"🚀 Total akun: {Fore.GREEN}{total}{Style.RESET_ALL}")
            log(f"🔁 Mode thread: {Fore.MAGENTA}{ACCOUNTS_PER_BATCH} akun per batch")

            for i in range(0, total, ACCOUNTS_PER_BATCH):
                batch = all_accounts[i:i + ACCOUNTS_PER_BATCH]
                log(f"\n📦 {Fore.CYAN}Batch {batch_num}: {len(batch)} akun")
                threads = []

                for acc in batch:
                    t = threading.Thread(target=run_account, args=(acc, proxy_list, bad_proxy_set))
                    t.start()
                    threads.append(t)
                    time.sleep(0.5)

                for t in threads:
                    t.join()
                batch_num += 1

            log(f"{Fore.BLUE}⏳ Tunggu 1 jam sebelum klaim berikutnya...\n")
            time.sleep(1 * 60 * 60)  # 1 jam

    except KeyboardInterrupt:
        log("🛑 Program dihentikan oleh pengguna (Ctrl+C).")

if __name__ == "__main__":
    main_loop()
