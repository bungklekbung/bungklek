import requests
from datetime import datetime, timezone
from eth_account import Account
from eth_account.messages import encode_defunct
import os
import json
import random
import time
import threading
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.live import Live

Account.enable_unaudited_hdwallet_features()
console = Console()

# === Konstanta dan Endpoint ===

DOMAIN = "faucet-miniapp.monad.xyz"
BASE_URL = f"https://{DOMAIN}"
CHAIN\_ID = 10

GET\_NONCE\_ENDPOINT = f"{BASE\_URL}/api/auth"
POST\_AUTH\_ENDPOINT = f"{BASE\_URL}/api/auth"
POST\_CLAIM\_ENDPOINT = f"{BASE\_URL}/api/claim"
PROXY\_CHECK\_URL = "[http://httpbin.org/ip](http://httpbin.org/ip)"

MAX\_ATTEMPTS = 2
ACCOUNTS\_PER\_BATCH = 5
lock = threading.Lock()

# === Loader Akun & Proxy ===

def load\_accounts\_from\_json(json\_file="data.json"):
if not os.path.exists(json\_file):
console.print(f"\[bold red]❌ File `{json_file}` tidak ditemukan.")
return \[]
with open(json\_file, "r") as f:
data = json.load(f)
return \[
{
"wallet\_address": acc\["wallet\_address"].strip(),
"private\_key": acc\["private\_key"].strip(),
"fid": int(acc\["fid"])
}
for acc in data
if all(k in acc for k in \["wallet\_address", "private\_key", "fid"])
]

def load\_proxies(proxy\_file="proxy.txt"):
if not os.path.exists(proxy\_file):
console.print(f"\[bold red]❌ File `{proxy_file}` tidak ditemukan.")
return \[]
proxies = \[]
with open(proxy\_file, "r") as f:
for line in f:
proxy\_raw = line.strip()
if not proxy\_raw:
continue
proxies.append({"http": proxy\_raw, "https": proxy\_raw})
return proxies

def get\_external\_ip(proxy):
try:
res = requests.get(PROXY\_CHECK\_URL, proxies=proxy, timeout=10)
return res.json().get("origin")
except:
return None

def fetch\_nonce(fid, proxy):
try:
res = requests.get(f"{GET\_NONCE\_ENDPOINT}?fid={fid}", proxies=proxy, timeout=15)
return res.json().get("nonce")
except:
return None

def build\_siwe\_message(wallet, fid, nonce, issued\_at):
return (
f"{DOMAIN} wants you to sign in with your Ethereum account:\n"
f"{wallet}\n\nFarcaster Auth\n\n"
f"URI: https\://{DOMAIN}/\nVersion: 1\nChain ID: {CHAIN\_ID}\n"
f"Nonce: {nonce}\nIssued At: {issued\_at}\n"
f"Resources:\n- farcaster://fid/{fid}"
)

def sign\_message(message, pk):
encoded = encode\_defunct(text=message)
signed = Account.sign\_message(encoded, pk)
return "0x" + signed.signature.hex()

def authenticate(wallet\_address, fid, private\_key, proxy):
nonce = fetch\_nonce(fid, proxy)
if not nonce:
return None
issued\_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
message = build\_siwe\_message(wallet\_address, fid, nonce, issued\_at)
signature = sign\_message(message, private\_key)
payload = {
"message": message,
"signature": signature,
"nonce": nonce,
"fid": fid
}
headers = {"Content-Type": "application/json"}
try:
res = requests.post(POST\_AUTH\_ENDPOINT, headers=headers, json=payload, proxies=proxy, timeout=30)
return res.json().get("token")
except:
return None

def claim\_faucet(token, wallet\_address, proxy):
payload = {"address": wallet\_address}
headers = {
"Authorization": f"Bearer {token}",
"Content-Type": "application/json"
}
try:
res = requests.post(POST\_CLAIM\_ENDPOINT, headers=headers, json=payload, proxies=proxy, timeout=30)
result = res.json()
if "txHash" in result:
return "already\_claimed"
return "claimed"
except:
return "failed"

def run\_account(acc, proxies):
wallet = acc\["wallet\_address"]
fid = acc\["fid"]
pk = acc\["private\_key"]
used\_proxies = set()

```
for attempt in range(1, MAX_ATTEMPTS + 1):
    available_proxies = [p for p in proxies if str(p) not in used_proxies]
    if not available_proxies:
        used_proxies.clear()
        available_proxies = proxies

    proxy = random.choice(available_proxies)
    used_proxies.add(str(proxy))
    ip = get_external_ip(proxy)
    if not ip:
        with lock:
            console.print(f"[yellow]⚠️ {wallet} - Proxy gagal (percobaan {attempt})")
        continue
    else:
        with lock:
            console.print(f"[cyan]🌐 {wallet} - IP proxy: {ip}")

    try:
        signer = Account.from_key(pk)
        if signer.address.lower() != wallet.lower():
            with lock:
                console.print(f"[red]❌ {wallet} - Private key tidak cocok")
            return
    except:
        with lock:
            console.print(f"[red]❌ {wallet} - Private key tidak valid")
        return

    token = authenticate(wallet, fid, pk, proxy)
    if not token:
        with lock:
            console.print(f"[yellow]⚠️ {wallet} - Autentikasi gagal (percobaan {attempt})")
        continue

    result = claim_faucet(token, wallet, proxy)
    with lock:
        if result == "claimed":
            console.print(f"[green]🎉 {wallet} - Klaim sukses")
            return
        elif result == "already_claimed":
            console.print(f"[blue]✅ {wallet} - Sudah diklaim sebelumnya")
            return
        else:
            console.print(f"[yellow]⚠️ {wallet} - Klaim gagal (percobaan {attempt})")
    time.sleep(2)

with lock:
    console.print(f"[red]❌ {wallet} - Gagal setelah {MAX_ATTEMPTS} percobaan")
```

def animate\_banner():
frames = \[
r"""
.     .        .        .
.     .   .  .     .     .
.  \   /  \   /
.--(   )--.
.     \ /     .
.     .   o   .     .
""",
r"""
.     .   .  .     .     .
.     .        .        .
.--(   )--.
.     \ /     .
.     .   o   .     .
.  \   /  \   /
""",
r"""
.     .        .        .
.     .   o   .     .
.  \   /  \   /
.     (^)^     .
.--(   )--.
""",
]
scroll\_text = " by angga 404 "
max\_width = 40
spacer = " " \* max\_width
scroll\_line = spacer + scroll\_text + spacer
scroll\_pos = 0

```
with Live(console=console, refresh_per_second=4):
    for _ in range(20):
        for frame in frames:
            scroll_output = scroll_line[scroll_pos:scroll_pos + max_width]
            output = frame + "\n" + f"[bold magenta]{scroll_output}[/bold magenta]"
            console.clear()
            console.print(output)
            time.sleep(0.3)
            scroll_pos = (scroll_pos + 1) % len(scroll_line)
```

def main\_loop():
try:
console.print("\[bold yellow]✨ Loading MONAD Faucet Auto Claim by angga 404...\n")
animate\_banner()

```
    while True:
        all_accounts = load_accounts_from_json()
        proxies = load_proxies()
        if not all_accounts or not proxies:
            console.print("[bold red]❌ Tidak ada akun atau proxy.")
            break

        batch_num = 1
        total = len(all_accounts)
        console.print(Panel(f"🚀 Menjalankan total [bold]{total}[/bold] akun dalam batch {ACCOUNTS_PER_BATCH}-thread", title="Faucet Bot", box=box.DOUBLE))

        for i in range(0, total, ACCOUNTS_PER_BATCH):
            batch = all_accounts[i:i + ACCOUNTS_PER_BATCH]
            console.print(Panel(f"📦 Batch {batch_num}: {len(batch)} akun", style="bold green"))
            threads = []

            for acc in batch:
                t = threading.Thread(target=run_account, args=(acc, proxies))
                t.start()
                threads.append(t)
                time.sleep(0.5)

            for t in threads:
                t.join()
            batch_num += 1

        console.print("[bold green]\n✅ Semua akun selesai diproses.")
        console.print("[yellow]⏳ Menunggu 6 jam sebelum siklus berikutnya...\n")
        time.sleep(6 * 60 * 60)

except KeyboardInterrupt:
    console.print("[bold red]\n🛑 Dihentikan oleh pengguna (Ctrl+C)")
```

if **name** == "**main**":
main\_loop()
