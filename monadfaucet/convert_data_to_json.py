import csv
import json

# === 1. Baca data dari CSV ===
csv_data = []
with open("data.csv", newline="", encoding="utf-8") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        csv_data.append({
            "private_key": row["private_key"],
            "wallet_address": row["wallet_address"],
            "fid": int(row["fid"]),
            "username": row["username"]
        })

# === 2. Baca data dari JSON lama ===
with open("data.json", "r", encoding="utf-8") as f:
    json_data = json.load(f)

# === 3. Gabungkan dan hapus duplikat berdasarkan wallet_address ===
combined = json_data + csv_data
unique_data = {}
for entry in combined:
    unique_data[entry["wallet_address"]] = entry  # otomatis hapus duplikat

# === 4. Urutkan berdasarkan fid ===
sorted_data = sorted(unique_data.values(), key=lambda x: x["fid"])

# === 5. Simpan ke file baru ===
with open("data.json", "w", encoding="utf-8") as f:
    json.dump(sorted_data, f, indent=4)

print("✅ File 'data_merged.json' berhasil dibuat dan disortir.")
