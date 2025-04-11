import hashlib

tx_hex = "xxxx"  # your transaction in hex
tx_bytes = bytes.fromhex(tx_hex)
# Use double-SHA256 (standard in Bitcoin for signing)
digest = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()

print("Digest length:", len(digest))  # Should output 32
