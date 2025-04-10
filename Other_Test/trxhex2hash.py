import hashlib

tx_hex = "0200000001df67f74f0ddc3266f2d75429fd2e52977c1de2b179c7bdfa861b89698acfa7390000000000fdffffff0200f398e407000000160014f5689400671c266948f407e484c0c54c663979ab9cdff5050000000016001412ccc1e401ac8c4f2d93898d704d91626dbde916387f0d00"  # your transaction in hex
tx_bytes = bytes.fromhex(tx_hex)
# Use double-SHA256 (standard in Bitcoin for signing)
digest = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()

print("Digest length:", len(digest))  # Should output 32
