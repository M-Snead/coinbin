
import hashlib
import ecdsa
from ecdsa.util import sigencode_der, sigdecode_der

# Replace these variables with your actual private key and transaction hex.
private_key_hex = 'xxxx'
tx_hex = 'xxxx'

# Convert private key (must be 32-byte for SECP256k1) and transaction hex
sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)

# Hash your transaction properly (using double-SHA256 for Bitcoin transactions)
tx_bytes = bytes.fromhex(tx_hex)
digest = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()

# Now, sign the digest using the canonical DER encoding.
signature_der = sk.sign_digest(digest, sigencode=sigencode_der)

# Optionally, enforce the low-S rule (BIP 62)
order = sk.curve.generator.order()
r, s = ecdsa.util.sigdecode_der(signature_der, order)
if s > order // 2:
    s = order - s
canonical_signature_der = ecdsa.util.sigencode_der(r, s, order)

# Append the sighash flag (commonly 0x01 for SIGHASH_ALL)
final_signature = canonical_signature_der + b'\x01'

print("Canonical DER Signature (hex):", final_signature.hex())
