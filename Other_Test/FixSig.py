
import hashlib
import ecdsa
from ecdsa.util import sigencode_der, sigdecode_der

# Replace these variables with your actual private key and transaction hex.
private_key_hex = 'fe26dcb1b995d6168aedf3e64a21310c5f51d0572bff16725ad076deccc008a0'
tx_hex = '0200000001df67f74f0ddc3266f2d75429fd2e52977c1de2b179c7bdfa861b89698acfa7390000000000fdffffff0200f398e407000000160014f5689400671c266948f407e484c0c54c663979ab9cdff5050000000016001412ccc1e401ac8c4f2d93898d704d91626dbde916387f0d00'

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
