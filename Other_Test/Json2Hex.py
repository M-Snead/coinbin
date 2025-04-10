#!/usr/bin/env python3
import binascii
import json
import ecdsa
import hashlib

from bitcoin import SelectParams
from bitcoin.core import (
    lx, x, b2x, COutPoint, CTxIn, CTxOut, CTransaction, CScript
)
from ecdsa.util import sigencode_der, sigdecode_der

# Select the network parameters ('mainnet' or 'testnet')
SelectParams('mainnet')

def canonicalize_signature(der_sig_hex):
    """
    Given a DER-encoded signature (with the sighash flag appended),
    decode it, enforce low-S and minimal encoding, and re-encode it canonically.
    
    Returns the canonical signature (with the sighash flag appended).
    """
    # Convert provided hex to bytes
    sig_bytes = bytes.fromhex(der_sig_hex)
    # The last byte is assumed to be the sighash flag (e.g. 0x01 for SIGHASH_ALL)
    sighash = sig_bytes[-1:]
    der_bytes = sig_bytes[:-1]
    
    # Get the generator order for SECP256k1
    order = ecdsa.SECP256k1.generator.order()
    
    try:
        # Decode the DER signature into (r, s) components.
        r, s = sigdecode_der(der_bytes, order)
    except Exception as e:
        print("Error decoding DER signature:", e)
        return None

    # Enforce low-S (BIP 62): if s > order/2, use order - s.
    if s > order // 2:
        s = order - s

    # Re-encode the signature in DER (this produces a minimal encoding)
    canonical_der = sigencode_der(r, s, order)
    # Append the sighash flag again
    return canonical_der + sighash

def push_data(data_hex):
    """
    Returns a hex string that represents the push operation for the given hex data.
    For data shorter than 76 bytes, the push opcode is just the length as one byte.
    """
    data_bytes = bytes.fromhex(data_hex)
    n = len(data_bytes)
    
    if n < 0x4c:
        return "{:02x}".format(n) + data_hex
    elif n <= 0xff:
        return "4c" + "{:02x}".format(n) + data_hex
    elif n <= 0xffff:
        return "4d" + "{:04x}".format(n) + data_hex
    else:
        return "4e" + "{:08x}".format(n) + data_hex

# ======================================================
# Replace these placeholders with your actual values.
#
# Your provided (non-canonical) DER signature with sighash flag appended.
# (This is the raw output from your signing routine; it might be non-canonical.)
provided_sig_hex = (
    "3045022100a1b2c3d4e5f67890abcdef01234567890abcdef01234567890"
    "abcdef01234502201a2b3c4d5e6f7890abcdef01234567890abcdef012345"
    "67890abcdef01234501"
)

# Canonicalize the signature.
canonical_sig = canonicalize_signature(provided_sig_hex)
if canonical_sig is None:
    raise Exception("Canonicalization of signature failed.")

canonical_sig_hex = canonical_sig.hex()
print("Canonical DER signature with sighash:", canonical_sig_hex)

# Your public key in hex (uncompressed: 65 bytes or compressed: 33 bytes)
public_key_hex = (
    "041b2c906b7c481f4ab3d8189d911041157ff93543bd89c2267796c16b953d7e"
    "cdd925d69974e471dee85a663811cd669417195a63d1550b77f3b37f465b3b6882"
)

# ======================================================
# Rebuild the unlocking script (scriptSig).
# The unlocking script is constructed by "pushing" the signature and the public key.
scriptSig_hex = push_data(canonical_sig_hex) + push_data(public_key_hex)
print("Rebuilt scriptSig:", scriptSig_hex)

# ---------------------------------------------------------------------
# Build the transaction input.
#
# Your previous transaction reference data.
prev_txid_str = "39a7cf8a69891b86fabdc779b1e21d7c97522efd2954d7f26632dc0d4ff767df"
vout = 0
prev_txid = lx(prev_txid_str)
outpoint = COutPoint(prev_txid, vout)

# Create the transaction input using the updated scriptSig.
txin = CTxIn(outpoint, CScript(x(scriptSig_hex)), nSequence=4294967293)

# ---------------------------------------------------------------------
# Build the transaction outputs.
#
# Output 0: 33,900,000,000 satoshis to a P2WPKH address.
value0 = 33900000000
scriptPubKey0_hex = "0014f5689400671c266948f407e484c0c54c663979ab"
txout0 = CTxOut(value0, CScript(x(scriptPubKey0_hex)))

# Output 1: 99,999,644 satoshis to another P2WPKH address.
value1 = 99999644
scriptPubKey1_hex = "001412ccc1e401ac8c4f2d93898d704d91626dbde916"
txout1 = CTxOut(value1, CScript(x(scriptPubKey1_hex)))

# ---------------------------------------------------------------------
# Create the transaction.
#
version = 2
locktime = 884536
tx = CTransaction([txin], [txout0, txout1], nLockTime=locktime, nVersion=version)

# Serialize the transaction.
raw_tx_bytes = tx.serialize()
raw_tx_hex = b2x(raw_tx_bytes)
print("\nRaw Transaction Hex for Broadcast:")
print(raw_tx_hex)

# ---------------------------------------------------------------------
# (OPTIONAL) For review, here is a JSON representation of the transaction.
tx_json = {
    "version": tx.nVersion,
    "locktime": tx.nLockTime,
    "ins": [
        {
            "txid": prev_txid_str,
            "vout": vout,
            "scriptSig": {
                "asm": f"{canonical_sig_hex} {public_key_hex}",
                "hex": scriptSig_hex,
            },
            "sequence": txin.nSequence,
            "witness": []
        }
    ],
    "outs": [
        {
            "value": value0,
            "scriptPubKey": {
                "hex": scriptPubKey0_hex,
                "addresses": ["bc1q745fgqr8rsnxjj85qljgfsx9f3nrj7dt6whruc"]
            }
        },
        {
            "value": value1,
            "scriptPubKey": {
                "hex": scriptPubKey1_hex,
                "addresses": ["bc1qztxvreqp4jxy7tvn3xxhqnv3vfkmm6gk83e8c6"]
            }
        }
    ]
}

print("\nTransaction JSON (for review):")
print(json.dumps(tx_json, indent=4))
