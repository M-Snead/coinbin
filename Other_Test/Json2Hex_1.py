#!/usr/bin/env python3
import binascii
import json

from bitcoin import SelectParams
from bitcoin.core import (
    b2x,
    lx,
    x,
    COutPoint,
    CTxIn,
    CTxOut,
    CTransaction,
    CScript
)

# Select the network parameters (use 'testnet' if you’re testing)
SelectParams('mainnet')

def push_data(data_hex):
    """
    Returns a hex string representing the push instruction for a given hex-encoded data.
    For data lengths < 0x4c (76 bytes), the opcode is simply the length.
    """
    data_bytes = binascii.unhexlify(data_hex)
    n = len(data_bytes)
    
    if n < 0x4c:
        return "{:02x}".format(n) + data_hex
    elif n <= 0xff:
        # OP_PUSHDATA1: 0x4c followed by 1 byte length
        return "4c" + "{:02x}".format(n) + data_hex
    elif n <= 0xffff:
        # OP_PUSHDATA2: 0x4d followed by 2 bytes length
        return "4d" + "{:04x}".format(n) + data_hex
    else:
        # OP_PUSHDATA4 is rarely needed.
        return "4e" + "{:08x}".format(n) + data_hex

# ======================================================
# Replace these placeholders with your actual values.
# Your updated canonical DER signature with sighash flag appended.
new_signature_hex = (
    "xxxx"
    "xxxx"
    "67890abcdef01234501"
)
# Your public key in hex (uncompressed is 65 bytes; compressed is 33 bytes)
public_key_hex = (
    "xxxx"
    "xxxx"
)
# ======================================================

# Build the unlocking script (scriptSig) by adding the proper push opcodes.
scriptSig_hex = push_data(new_signature_hex) + push_data(public_key_hex)
print("Updated unlocking script (scriptSig) in hex:")
print(scriptSig_hex)

# ---------------------------------------------------------------------
# Build the transaction input.
#
prev_txid_str = "xxxx"
vout = 0

# Convert the previous txid into bytes (little-endian format)
prev_txid = lx(prev_txid_str)
# Create an outpoint object referencing the previous output
outpoint = COutPoint(prev_txid, vout)

# Create the transaction input (CTxIn) with the updated scriptSig.
txin = CTxIn(outpoint, CScript(x(scriptSig_hex)), nSequence=4294967293)

# ---------------------------------------------------------------------
# Build the transaction outputs.
#
# Output 0: spending 33,900,000,000 satoshis to a P2WPKH address.
value0 = 33900000000
scriptPubKey0_hex = "xxxx"
txout0 = CTxOut(value0, CScript(x(scriptPubKey0_hex)))

# Output 1: spending 99,999,644 satoshis to another P2WPKH address.
value1 = 99999644
scriptPubKey1_hex = "xxxx"
txout1 = CTxOut(value1, CScript(x(scriptPubKey1_hex)))

# ---------------------------------------------------------------------
# Define transaction version and locktime.
version = 2
locktime = 884536

# Create the transaction by passing version and locktime to the constructor.
tx = CTransaction([txin], [txout0, txout1], nLockTime=locktime, nVersion=version)

# ---------------------------------------------------------------------
# Serialize the transaction.
raw_tx_bytes = tx.serialize()
raw_tx_hex = b2x(raw_tx_bytes)  # convert binary transaction to hex string

print("\nRaw Transaction Hex for Broadcast:")
print(raw_tx_hex)

# ---------------------------------------------------------------------
# (OPTIONAL) Create a JSON representation to review the updated fields.
tx_json = {
    "version": tx.nVersion,
    "locktime": tx.nLockTime,
    "ins": [
        {
            "txid": prev_txid_str,
            "vout": vout,
            "scriptSig": {"hex": scriptSig_hex},
            "sequence": txin.nSequence,
            "witness": []  # no witness data in a legacy input
        }
    ],
    "outs": [
        {
            "value": value0,
            "scriptPubKey": {
                "hex": scriptPubKey0_hex,
                "addresses": ["xxxx"]
            }
        },
        {
            "value": value1,
            "scriptPubKey": {
                "hex": scriptPubKey1_hex,
                "addresses": ["xxxx"]
            }
        }
    ]
}

print("\nTransaction JSON (for review):")
print(json.dumps(tx_json, indent=4))
