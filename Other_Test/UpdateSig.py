import binascii
import json

def push_data(data_hex):
    """
    Returns a hex string representing the push operation for the given data.
    For small data (< 0x4c bytes), the opcode is simply the length in one byte.
    """
    data_bytes = binascii.unhexlify(data_hex)
    n = len(data_bytes)
    
    if n < 0x4c:
        # For data lengths less than 76 bytes, push opcode is just the length as one byte.
        return "{:02x}".format(n) + data_hex
    elif n <= 0xff:
        # OP_PUSHDATA1 followed by 1 byte of length.
        return "4c" + "{:02x}".format(n) + data_hex
    elif n <= 0xffff:
        # OP_PUSHDATA2 followed by 2 bytes of length.
        return "4d" + "{:04x}".format(n) + data_hex
    else:
        # OP_PUSHDATA4 is rarely needed for typical signatures/pubkeys.
        return "4e" + "{:08x}".format(n) + data_hex

# === Replace these with your actual values ===
# Your new canonical DER signature + sighash flag (in hex)
new_signature_hex = "xxxx"

# Your public key in hex (uncompressed is 65 bytes; compressed is 33 bytes)
public_key_hex = "xxxx"

# =================================================

# Rebuild the unlocking script for input: push signature then push public key.
new_scriptSig = push_data(new_signature_hex) + push_data(public_key_hex)
print("Updated unlocking script (scriptSig) in hex:")
print(new_scriptSig)

# --- Now, update the transaction JSON ---
# Here’s the original transaction data (adapted from your JSON; note that we rename some fields)
tx = {
    "version": 2,
    "locktime": 884536,
    "ins": [
        {
            "txid": "xxxx",
            "vout": 0,
            # Our updated scriptSig goes here.
            "scriptSig": {"hex": new_scriptSig},
            "sequence": 4294967293,
            "witness": []
        }
    ],
    "outs": [
        {
            "value": 33900000000,
            "scriptPubKey": {
                "hex": "0014f5689400671c266948f407e484c0c54c663979ab",
                "addresses": "xxxx"],
                "asm": "OP_0 f5689400671c266948f407e484c0c54c663979ab"
            }
        },
        {
            "value": 99999644,
            "scriptPubKey": {
                "hex": "xxxx",
                "addresses": ["xxxx"],
                "asm": "OP_0 12ccc1e401ac8c4f2d93898d704d91626dbde916"
            }
        }
    ]
}

print("\nUpdated full transaction JSON:")
print(json.dumps(tx, indent=4))
