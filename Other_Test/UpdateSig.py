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
new_signature_hex = "3045022100a1b2c3d4e5f67890abcdef01234567890abcdef01234567890abcdef01234502201a2b3c4d5e6f7890abcdef01234567890abcdef01234567890abcdef01234501"

# Your public key in hex (uncompressed is 65 bytes; compressed is 33 bytes)
public_key_hex = "041b2c906b7c481f4ab3d8189d911041157ff93543bd89c2267796c16b953d7ecdd925d69974e471dee85a663811cd669417195a63d1550b77f3b37f465b3b6882"

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
            "txid": "39a7cf8a69891b86fabdc779b1e21d7c97522efd2954d7f26632dc0d4ff767df",
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
                "addresses": ["bc1q745fgqr8rsnxjj85qljgfsx9f3nrj7dt6whruc"],
                "asm": "OP_0 f5689400671c266948f407e484c0c54c663979ab"
            }
        },
        {
            "value": 99999644,
            "scriptPubKey": {
                "hex": "001412ccc1e401ac8c4f2d93898d704d91626dbde916",
                "addresses": ["bc1qztxvreqp4jxy7tvn3xxhqnv3vfkmm6gk83e8c6"],
                "asm": "OP_0 12ccc1e401ac8c4f2d93898d704d91626dbde916"
            }
        }
    ]
}

print("\nUpdated full transaction JSON:")
print(json.dumps(tx, indent=4))
