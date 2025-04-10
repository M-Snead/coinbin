#!/usr/bin/env python3
import binascii
import ecdsa
from ecdsa.util import sigencode_der, sigdecode_der

def canonicalize_signature(der_sig_hex):
    """
    Given a DER-encoded signature in hex (with the sighash flag appended),
    decode it, enforce the low-S rule and minimal encoding, 
    and return the canonical signature (with the sighash flag appended) as bytes.
    
    If the signature is invalid, returns None.
    """
    try:
        # Convert provided hex string to bytes.
        sig_bytes = bytes.fromhex(der_sig_hex)
    except ValueError as e:
        print("Invalid hex input:", e)
        return None

    # The signature must include at least one byte for DER data and one for the sighash.
    if len(sig_bytes) < 2:
        print("Provided signature is too short.")
        return None

    # The last byte is assumed to be the sighash flag (commonly 0x01 for SIGHASH_ALL)
    sighash = sig_bytes[-1:]
    der_bytes = sig_bytes[:-1]

    # Check that it starts with 0x30 (the DER sequence tag).
    if der_bytes[0] != 0x30:
        print("Signature does not start with DER sequence identifier (0x30).")
        return None

    # Get the generator order for SECP256k1.
    order = ecdsa.SECP256k1.generator.order()
    try:
        # Decode the DER signature into (r, s) integer components.
        r, s = sigdecode_der(der_bytes, order)
    except Exception as e:
        print("Error decoding DER signature:", e)
        return None

    # Enforce low-S (BIP 62): if s > order/2, replace s with (order - s).
    if s > order // 2:
        s = order - s

    # Re-encode the signature in DER (produces a minimal encoding).
    canonical_der = sigencode_der(r, s, order)
    # Append the sighash flag back.
    return canonical_der + sighash

def main():
    print("Enter your DER signature in hex (with sighash flag appended):")
    provided_sig_hex = input().strip()

    canonical_sig = canonicalize_signature(provided_sig_hex)
    if canonical_sig is None:
        print("Canonicalization of signature failed.")
    else:
        print("Canonical signature hex:", canonical_sig.hex())

if __name__ == '__main__':
    main()
