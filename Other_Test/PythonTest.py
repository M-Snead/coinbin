#This will: 
# 1. Take a WIF private key and a transaction hash as input, and generate a BIP66 DER signature.
# 2. Check the validity of the WIF key and transaction hash, and handle errors gracefully.
# 3. Print the signature in hex format and the length of the signature.
# #!/usr/bin/env python3
"""
Bitcoin Transaction Signature Generator (BIP66 DER format)
This script generates a signature in BIP66 DER format from a WIF private key and a transaction hash.
"""

import hashlib
import base58
import ecdsa
import binascii
import sys

def decode_wif(wif_key):
    """Decode a WIF private key to get the raw private key bytes."""
    try:
        # Decode Base58 WIF to bytes
        decoded = base58.b58decode(wif_key)
        
        # Check basic structure (version byte + private key + [compressed flag] + checksum)
        if len(decoded) not in (37, 38):
            raise ValueError(f"Invalid WIF length: {len(decoded)}")
        
        # Extract the checksum (last 4 bytes)
        checksum = decoded[-4:]
        
        # Verify the checksum
        data_to_check = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(data_to_check).digest()).digest()[:4]
        
        if checksum != calculated_checksum:
            raise ValueError("Invalid WIF checksum")
        
        # Extract the private key (skip version byte and ignore potential compressed flag)
        private_key = decoded[1:33]
        
        # Check if the key is for compressed public keys
        compressed = False
        if len(decoded) == 38:
            compressed = True
        
        return private_key, compressed
    except Exception as e:
        raise ValueError(f"WIF key decoding error: {str(e)}")

def sign_transaction(private_key_bytes, tx_hash_hex):
    """Sign a transaction hash with a private key and return the signature."""
    try:
        # Convert transaction hash hex to bytes
        tx_hash_bytes = bytes.fromhex(tx_hash_hex)
        
        # Create signing key from private key bytes
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        
        # Sign the transaction hash
        signature = sk.sign_digest(tx_hash_bytes, sigencode=ecdsa.util.sigencode_der)
        
        return signature
    except Exception as e:
        raise ValueError(f"Signing error: {str(e)}")

def format_signature_with_sighash(signature, hash_type=1):
    """Format the DER signature with the specified SIGHASH byte."""
    # Convert signature to hex
    sig_hex = binascii.hexlify(signature).decode('ascii')
    
    # Append the hash type byte
    return sig_hex + format(hash_type, '02x')

def main():
    print("Bitcoin Transaction Signature Generator (BIP66 DER format)")
    print("-------------------------------------------------------")
    
    # Get inputs
    wif_key = input("Enter WIF private key: ").strip()
    tx_hash = input("Enter transaction hash (64-character hex): ").strip()
    
    # Validate inputs
    if not wif_key:
        print("Error: WIF key cannot be empty")
        return
    
    if not tx_hash or len(tx_hash) != 64 or not all(c in '0123456789abcdefABCDEF' for c in tx_hash):
        print("Error: Transaction hash must be a 64-character hex string")
        return
    
    try:
        # Decode the WIF key
        private_key_bytes, compressed = decode_wif(wif_key)
        print(f"\nPrivate key successfully decoded (Compressed: {compressed})")
        
        # Sign the transaction
        signature = sign_transaction(private_key_bytes, tx_hash)
        
        # Format with SIGHASH_ALL
        formatted_sig = format_signature_with_sighash(signature)
        
        print("\nSignature generated successfully!")
        print("\nDER Signature with SIGHASH_ALL:")
        print(formatted_sig)
        
        print("\nSignature length: ", len(formatted_sig) // 2, "bytes")
        
    except ValueError as e:
        print(f"Error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)