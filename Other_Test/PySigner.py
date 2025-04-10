#!/usr/bin/env python3
"""
Bitcoin Transaction Signer
This script generates a valid signature for a Bitcoin transaction and prepares it for submission to the network.
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

def sign_transaction(private_key_bytes, tx_hash_hex, compressed=True):
    """Sign a transaction hash with a private key and return the signature."""
    try:
        # Convert transaction hash hex to bytes
        tx_hash_bytes = bytes.fromhex(tx_hash_hex)
        
        # Create signing key from private key bytes
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        
        # Sign the transaction hash
        signature = sk.sign_digest(tx_hash_bytes, sigencode=ecdsa.util.sigencode_der)
        
        # Low S value enforcement for BIP-62/66 compliance
        signature = enforce_low_s(signature)
        
        # Get the corresponding public key (compressed or uncompressed)
        vk = sk.get_verifying_key()
        if compressed:
            pub_key = get_compressed_pubkey(vk)
        else:
            pub_key = get_uncompressed_pubkey(vk)
        
        return signature, pub_key
    except Exception as e:
        raise ValueError(f"Signing error: {str(e)}")

def enforce_low_s(der_sig):
    """
    Enforce low S values in signatures (BIP-62/66 compliance)
    """
    # Parse DER signature to extract r and s values
    r, s = ecdsa.util.sigdecode_der(der_sig, ecdsa.SECP256k1.order)
    
    # Check if s is greater than half the curve order
    # If so, compute s' = curve_order - s
    half_order = ecdsa.SECP256k1.order // 2
    if s > half_order:
        s = ecdsa.SECP256k1.order - s
    
    # Re-encode with the possibly modified s value
    return ecdsa.util.sigencode_der(r, s, ecdsa.SECP256k1.order)

def get_compressed_pubkey(verifying_key):
    """Get the compressed public key from a verifying key."""
    point_x = verifying_key.pubkey.point.x()
    point_y = verifying_key.pubkey.point.y()
    
    prefix = b'\x02' if point_y % 2 == 0 else b'\x03'
    return prefix + point_x.to_bytes(32, 'big')

def get_uncompressed_pubkey(verifying_key):
    """Get the uncompressed public key from a verifying key."""
    point_x = verifying_key.pubkey.point.x()
    point_y = verifying_key.pubkey.point.y()
    
    return b'\x04' + point_x.to_bytes(32, 'big') + point_y.to_bytes(32, 'big')

def format_signature_with_sighash(signature, hash_type=1):
    """Format the DER signature with the specified SIGHASH byte."""
    # Convert signature to hex
    sig_hex = binascii.hexlify(signature).decode('ascii')
    
    # Append the hash type byte
    return sig_hex + format(hash_type, '02x')

def create_scriptsig(signature, pubkey, hash_type=1):
    """
    Create a complete scriptSig for P2PKH inputs
    Structure: <sig_length> <signature+hashtype> <pubkey_length> <pubkey>
    """
    # Add hash type to signature
    sig_with_hashtype = signature + bytes([hash_type])
    
    # Create length bytes
    sig_length = len(sig_with_hashtype)
    pubkey_length = len(pubkey)
    
    # Combine everything
    script = bytes([sig_length]) + sig_with_hashtype + bytes([pubkey_length]) + pubkey
    
    return script

def main():
    print("Bitcoin Transaction Signer")
    print("-------------------------")
    
    # Get inputs
    wif_key = input("Enter WIF private key: ").strip()
    tx_hash = input("Enter transaction hash (64-character hex): ").strip()
    
    # Optional: Ask if they want to use compressed public keys
    use_compressed = input("Use compressed public key format? (Y/n): ").strip().lower() != 'n'
    
    # Validate inputs
    if not wif_key:
        print("Error: WIF key cannot be empty")
        return
    
    if not tx_hash or len(tx_hash) != 64 or not all(c in '0123456789abcdefABCDEF' for c in tx_hash):
        print("Error: Transaction hash must be a 64-character hex string")
        return
    
    try:
        # Decode the WIF key
        private_key_bytes, key_is_compressed = decode_wif(wif_key)
        
        # Use the compression format from the WIF key unless explicitly specified
        compressed = key_is_compressed if use_compressed else use_compressed
        
        print(f"\nPrivate key successfully decoded (Key indicates {'compressed' if key_is_compressed else 'uncompressed'} format)")
        print(f"Using {'compressed' if compressed else 'uncompressed'} public key format for signature")
        
        # Sign the transaction
        signature, pubkey = sign_transaction(private_key_bytes, tx_hash, compressed)
        
        # Format with SIGHASH_ALL for straight hex output
        formatted_sig_hex = format_signature_with_sighash(signature)
        
        # Create complete scriptSig
        script_sig = create_scriptsig(signature, pubkey)
        script_sig_hex = binascii.hexlify(script_sig).decode('ascii')
        
        print("\nSignature generated successfully!")
        
        print("\nDER Signature with SIGHASH_ALL (hex):")
        print(formatted_sig_hex)
        
        print("\nPublic Key (hex):")
        print(binascii.hexlify(pubkey).decode('ascii'))
        
        print("\nComplete scriptSig (for P2PKH transaction, hex):")
        print(script_sig_hex)
        
        print("\nScriptSig length:", len(script_sig), "bytes")
        
        print("\n--- Verification Information ---")
        print("The DER signature format follows strict BIP-66 compliance.")
        print("Low S values are enforced per BIP-62 for transaction malleability protection.")
        print("For transaction submission, use the Complete scriptSig in your raw transaction.")
        
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