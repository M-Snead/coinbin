#!/usr/bin/env python3
"""
Bitcoin Transaction Validator and Fixer
This script validates a raw Bitcoin transaction hex and checks for non-canonical DER signatures.
"""

import hashlib
import binascii
import sys
import re
import struct

class TransactionValidator:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []
    
    def validate_transaction(self, tx_hex):
        """Validate a raw transaction hex."""
        try:
            # Convert hex to bytes
            tx_bytes = bytes.fromhex(tx_hex)
            
            # Parse the transaction
            tx_data = self.parse_tx(tx_bytes)
            
            return tx_data
            
        except Exception as e:
            self.errors.append(f"Fatal parsing error: {str(e)}")
            return None
    
    def parse_tx(self, tx_bytes):
        """Parse a raw transaction and return its components."""
        try:
            # Parse transaction version (4 bytes)
            if len(tx_bytes) < 4:
                self.errors.append("Transaction too short (less than 4 bytes)")
                return None
            
            version = struct.unpack("<I", tx_bytes[:4])[0]
            self.info.append(f"Transaction version: {version}")
            
            # Check for segwit marker and flag
            pos = 4
            is_segwit = False
            
            if pos < len(tx_bytes) and tx_bytes[pos] == 0 and tx_bytes[pos + 1] != 0:
                is_segwit = True
                pos += 2  # Skip marker and flag
                self.info.append("SegWit transaction detected")
            
            # Parse input count (varint)
            if pos >= len(tx_bytes):
                self.errors.append("Transaction truncated before input count")
                return None
                
            input_count, varint_size = self.parse_varint(tx_bytes[pos:])
            pos += varint_size
            
            self.info.append(f"Input count: {input_count}")
            
            # Parse inputs
            inputs = []
            for i in range(input_count):
                if pos + 36 >= len(tx_bytes):
                    self.errors.append(f"Transaction truncated in input {i}")
                    return None
                
                # Previous output hash (32 bytes) and index (4 bytes)
                prev_hash = tx_bytes[pos:pos+32]
                pos += 32
                prev_index = struct.unpack("<I", tx_bytes[pos:pos+4])[0]
                pos += 4
                
                # Script length
                script_length, varint_size = self.parse_varint(tx_bytes[pos:])
                pos += varint_size
                
                if pos + script_length > len(tx_bytes):
                    self.errors.append(f"Transaction truncated in input {i} script")
                    return None
                
                # Script
                script = tx_bytes[pos:pos+script_length]
                pos += script_length
                
                # Sequence
                if pos + 4 > len(tx_bytes):
                    self.errors.append(f"Transaction truncated in input {i} sequence")
                    return None
                    
                sequence = struct.unpack("<I", tx_bytes[pos:pos+4])[0]
                pos += 4
                
                input_data = {
                    'prev_hash': binascii.hexlify(prev_hash[::-1]).decode('ascii'),  # Reverse for display
                    'prev_index': prev_index,
                    'script': script,
                    'script_hex': binascii.hexlify(script).decode('ascii'),
                    'sequence': sequence
                }
                
                # Validate signatures in this input
                self.validate_script_signatures(script, i)
                
                inputs.append(input_data)
            
            # Parse outputs (truncated for brevity as we focus on inputs/signatures)
            # In a complete implementation, we would continue parsing outputs, witness data for segwit, and locktime
            
            return {
                'version': version,
                'is_segwit': is_segwit,
                'inputs': inputs,
                # We would add outputs, witnesses, and locktime here in a complete implementation
            }
            
        except Exception as e:
            self.errors.append(f"Transaction parsing error: {str(e)}")
            return None
    
    def validate_script_signatures(self, script, input_index):
        """Validate DER signatures in a script."""
        try:
            # Skip if script is empty
            if not script:
                return
                
            # Find DER signatures in the script
            # Signatures typically start with a length byte, followed by a DER sequence
            pos = 0
            while pos < len(script):
                # Look for potential signature (length byte followed by 0x30)
                if pos + 2 < len(script) and script[pos+1] == 0x30:
                    sig_len = script[pos]
                    
                    # Check if we have enough bytes
                    if pos + 1 + sig_len <= len(script):
                        # Extract potential signature
                        potential_sig = script[pos+1:pos+1+sig_len]
                        
                        # Validate DER format
                        sig_errors = self.validate_der_signature(potential_sig)
                        
                        if sig_errors:
                            self.errors.append(f"Input {input_index} contains non-canonical DER signature:")
                            for err in sig_errors:
                                self.errors.append(f"  - {err}")
                            
                            # Attempt to show how to fix it
                            self.suggest_fix(potential_sig)
                        else:
                            self.info.append(f"Input {input_index} contains a valid DER signature")
                    
                    # Move past this signature
                    pos += 1 + sig_len
                else:
                    # Move to next byte
                    pos += 1
                    
        except Exception as e:
            self.errors.append(f"Error validating signatures in input {input_index}: {str(e)}")
    
    def validate_der_signature(self, sig_bytes):
        """Validate that a signature follows the canonical DER format per BIP-66."""
        errors = []
        
        # Must start with 0x30 (compound sequence)
        if not sig_bytes or sig_bytes[0] != 0x30:
            errors.append("Signature does not start with 0x30 (DER sequence marker)")
            return errors
        
        # Check length - minimum 8 bytes (for empty r and s values plus headers)
        if len(sig_bytes) < 8:
            errors.append("Signature too short (min 8 bytes for DER)")
            return errors
        
        # Get overall length from second byte
        der_len = sig_bytes[1]
        
        # Length must match
        if len(sig_bytes) - 2 != der_len:
            errors.append(f"DER length byte ({der_len}) does not match actual signature length ({len(sig_bytes) - 2})")
        
        # Check for integer marker for r value
        if len(sig_bytes) < 3 or sig_bytes[2] != 0x02:
            errors.append("Missing integer marker for r value")
            return errors
        
        # Get r length
        if len(sig_bytes) < 4:
            errors.append("Signature too short to contain r length")
            return errors
            
        r_len = sig_bytes[3]
        
        # Make sure r length is valid
        if r_len == 0 or r_len > 33:
            errors.append(f"Invalid r length: {r_len}")
        
        if len(sig_bytes) < 4 + r_len:
            errors.append("Signature too short to contain full r value")
            return errors
        
        # Extract r value
        r_pos = 4
        r_value = sig_bytes[r_pos:r_pos + r_len]
        
        # Check r value for canonical form
        if len(r_value) > 1 and r_value[0] == 0x00 and not (r_value[1] & 0x80):
            errors.append("Non-canonical r value: unnecessary leading zero")
        
        # Check for integer marker for s value
        s_pos = r_pos + r_len
        if len(sig_bytes) <= s_pos or sig_bytes[s_pos] != 0x02:
            errors.append("Missing integer marker for s value")
            return errors
        
        # Get s length
        if len(sig_bytes) < s_pos + 2:
            errors.append("Signature too short to contain s length")
            return errors
            
        s_len = sig_bytes[s_pos + 1]
        
        # Make sure s length is valid
        if s_len == 0 or s_len > 33:
            errors.append(f"Invalid s length: {s_len}")
        
        if len(sig_bytes) < s_pos + 2 + s_len:
            errors.append("Signature too short to contain full s value")
            return errors
        
        # Extract s value
        s_value = sig_bytes[s_pos + 2:s_pos + 2 + s_len]
        
        # Check s value for canonical form
        if len(s_value) > 1 and s_value[0] == 0x00 and not (s_value[1] & 0x80):
            errors.append("Non-canonical s value: unnecessary leading zero")
        
        # Ensure there are no extra bytes
        if s_pos + 2 + s_len != len(sig_bytes):
            errors.append("Extra bytes at end of signature")
        
        # Check for low S value (BIP-62)
        # In a real implementation, we would check if s > N/2 where N is the curve order
        # But here we'll just note that this should be verified
        self.warnings.append("Note: Low S value requirement not checked (requires secp256k1 parameters)")
        
        return errors
        
    def suggest_fix(self, sig_bytes):
        """Attempt to suggest how to fix a non-canonical signature."""
        try:
            if not sig_bytes or sig_bytes[0] != 0x30:
                return
                
            # TODO: Implement specific fixes based on common issues
            self.info.append("Signature fix suggestions:")
            self.info.append("  - Ensure you're using a Bitcoin library that enforces BIP-66 canonical signatures")
            self.info.append("  - If using a custom signing function, make sure to enforce low S values")
            self.info.append("  - Verify that signature encoding correctly includes the hashtype byte (but not as part of DER)")
            
        except Exception:
            pass
    
    def parse_varint(self, data):
        """Parse a variable int and return (value, bytes_read)."""
        if not data:
            raise ValueError("Empty data for varint")
            
        first_byte = data[0]
        
        if first_byte < 0xfd:
            return first_byte, 1
        elif first_byte == 0xfd:
            if len(data) < 3:
                raise ValueError("Truncated varint (0xfd prefix)")
            return struct.unpack("<H", data[1:3])[0], 3
        elif first_byte == 0xfe:
            if len(data) < 5:
                raise ValueError("Truncated varint (0xfe prefix)")
            return struct.unpack("<I", data[1:5])[0], 5
        elif first_byte == 0xff:
            if len(data) < 9:
                raise ValueError("Truncated varint (0xff prefix)")
            return struct.unpack("<Q", data[1:9])[0], 9
        else:
            raise ValueError(f"Invalid varint prefix: {first_byte}")

def extract_normalized_signatures(tx_hex):
    """
    Extract and attempt to normalize signatures from a transaction.
    This function identifies DER signatures and shows them in both hex and normalized form.
    """
    # Simple regex to find potential DER signatures
    # This isn't perfect but helps identify signatures for inspection
    sig_pattern = r'30[0-9a-fA-F]{2}02[0-9a-fA-F]{2}[0-9a-fA-F]+02[0-9a-fA-F]{2}[0-9a-fA-F]+'
    
    signatures = re.findall(sig_pattern, tx_hex)
    
    if not signatures:
        return ["No DER signatures found in transaction"]
    
    results = ["Found potential DER signatures:"]
    
    for i, sig_hex in enumerate(signatures):
        results.append(f"Signature {i+1}: {sig_hex}")
        
        try:
            # Convert to bytes
            sig_bytes = bytes.fromhex(sig_hex)
            
            # Basic validation
            if sig_bytes[0] != 0x30:
                results.append("  Not a valid DER sequence (doesn't start with 0x30)")
                continue
                
            # Extract length, r and s values
            der_len = sig_bytes[1]
            
            r_len = sig_bytes[3]
            r_value = sig_bytes[4:4+r_len]
            r_hex = binascii.hexlify(r_value).decode('ascii')
            
            s_pos = 4 + r_len
            s_len = sig_bytes[s_pos+1]
            s_value = sig_bytes[s_pos+2:s_pos+2+s_len]
            s_hex = binascii.hexlify(s_value).decode('ascii')
            
            results.append(f"  Length: {der_len}")
            results.append(f"  R value ({r_len} bytes): {r_hex}")
            results.append(f"  S value ({s_len} bytes): {s_hex}")
            
            # Check for common issues
            if len(r_value) > 1 and r_value[0] == 0x00 and not (r_value[1] & 0x80):
                results.append("  ISSUE: R value has unnecessary leading zero")
            
            if len(s_value) > 1 and s_value[0] == 0x00 and not (s_value[1] & 0x80):
                results.append("  ISSUE: S value has unnecessary leading zero")
            
            # For a really complete solution, we'd check if s > N/2 and normalize it
            
        except Exception as e:
            results.append(f"  Error analyzing signature: {str(e)}")
    
    return results

def fix_transaction(tx_hex):
    """
    Attempt to fix common issues with transactions.
    This is a placeholder - in practice, re-signing with a proper library is better.
    """
    # This would be a very complex function to implement correctly
    # The best approach is usually to re-sign the transaction using a library
    # that correctly implements BIP-66 canonical signatures
    
    return ["Transaction repair functionality is not implemented.",
            "The recommended approach is to re-sign the transaction using a proper Bitcoin library.",
            "Libraries like bitcoinjs-lib, libbitcoin, or bitcoin-core will enforce canonical signatures."]

def main():
    print("Bitcoin Transaction Validator")
    print("----------------------------")
    
    # Get input
    tx_hex = input("Enter raw transaction hex: ").strip()
    
    # Basic validation
    if not tx_hex:
        print("Error: Transaction hex cannot be empty")
        return
    
    if not all(c in '0123456789abcdefABCDEF' for c in tx_hex):
        print("Error: Transaction must be a hex string")
        return
    
    print("\nValidating transaction...")
    validator = TransactionValidator()
    tx_data = validator.validate_transaction(tx_hex)
    
    # Display errors and warnings
    if validator.errors:
        print("\n❌ ERRORS:")
        for error in validator.errors:
            print(f"  - {error}")
    else:
        print("\n✅ No structural errors found in transaction format")
    
    if validator.warnings:
        print("\n⚠️ WARNINGS:")
        for warning in validator.warnings:
            print(f"  - {warning}")
    
    if validator.info:
        print("\nℹ️ INFO:")
        for info in validator.info:
            print(f"  - {info}")
    
    # Extract and analyze signatures
    print("\n🔍 SIGNATURE ANALYSIS:")
    sig_results = extract_normalized_signatures(tx_hex)
    for line in sig_results:
        print(f"  {line}")
    
    # Offer to fix transaction
    print("\n🔧 RECOMMENDATIONS:")
    print("  For 'Non-canonical DER signature' errors, you should:")
    print("  1. Use a standard Bitcoin library that enforces BIP-66 signature format")
    print("  2. Re-sign the transaction with the same private key")
    print("  3. Common issues include:")
    print("     - Unnecessary leading zeros in R or S values")
    print("     - S values greater than half the curve order (non-low-S form)")
    print("     - Incorrect length bytes in the DER structure")
    print("     - Incorrect format for the hashtype byte (should be appended after DER)")
    print("\n  Bitcoin Core and modern libraries like bitcoinjs-lib automatically")
    print("  enforce canonical signatures.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)