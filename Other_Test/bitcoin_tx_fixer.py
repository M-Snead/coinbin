#!/usr/bin/env python3
"""
Bitcoin Transaction Signature Fixer
This script fixes non-canonical DER signatures in Bitcoin transactions.
"""

import binascii
import sys
import struct
import re

class TransactionFixer:
    def __init__(self):
        self.info = []
        self.warnings = []
        self.errors = []
    
    def fix_transaction(self, tx_hex):
        """Fix DER signature issues in a transaction."""
        try:
            # Convert hex to bytes
            tx_bytes = bytearray.fromhex(tx_hex)
            
            # Parse and fix the transaction
            fixed_tx = self.parse_and_fix_tx(tx_bytes)
            
            if fixed_tx:
                return binascii.hexlify(fixed_tx).decode('ascii')
            else:
                return None
                
        except Exception as e:
            self.errors.append(f"Fatal error: {str(e)}")
            return None
    
    def parse_and_fix_tx(self, tx_bytes):
        """Parse and fix a transaction's signatures."""
        try:
            # Create a copy we can modify
            fixed_tx = bytearray(tx_bytes)
            
            # Parse transaction version (4 bytes)
            if len(fixed_tx) < 4:
                self.errors.append("Transaction too short (less than 4 bytes)")
                return None
            
            version = struct.unpack("<I", fixed_tx[:4])[0]
            self.info.append(f"Transaction version: {version}")
            
            # Check for segwit marker and flag
            pos = 4
            is_segwit = False
            
            if pos < len(fixed_tx) and fixed_tx[pos] == 0 and fixed_tx[pos + 1] != 0:
                is_segwit = True
                pos += 2  # Skip marker and flag
                self.info.append("SegWit transaction detected")
            
            # Parse input count (varint)
            if pos >= len(fixed_tx):
                self.errors.append("Transaction truncated before input count")
                return None
                
            input_count, varint_size = self.parse_varint(fixed_tx[pos:])
            pos += varint_size
            
            self.info.append(f"Input count: {input_count}")
            
            # Parse and fix inputs
            for i in range(input_count):
                if pos + 36 >= len(fixed_tx):
                    self.errors.append(f"Transaction truncated in input {i}")
                    return None
                
                # Previous output hash (32 bytes) and index (4 bytes)
                pos += 36  # Skip these fields
                
                # Script length
                script_length, varint_size = self.parse_varint(fixed_tx[pos:])
                pos += varint_size
                
                if pos + script_length > len(fixed_tx):
                    self.errors.append(f"Transaction truncated in input {i} script")
                    return None
                
                # Script start position
                script_start = pos
                script_end = pos + script_length
                
                # Fix signatures in this script
                script_fixed = self.fix_signatures_in_script(fixed_tx[script_start:script_end], i)
                
                if script_fixed:
                    # Replace script in transaction
                    fixed_tx[script_start:script_end] = script_fixed
                    
                    # Script length might have changed
                    new_script_length = len(script_fixed)
                    if new_script_length != script_length:
                        # Update script length varint
                        length_pos = script_start - varint_size
                        length_bytes = self.create_varint(new_script_length)
                        fixed_tx[length_pos:script_start] = length_bytes
                        
                        # Adjust end position
                        script_end = script_start + new_script_length
                
                # Move to next input
                pos = script_end + 4  # Skip sequence (4 bytes)
            
            # We've fixed the inputs, now we need to keep the rest of the transaction intact
            # For brevity, we're not parsing outputs in detail
            
            return fixed_tx
            
        except Exception as e:
            self.errors.append(f"Error parsing transaction: {str(e)}")
            return None
    
    def fix_signatures_in_script(self, script, input_index):
        """Find and fix DER signatures in a script."""
        try:
            # Create a copy of the script
            fixed_script = bytearray(script)
            signatures_fixed = False
            
            # Scan for DER signatures
            pos = 0
            while pos < len(fixed_script):
                # Look for potential signature push
                if pos + 2 < len(fixed_script):
                    # Check for signature length byte followed by DER sequence marker (0x30)
                    if fixed_script[pos+1] == 0x30:
                        sig_push_len = fixed_script[pos]
                        
                        # Check if we have enough bytes
                        if pos + 1 + sig_push_len <= len(fixed_script):
                            # Extract potential signature
                            sig_start = pos + 1
                            sig_end = pos + 1 + sig_push_len
                            
                            potential_sig = fixed_script[sig_start:sig_end]
                            
                            # Try to fix this signature
                            fixed_sig = self.fix_der_signature(potential_sig, input_index)
                            
                            if fixed_sig is not None and fixed_sig != potential_sig:
                                # Replace the signature
                                fixed_script[sig_start:sig_end] = fixed_sig
                                signatures_fixed = True
                                
                                # Adjust position if length changed
                                length_diff = len(fixed_sig) - len(potential_sig)
                                if length_diff != 0:
                                    # Update sig push length
                                    fixed_script[pos] = len(fixed_sig)
                                    
                                    # We need to rebuild the script since its length changed
                                    return self.rebuild_script(fixed_script, pos, sig_start, sig_end, fixed_sig)
                    
                # Move to next byte
                pos += 1
            
            if signatures_fixed:
                self.info.append(f"Fixed signature(s) in input {input_index}")
                return fixed_script
            else:
                self.info.append(f"No signature issues found in input {input_index}")
                return None
                
        except Exception as e:
            self.errors.append(f"Error fixing signatures in input {input_index}: {str(e)}")
            return None
    
    def rebuild_script(self, script, pos, sig_start, sig_end, fixed_sig):
        """Rebuild a script when a signature length changes."""
        # Create new script with correct space for the new signature
        new_script = bytearray()
        
        # Add bytes before the signature
        new_script.extend(script[:pos])
        
        # Add signature length byte
        new_script.append(len(fixed_sig))
        
        # Add fixed signature
        new_script.extend(fixed_sig)
        
        # Add bytes after the signature
        new_script.extend(script[sig_end:])
        
        return new_script
    
    def fix_der_signature(self, sig_bytes, input_index):
        """Fix a non-canonical DER signature."""
        try:
            # Basic check - must start with 0x30 (DER sequence)
            if not sig_bytes or sig_bytes[0] != 0x30:
                return None
            
            # Check if this is a Bitcoin transaction signature (should end with hashtype)
            hashtype = None
            if len(sig_bytes) > 1:
                # Extract potential hashtype (last byte)
                hashtype = sig_bytes[-1]
                # Remove hashtype for proper DER analysis
                der_bytes = sig_bytes[:-1]
            else:
                der_bytes = sig_bytes
            
            # Check for the common "extra byte" issue
            # If DER length byte doesn't match actual content length
            if len(der_bytes) > 2 and der_bytes[1] != len(der_bytes) - 2:
                self.info.append(f"Found DER length mismatch in input {input_index}")
                
                # Fix the DER length byte
                fixed_der = bytearray(der_bytes)
                fixed_der[1] = len(fixed_der) - 2
                
                # Re-add hashtype if it was present
                if hashtype is not None:
                    fixed_sig = bytearray(fixed_der)
                    fixed_sig.append(hashtype)
                    return fixed_sig
                else:
                    return fixed_der
            
            # Check R value (first integer in DER sequence)
            if len(der_bytes) >= 4 and der_bytes[2] == 0x02:
                r_len = der_bytes[3]
                if len(der_bytes) > 4 + r_len:
                    r_start = 4
                    r_end = r_start + r_len
                    r_value = der_bytes[r_start:r_end]
                    
                    # Fix redundant leading zero in R
                    if len(r_value) > 1 and r_value[0] == 0x00 and not (r_value[1] & 0x80):
                        self.info.append(f"Found unnecessary leading zero in R value in input {input_index}")
                        
                        # Create fixed signature
                        fixed_der = bytearray()
                        fixed_der.append(0x30)  # DER sequence marker
                        
                        # We'll compute the length after building the content
                        fixed_der.append(0x00)  # Placeholder for length
                        
                        fixed_der.append(0x02)  # Integer marker for R
                        
                        # Remove unnecessary leading zero
                        fixed_r = r_value[1:]
                        fixed_der.append(len(fixed_r))  # R length
                        fixed_der.extend(fixed_r)       # R value
                        
                        # Add the S value as-is
                        s_start = r_end
                        if s_start < len(der_bytes):
                            fixed_der.extend(der_bytes[s_start:])
                        
                        # Update the total length
                        fixed_der[1] = len(fixed_der) - 2
                        
                        # Re-add hashtype if it was present
                        if hashtype is not None:
                            fixed_sig = bytearray(fixed_der)
                            fixed_sig.append(hashtype)
                            return fixed_sig
                        else:
                            return fixed_der
            
            # Check S value (second integer in DER sequence)
            if len(der_bytes) >= 7 and der_bytes[2] == 0x02:
                r_len = der_bytes[3]
                s_start = 4 + r_len
                
                if s_start + 2 < len(der_bytes) and der_bytes[s_start] == 0x02:
                    s_len = der_bytes[s_start + 1]
                    s_value_start = s_start + 2
                    s_value_end = s_value_start + s_len
                    
                    if s_value_end <= len(der_bytes):
                        s_value = der_bytes[s_value_start:s_value_end]
                        
                        # Fix redundant leading zero in S
                        if len(s_value) > 1 and s_value[0] == 0x00 and not (s_value[1] & 0x80):
                            self.info.append(f"Found unnecessary leading zero in S value in input {input_index}")
                            
                            # Create fixed signature
                            fixed_der = bytearray()
                            
                            # Add R value as-is
                            fixed_der.extend(der_bytes[:s_start])
                            
                            # Add S with fixed format
                            fixed_der.append(0x02)  # Integer marker for S
                            
                            # Remove unnecessary leading zero
                            fixed_s = s_value[1:]
                            fixed_der.append(len(fixed_s))  # S length
                            fixed_der.extend(fixed_s)       # S value
                            
                            # Update the total length
                            fixed_der[1] = len(fixed_der) - 2
                            
                            # Re-add hashtype if it was present
                            if hashtype is not None:
                                fixed_sig = bytearray(fixed_der)
                                fixed_sig.append(hashtype)
                                return fixed_sig
                            else:
                                return fixed_der
            
            # If we get here, we couldn't fix a specific issue
            return None
            
        except Exception as e:
            self.errors.append(f"Error fixing DER signature in input {input_index}: {str(e)}")
            return None
    
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
    
    def create_varint(self, value):
        """Create a varint from a value."""
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return bytes([0xfd]) + struct.pack("<H", value)
        elif value <= 0xffffffff:
            return bytes([0xfe]) + struct.pack("<I", value)
        else:
            return bytes([0xff]) + struct.pack("<Q", value)


def extract_tx_signatures(tx_hex):
    """Extract all potential signatures from a transaction."""
    # Note: This function isn't perfect, but helps identify and display signatures
    
    # Look for DER signatures with SIGHASH byte
    sig_pattern = r'(30[0-9a-fA-F]{2}02[0-9a-fA-F]{2}[0-9a-fA-F]+02[0-9a-fA-F]{2}[0-9a-fA-F]+(?:01|81|82|83))'
    
    signatures = re.findall(sig_pattern, tx_hex)
    
    if not signatures:
        return ["No DER signatures found in transaction"]
    
    results = ["Found potential DER signatures:"]
    
    for i, sig_hex in enumerate(signatures):
        try:
            # Skip if this is clearly not a signature (too short)
            if len(sig_hex) < 8:
                continue
                
            results.append(f"Signature {i+1}: {sig_hex}")
            
            # Convert to bytes
            sig_bytes = bytes.fromhex(sig_hex)
            
            # Extract potential hashtype (last byte)
            hashtype = sig_bytes[-1]
            
            # Remove hashtype for DER analysis
            der_bytes = sig_bytes[:-1]
            
            if der_bytes[0] != 0x30:
                results.append("  Warning: Not a valid DER sequence")
                continue
                
            # Get DER length
            der_len = der_bytes[1]
            
            # Check for length mismatch
            if der_len != len(der_bytes) - 2:
                results.append(f"  Issue: DER length byte ({der_len}) doesn't match actual length ({len(der_bytes) - 2})")
            
            # Extract R value
            if len(der_bytes) > 3 and der_bytes[2] == 0x02:
                r_len = der_bytes[3]
                r_start = 4
                r_end = r_start + r_len
                
                if r_end <= len(der_bytes):
                    r_value = der_bytes[r_start:r_end]
                    results.append(f"  R value ({r_len} bytes): {r_value.hex()}")
                    
                    # Check for unnecessary leading zero
                    if len(r_value) > 1 and r_value[0] == 0x00:
                        if not (r_value[1] & 0x80):
                            results.append("  Issue: Unnecessary leading zero in R value")
                        else:
                            results.append("  Note: Leading zero in R value is correct (high bit set)")
                    
                    # Extract S value
                    s_start = r_end
                    if s_start + 2 <= len(der_bytes) and der_bytes[s_start] == 0x02:
                        s_len = der_bytes[s_start + 1]
                        s_value_start = s_start + 2
                        s_value_end = s_value_start + s_len
                        
                        if s_value_end <= len(der_bytes):
                            s_value = der_bytes[s_value_start:s_value_end]
                            results.append(f"  S value ({s_len} bytes): {s_value.hex()}")
                            
                            # Check for unnecessary leading zero
                            if len(s_value) > 1 and s_value[0] == 0x00:
                                if not (s_value[1] & 0x80):
                                    results.append("  Issue: Unnecessary leading zero in S value")
                                else:
                                    results.append("  Note: Leading zero in S value is correct (high bit set)")
                            
                            # Check for extra bytes
                            if s_value_end < len(der_bytes):
                                extra_bytes = der_bytes[s_value_end:]
                                results.append(f"  Issue: Extra bytes in DER: {extra_bytes.hex()}")
            
            # Show hashtype
            results.append(f"  Hashtype: {hashtype:#04x}")
            
        except Exception as e:
            results.append(f"  Error analyzing signature: {str(e)}")
    
    return results


def main():
    print("Bitcoin Transaction Signature Fixer")
    print("--------------------------------")
    
    # Get input
    tx_hex = input("Enter raw transaction hex: ").strip()
    
    # Basic validation
    if not tx_hex:
        print("Error: Transaction hex cannot be empty")
        return
    
    if not all(c in '0123456789abcdefABCDEF' for c in tx_hex):
        print("Error: Transaction must be a hex string")
        return
    
    # Analyze signatures in the transaction
    print("\n🔍 ANALYZING SIGNATURES:")
    sig_analysis = extract_tx_signatures(tx_hex)
    for line in sig_analysis:
        print(f"  {line}")
    
    # Fix the transaction
    print("\n🔧 ATTEMPTING TO FIX TRANSACTION:")
    fixer = TransactionFixer()
    fixed_tx_hex = fixer.fix_transaction(tx_hex)
    
    # Display errors, warnings, and info
    if fixer.errors:
        print("\n❌ ERRORS:")
        for error in fixer.errors:
            print(f"  - {error}")
    
    if fixer.warnings:
        print("\n⚠️ WARNINGS:")
        for warning in fixer.warnings:
            print(f"  - {warning}")
    
    if fixer.info:
        print("\nℹ️ INFO:")
        for info in fixer.info:
            print(f"  - {info}")
    
    # Display fixed transaction
    if fixed_tx_hex:
        print("\n✅ TRANSACTION FIXED SUCCESSFULLY!")
        print("\nFixed Transaction Hex:")
        print(fixed_tx_hex)
        
        # Analyze the fixed transaction signatures
        print("\n🔍 VERIFYING FIXED SIGNATURES:")
        fixed_sig_analysis = extract_tx_signatures(fixed_tx_hex)
        for line in fixed_sig_analysis:
            print(f"  {line}")
    else:
        print("\n❌ COULD NOT FIX TRANSACTION")
        print("Try re-signing with a proper Bitcoin library.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)