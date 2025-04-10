#!/usr/bin/env python3
"""
Bitcoin DER Signature Length Fixer
Specifically targets and fixes DER length byte issues in Bitcoin transaction signatures.
"""

import binascii
import sys
import re

def fix_der_lengths(tx_hex):
    """Find and fix all DER signatures with incorrect length bytes."""
    print("Original TX:", tx_hex)
    
    # First, find all potential DER signatures
    # Look for sequence starting with 30 + length byte + 02 (Integer marker for R value)
    der_pattern = re.compile(r'30([0-9a-fA-F]{2})02([0-9a-fA-F]{2}[0-9a-fA-F]+)02([0-9a-fA-F]{2}[0-9a-fA-F]+)([0-9a-fA-F]{2})?')
    
    # Keep track of all replacements to make
    replacements = []
    
    for match in der_pattern.finditer(tx_hex):
        # Get full signature and its position
        sig_start = match.start()
        sig_end = match.end()
        sig_hex = match.group(0)
        
        # Get components 
        length_byte_hex = match.group(1)
        r_length_and_value = match.group(2)
        s_length_and_value = match.group(3)
        sighash_byte = match.group(4)  # This may be None
        
        print(f"\nFound potential signature at position {sig_start}:")
        print(f"  Signature: {sig_hex}")
        print(f"  DER Length Byte: {length_byte_hex}")
        print(f"  R Component: {r_length_and_value}")
        print(f"  S Component: {s_length_and_value}")
        if sighash_byte:
            print(f"  Potential SIGHASH byte: {sighash_byte}")
        
        # Calculate actual content length (everything except 30 and length byte)
        content_hex = sig_hex[4:]  # Skip '30' and length byte
        if sighash_byte:
            content_hex = content_hex[:-2]  # Remove sighash byte if present
            
        content_length = len(content_hex) // 2  # Convert hex length to byte length
        
        # Convert length byte to int
        declared_length = int(length_byte_hex, 16)
        
        print(f"  Declared Length: {declared_length} bytes")
        print(f"  Actual Content Length: {content_length} bytes")
        
        # Check if length byte is incorrect
        if declared_length != content_length:
            print(f"  ISSUE DETECTED: Length mismatch!")
            
            # Calculate correct length byte
            correct_length_byte_hex = f"{content_length:02x}"
            
            # Create fixed signature
            fixed_sig = f"30{correct_length_byte_hex}{content_hex}"
            if sighash_byte:
                fixed_sig += sighash_byte
                
            print(f"  Fixed signature: {fixed_sig}")
            
            # Add to replacements list
            replacements.append((sig_hex, fixed_sig))
    
    # Apply all replacements to the transaction
    fixed_tx_hex = tx_hex
    for old_sig, new_sig in replacements:
        fixed_tx_hex = fixed_tx_hex.replace(old_sig, new_sig)
    
    # Check if any changes were made
    if fixed_tx_hex == tx_hex:
        if replacements:
            print("\nWARNING: Failed to apply some replacements. This can happen if signatures overlap or if the regex didn't match exactly.")
        else:
            print("\nNo signature length issues were detected or fixed.")
    else:
        print(f"\nSuccessfully fixed {len(replacements)} DER signature(s)!")
    
    return fixed_tx_hex

def check_r_s_values(tx_hex):
    """Analyze R and S values for additional issues."""
    # Find R and S components in all signatures
    sig_pattern = re.compile(r'30[0-9a-fA-F]{2}02([0-9a-fA-F]{2})([0-9a-fA-F]+)02([0-9a-fA-F]{2})([0-9a-fA-F]+)')
    
    issues_found = False
    
    for i, match in enumerate(sig_pattern.finditer(tx_hex)):
        r_len_hex = match.group(1)
        r_value_hex = match.group(2)
        s_len_hex = match.group(3)
        s_value_hex = match.group(4)
        
        r_len = int(r_len_hex, 16)
        s_len = int(s_len_hex, 16)
        
        print(f"\nSignature #{i+1}")
        print(f"  R value ({r_len} bytes): {r_value_hex}")
        print(f"  S value ({s_len} bytes): {s_value_hex}")
        
        # Check for unnecessary leading zeros in R
        if r_value_hex.startswith('00') and not int(r_value_hex[2:3], 16) & 0x8:
            print("  ⚠️ R value has unnecessary leading zero")
            issues_found = True
            
        # Check for unnecessary leading zeros in S
        if s_value_hex.startswith('00') and not int(s_value_hex[2:3], 16) & 0x8:
            print("  ⚠️ S value has unnecessary leading zero")
            issues_found = True
    
    if not issues_found:
        print("\nNo additional issues found with R and S values.")
    else:
        print("\n⚠️ Found potential issues with R or S values.")
        print("These are separate from length byte issues and may require additional fixes.")

def main():
    print("Bitcoin DER Signature Length Fixer")
    print("=================================")
    
    # Get transaction hex
    tx_hex = input("Enter raw transaction hex: ").strip()
    
    # Basic validation
    if not tx_hex:
        print("Error: Transaction hex cannot be empty")
        return
    
    if not all(c in '0123456789abcdefABCDEF' for c in tx_hex):
        print("Error: Transaction must be a hex string")
        return
    
    # Fix DER lengths
    print("\n## ANALYZING AND FIXING DER LENGTH BYTES ##")
    fixed_tx_hex = fix_der_lengths(tx_hex)
    
    # Additional checks
    print("\n## CHECKING FOR OTHER SIGNATURE ISSUES ##")
    check_r_s_values(fixed_tx_hex)
    
    # Output fixed transaction
    if fixed_tx_hex != tx_hex:
        print("\n## FIXED TRANSACTION ##")
        print(fixed_tx_hex)
    else:
        print("\n## NO CHANGES MADE TO TRANSACTION ##")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nError: {str(e)}")