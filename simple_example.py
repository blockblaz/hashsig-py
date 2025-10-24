#!/usr/bin/env python3
"""
Simple example for the hashsig Python bindings.
"""

import hashsig_py
import os


def simple_example():
    """Simple example using the current API."""
    print("=== Simple Hash-Sig Example ===\n")
    
    # Create a signature scheme using SHA3
    scheme = hashsig_py.HashSigSHA3()
    print(f"Created signature scheme with lifetime: {scheme.get_lifetime():,}")
    
    # Generate a key pair
    print("\nGenerating keys...")
    pk, sk = scheme.key_gen()
    print(f"Public key: {pk}")
    print(f"Secret key: {sk}")
    print(f"Prepared interval: [{sk.get_prepared_start()}, {sk.get_prepared_end()})")
    
    # Sign a message
    epoch = 100
    message = b"Hello, hash-based signatures!"
    print(f"\nSigning message at epoch {epoch}: {message}")
    
    # Check if epoch is prepared
    if not sk.is_prepared_for_epoch(epoch):
        print(f"Epoch {epoch} not prepared, advancing preparation...")
        sk.advance_preparation()
        print(f"New prepared interval: [{sk.get_prepared_start()}, {sk.get_prepared_end()})")
    
    signature = scheme.sign(sk, epoch, message)
    print(f"Signature: {signature} (length: {len(signature)} bytes)")
    
    # Verify the signature
    print("\nVerifying signature...")
    is_valid = scheme.verify(pk, epoch, message, signature)
    print(f"Signature valid: {is_valid}")
    
    # Try to verify with wrong message
    wrong_message = b"Wrong message"
    is_valid_wrong = scheme.verify(pk, epoch, wrong_message, signature)
    print(f"Signature valid for wrong message: {is_valid_wrong}")
    
    print("\n✓ Simple example completed successfully!")


def poseidon_example():
    """Example using Poseidon2 scheme."""
    print("\n=== Poseidon2 Example ===\n")
    
    # Create a signature scheme using Poseidon2
    scheme = hashsig_py.HashSigPoseidon()
    print(f"Created Poseidon2 scheme with lifetime: {scheme.get_lifetime():,}")
    
    # Generate keys
    pk, sk = scheme.key_gen()
    print(f"Generated keys successfully")
    
    # Prepare and sign
    epoch = 42
    message = b"Poseidon2 is a ZK-friendly hash function"
    print(f"\nSigning message at epoch {epoch}: {message}")
    
    if not sk.is_prepared_for_epoch(epoch):
        sk.advance_preparation()
    
    signature = scheme.sign(sk, epoch, message)
    print(f"Signature: {signature}")
    
    # Verify
    is_valid = scheme.verify(pk, epoch, message, signature)
    print(f"Signature valid: {is_valid}")
    
    print("\n✓ Poseidon2 example completed successfully!")


def main():
    """Run examples."""
    print("Hash-Sig Python Bindings - Simple Examples")
    print("=" * 50)
    
    print("⚠️  WARNING: This is a prototype implementation!")
    print("⚠️  Do not use in production - not audited!\n")
    
    try:
        simple_example()
        poseidon_example()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully! ✓")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
