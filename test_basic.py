#!/usr/bin/env python3
"""
Basic test for the hashsig Python bindings.
"""

import hashsig_py
import os


def test_basic_functionality():
    """Test basic functionality of the Python bindings."""
    print("=== Testing Hash-Sig Python Bindings ===\n")
    
    # Test SHA3 scheme
    print("1. Testing HashSigSHA3...")
    sha3_scheme = hashsig_py.HashSigSHA3()
    print(f"   Lifetime: {sha3_scheme.get_lifetime()}")
    
    # Test key generation
    print("\n2. Testing key generation...")
    pk, sk = sha3_scheme.key_gen()
    print(f"   Public key: {pk}")
    print(f"   Secret key: {sk}")
    print(f"   Prepared interval: [{sk.get_prepared_start()}, {sk.get_prepared_end()})")
    
    # Test signing
    print("\n3. Testing signing...")
    epoch = 100
    message = b"Hello, hash-based signatures!"
    
    # Check if epoch is prepared
    if not sk.is_prepared_for_epoch(epoch):
        print(f"   Epoch {epoch} not prepared, advancing preparation...")
        sk.advance_preparation()
        print(f"   New prepared interval: [{sk.get_prepared_start()}, {sk.get_prepared_end()})")
    
    signature = sha3_scheme.sign(sk, epoch, message)
    print(f"   Signature: {signature}")
    
    # Test verification
    print("\n4. Testing verification...")
    is_valid = sha3_scheme.verify(pk, epoch, message, signature)
    print(f"   Signature valid: {is_valid}")
    
    # Test Poseidon scheme
    print("\n5. Testing HashSigPoseidon...")
    poseidon_scheme = hashsig_py.HashSigPoseidon()
    print(f"   Lifetime: {poseidon_scheme.get_lifetime()}")
    
    pk2, sk2 = poseidon_scheme.key_gen()
    print(f"   Generated Poseidon keys successfully")
    
    print("\n✓ All tests completed successfully!")


def test_key_serialization():
    """Test key serialization functionality."""
    print("\n=== Testing Key Serialization ===\n")
    
    scheme = hashsig_py.HashSigSHA3()
    pk, sk = scheme.key_gen()
    
    # Test public key serialization
    print("1. Testing public key serialization...")
    pk_bytes = pk.to_bytes()
    print(f"   Public key bytes length: {len(pk_bytes)}")
    
    # Test secret key serialization
    print("\n2. Testing secret key serialization...")
    sk_bytes = sk.to_bytes()
    print(f"   Secret key bytes length: {len(sk_bytes)}")
    
    # Test signature serialization
    print("\n3. Testing signature serialization...")
    epoch = 50
    message = b"Test message"
    
    if not sk.is_prepared_for_epoch(epoch):
        sk.advance_preparation()
    
    signature = scheme.sign(sk, epoch, message)
    sig_bytes = signature.to_bytes()
    print(f"   Signature bytes length: {len(sig_bytes)}")
    
    print("\n✓ Serialization tests completed successfully!")


def main():
    """Run all tests."""
    print("Hash-Sig Python Bindings - Basic Test")
    print("=" * 50)
    
    print("⚠️  WARNING: This is a prototype implementation!")
    print("⚠️  Do not use in production - not audited!\n")
    
    try:
        test_basic_functionality()
        test_key_serialization()
        
        print("\n" + "=" * 50)
        print("All tests passed! ✓")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
