"""
Python bindings for the hash-sig library.

This package provides Python interfaces to hash-based signature schemes
based on tweakable hash functions and incomparable encodings.

Warning: This is a prototype implementation and has not been audited.
Do not use in production!
"""

from typing import Optional, Tuple
from ._hashsig_py import (
    PyPublicKey as PublicKey,
    PySecretKey as SecretKey,
    PySignature as Signature,
    HashSigSHA3,
    HashSigPoseidon,
)

__version__ = "0.1.0"
__all__ = [
    "PublicKey",
    "SecretKey",
    "Signature",
    "HashSigSHA3",
    "HashSigPoseidon",
    "SignatureScheme",
]


class SignatureScheme:
    """
    High-level interface for hash-based signature schemes.
    
    This class provides a unified interface for working with different
    hash-based signature instantiations (SHA3, Poseidon, etc.).
    
    Example:
        >>> scheme = SignatureScheme.sha3(lifetime=1_000_000)
        >>> pk, sk = scheme.key_gen()
        >>> 
        >>> # Ensure the secret key is prepared for the epoch
        >>> epoch = 42
        >>> while not sk.is_prepared_for_epoch(epoch):
        >>>     sk.advance_preparation()
        >>> 
        >>> # Sign a message
        >>> message = b"Hello, world!"
        >>> signature = scheme.sign(sk, epoch, message)
        >>> 
        >>> # Verify the signature
        >>> is_valid = scheme.verify(pk, epoch, message, signature)
        >>> assert is_valid
    
    Important: Each (secret_key, epoch) pair must only be used ONCE for signing!
    """
    
    def __init__(self, backend):
        """
        Initialize with a backend implementation.
        
        Args:
            backend: The underlying signature scheme (HashSigSHA3 or HashSigPoseidon)
        """
        self._backend = backend
    
    @classmethod
    def sha3(cls, lifetime: Optional[int] = None) -> "SignatureScheme":
        """
        Create a signature scheme using SHA3.
        
        Args:
            lifetime: Maximum number of epochs (signatures) this key can support.
                     Default is 2^20 (~1 million).
        
        Returns:
            A SignatureScheme instance using SHA3.
        """
        return cls(HashSigSHA3(lifetime=lifetime))
    
    @classmethod
    def poseidon(cls, lifetime: Optional[int] = None) -> "SignatureScheme":
        """
        Create a signature scheme using Poseidon2.
        
        Args:
            lifetime: Maximum number of epochs (signatures) this key can support.
                     Default is 2^20 (~1 million).
        
        Returns:
            A SignatureScheme instance using Poseidon2.
        """
        return cls(HashSigPoseidon(lifetime=lifetime))
    
    def key_gen(
        self,
        seed: Optional[bytes] = None,
        activation_epoch: int = 0,
    ) -> Tuple[PublicKey, SecretKey]:
        """
        Generate a new key pair.
        
        Args:
            seed: Optional random seed for deterministic key generation.
                 If None, uses system randomness.
            activation_epoch: The epoch at which the key becomes active (default: 0).
        
        Returns:
            A tuple of (public_key, secret_key).
        
        Note:
            Key generation can be expensive, especially for large lifetimes.
        """
        return self._backend.key_gen(seed=seed, activation_epoch=activation_epoch)
    
    def sign(
        self,
        secret_key: SecretKey,
        epoch: int,
        message: bytes,
    ) -> Signature:
        """
        Sign a message for a specific epoch.
        
        Args:
            secret_key: The secret key to sign with.
            epoch: The epoch for this signature.
            message: The message to sign.
        
        Returns:
            The signature.
        
        Raises:
            ValueError: If the secret key is not prepared for this epoch.
        
        Important:
            - Each (secret_key, epoch) pair must only be used ONCE!
            - The secret key must be prepared for the epoch by calling
              secret_key.advance_preparation() in the background.
            - Reusing an epoch will compromise security!
        """
        return self._backend.sign(secret_key, epoch, message)
    
    def verify(
        self,
        public_key: PublicKey,
        epoch: int,
        message: bytes,
        signature: Signature,
    ) -> bool:
        """
        Verify a signature.
        
        Args:
            public_key: The public key to verify against.
            epoch: The epoch the signature was created for.
            message: The message that was signed.
            signature: The signature to verify.
        
        Returns:
            True if the signature is valid, False otherwise.
        """
        return self._backend.verify(public_key, epoch, message, signature)
    
    @property
    def lifetime(self) -> int:
        """
        Get the lifetime (maximum number of epochs/signatures) for this scheme.
        
        Returns:
            The maximum number of epochs this scheme supports.
        """
        return self._backend.get_lifetime()


def prepare_secret_key_for_epoch(
    secret_key: SecretKey,
    target_epoch: int,
    max_iterations: Optional[int] = None,
) -> bool:
    """
    Utility function to prepare a secret key for a specific epoch.
    
    This advances the secret key's preparation interval until it includes
    the target epoch.
    
    Args:
        secret_key: The secret key to prepare.
        target_epoch: The epoch to prepare for.
        max_iterations: Maximum number of preparation steps to take.
                       If None, continues until prepared.
    
    Returns:
        True if successfully prepared, False if max_iterations was reached.
    
    Example:
        >>> scheme = SignatureScheme.sha3()
        >>> pk, sk = scheme.key_gen()
        >>> 
        >>> # Prepare for signing at epoch 1000
        >>> if prepare_secret_key_for_epoch(sk, 1000):
        >>>     signature = scheme.sign(sk, 1000, b"message")
    """
    iterations = 0
    while not secret_key.is_prepared_for_epoch(target_epoch):
        if max_iterations is not None and iterations >= max_iterations:
            return False
        secret_key.advance_preparation()
        iterations += 1
    return True