package keygen

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

// Uses the provided seed to generate an Ed25519 private key.
func GeneratePrivateKey(seed []byte) ([]byte, error) { // Ensure the seed is 32 bytes (Ed25519 requirement)
	// Ensure the seed is at least 32 bytes (Ed25519 requirement)
	if len(seed) < ed25519.SeedSize {
		return nil, errors.New("seed must be exactly 32 bytes")
	}

	// Hash the input seed to derive a valid 32-byte seed
	hash := sha256.Sum256(seed)
	seed = hash[:]

	// Generate the Ed25519 private key from the (potentially hashed) seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey, nil
}

// Derives an Ed25519 public key from the private key.
func GeneratePublicKey(privateKey []byte) ([]byte, error) {
	// Ensure the private key length is valid for Ed25519
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}

	// Extract the public key from the private key
	publicKey := privateKey[ed25519.SeedSize:] // Public key is the last 32 bytes of the private key
	return publicKey, nil
}
