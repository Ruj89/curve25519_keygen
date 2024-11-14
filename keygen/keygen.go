package keygen

import (
	"golang.org/x/crypto/curve25519"
)

// Applies clamping to the private key to make it compatible with Yggdrasil's requirements.
func GeneratePrivateKey(seed []byte) []byte {
	privateKey := make([]byte, 32)
	copy(privateKey, seed)
	privateKey[0] &= 248  // Clear the lower 3 bits for clamping
	privateKey[31] &= 127 // Clear the highest bit
	privateKey[31] |= 64  // Set the second-highest bit
	return privateKey
}

// Derives a Curve25519 public key from the private key.
func GeneratePublicKey(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}
