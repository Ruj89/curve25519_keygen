package keygen

import (
	"crypto/rand"
	"testing"

	"crypto/ed25519"
)

func generateRandomSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	if err != nil {
		panic("Failed to generate random seed")
	}
	return seed
}

func TestGeneratePrivateKey_InvalidSeedLength(t *testing.T) {
	// Test case: Verify that a seed with invalid length causes an error
	seed := make([]byte, 16) // Invalid length
	_, err := GeneratePrivateKey(seed)

	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
}

func TestGeneratePrivateKey_ValidSeed(t *testing.T) {
	// Test case: Verify private key generation with valid seed
	seed := generateRandomSeed()
	privateKey, err := GeneratePrivateKey(seed)

	if err != nil || privateKey == nil {
		t.Errorf("Expected a valid private key, got an error or nil")
	}
}

func TestIntegration_PrivateToPublicKey(t *testing.T) {
	// Test case: Verify end-to-end generation of private and public keys
	seed := generateRandomSeed()

	privateKey, _ := GeneratePrivateKey(seed)
	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatalf("Error generating public key from private key: %v", err)
	}
	if publicKey == nil {
		t.Errorf("Expected a valid public key, got nil")
	}
}
