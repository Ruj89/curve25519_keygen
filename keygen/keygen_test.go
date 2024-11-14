package keygen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// Generates a random 32-byte seed
func generateRandomSeed() []byte {
	seed := make([]byte, 32)
	rand.Read(seed)
	return seed
}

// Derives a shared secret using Curve25519 based on private and public keys
func deriveSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, publicKey)
}

// Encrypts a message using AES-GCM with the provided secret
func encryptMessage(secret, message []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	return nonce, gcm.Seal(nil, nonce, message, nil), nil
}

// Decrypts a message encrypted with AES-GCM using the provided secret
func decryptMessage(secret, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestGeneratePrivateKey(t *testing.T) {
	// Test case: Verify private key length is 32 bytes
	seed := generateRandomSeed()
	privateKey := GeneratePrivateKey(seed)
	if len(privateKey) != 32 {
		t.Errorf("Expected private key length of 32 bytes, got %d", len(privateKey))
	}

	// Test case: Verify correct clamping of private key
	seed[0], seed[31] = 0xFF, 0xFF
	privateKey = GeneratePrivateKey(seed)
	if privateKey[0]&7 != 0 || privateKey[31]&0x80 != 0 || privateKey[31]&0x40 == 0 {
		t.Error("Private key clamping is incorrect")
	}
}

func TestGeneratePublicKey(t *testing.T) {
	// Test case: Verify public key length is 32 bytes
	seed := generateRandomSeed()
	privateKey := GeneratePrivateKey(seed)
	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Fatalf("Error generating public key: %v", err)
	}
	if len(publicKey) != 32 {
		t.Errorf("Expected public key length of 32 bytes, got %d", len(publicKey))
	}

	// Test case: Verify public key is deterministic
	publicKey2, err := GeneratePublicKey(privateKey)
	if err != nil || !bytes.Equal(publicKey, publicKey2) {
		t.Error("Public key generation is not deterministic")
	}
}

func TestEncryptDecryptMessage_Success(t *testing.T) {
	// Test case: Verify successful encryption and decryption with matching keys
	privateKey1 := GeneratePrivateKey(generateRandomSeed())
	publicKey1, _ := GeneratePublicKey(privateKey1)
	privateKey2 := GeneratePrivateKey(generateRandomSeed())
	publicKey2, _ := GeneratePublicKey(privateKey2)

	// Derives matching shared secrets for both nodes
	sharedSecret1, _ := deriveSharedSecret(privateKey1, publicKey2)
	sharedSecret2, _ := deriveSharedSecret(privateKey2, publicKey1)
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Fatal("Derived shared secrets do not match")
	}

	// Encrypts and then decrypts the message
	message := []byte("Test message")
	nonce, ciphertext, err := encryptMessage(sharedSecret1, message)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	plaintext, err := decryptMessage(sharedSecret2, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Decrypted message does not match the original. Got: %s", plaintext)
	}
}

func TestDecryptMessage_Failure(t *testing.T) {
	// Test case: Verify decryption fails with incorrect shared secret
	privateKey1 := GeneratePrivateKey(generateRandomSeed())
	publicKey1, _ := GeneratePublicKey(privateKey1)
	privateKey2 := GeneratePrivateKey(generateRandomSeed())
	publicKey2, _ := GeneratePublicKey(privateKey2)

	// Derives the correct shared secret for encryption
	sharedSecret1, _ := deriveSharedSecret(privateKey1, publicKey2)
	message := []byte("Test message")
	nonce, ciphertext, err := encryptMessage(sharedSecret1, message)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	// Attempts decryption with a mismatched shared secret
	wrongPrivateKey := GeneratePrivateKey(generateRandomSeed())
	wrongSharedSecret, _ := deriveSharedSecret(wrongPrivateKey, publicKey1)
	_, err = decryptMessage(wrongSharedSecret, nonce, ciphertext)
	if err == nil {
		t.Error("Decryption succeeded with an incorrect key, expected failure")
	}
}
