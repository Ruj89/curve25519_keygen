package mnemonic

import (
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestGetMnemonic_WithoutArgs(t *testing.T) {
	// Test case: Generate a new mnemonic when no arguments are provided
	mnemonic, err := GetMnemonic([]string{})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Errorf("Generated mnemonic phrase is invalid: %s", mnemonic)
	}
}

func TestGetMnemonic_WithValidMnemonicArg(t *testing.T) {
	// Generate a valid mnemonic for testing
	entropy, _ := bip39.NewEntropy(128)
	validMnemonic, _ := bip39.NewMnemonic(entropy)

	// Test case: Retrieve an existing, valid mnemonic passed as an argument
	mnemonic, err := GetMnemonic([]string{"appname", validMnemonic})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if mnemonic != validMnemonic {
		t.Errorf("Mnemonic phrase does not match expected value. Got: %s, Expected: %s", mnemonic, validMnemonic)
	}
}

func TestGetMnemonic_WithInvalidMnemonicArg(t *testing.T) {
	// Test case: Handle an invalid mnemonic passed as an argument
	_, err := GetMnemonic([]string{"appname", "invalid mnemonic phrase"})
	if err == nil {
		t.Errorf("Expected an error for an invalid mnemonic, but got none")
	}
}

func TestGenerateSeed(t *testing.T) {
	// Test case: Generate a seed of correct length from a valid mnemonic
	mnemonic, _ := GetMnemonic([]string{})
	seed := GenerateSeed(mnemonic, "")
	expectedLength := 64 // Expected seed length: 512 bits (64 bytes)
	if len(seed) != expectedLength {
		t.Errorf("Incorrect seed length, got: %d, expected: %d", len(seed), expectedLength)
	}
}
