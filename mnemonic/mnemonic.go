package mnemonic

import (
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// Retrieves a mnemonic phrase from the provided arguments or generates a new one.
func GetMnemonic(args []string) (string, error) {
	if len(args) > 1 {
		mnemonic := args[1]
		if !bip39.IsMnemonicValid(mnemonic) {
			return "", errors.New("invalid mnemonic phrase")
		}
		return mnemonic, nil
	}
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	fmt.Printf("Generated New Mnemonic Phrase: %s\n", mnemonic)
	return mnemonic, nil
}

// Generates a seed from the mnemonic phrase and an optional passphrase.
func GenerateSeed(mnemonic, passphrase string) []byte {
	return bip39.NewSeed(mnemonic, passphrase)
}
