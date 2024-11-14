package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"curve25519_keygen/keygen"
	"curve25519_keygen/mnemonic"
)

// Prints the private and public keys in hexadecimal format.
func PrintKeyInfo(privateKey, publicKey []byte) {
	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privateKey))
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(publicKey))
}

func main() {
	// Retrieves the mnemonic phrase from command-line arguments or generates a new one
	mnemonicPhrase, err := mnemonic.GetMnemonic(os.Args)
	if err != nil {
		panic(err)
	}

	// Generates the seed from the mnemonic phrase with an optional empty passphrase
	seed := mnemonic.GenerateSeed(mnemonicPhrase, "")

	// Generates the private and public keys using the seed
	privateKey := keygen.GeneratePrivateKey(seed)
	publicKey, err := keygen.GeneratePublicKey(privateKey)
	if err != nil {
		log.Fatalf("Error generating public key: %v", err)
	}

	// Outputs the generated private and public keys
	PrintKeyInfo(privateKey, publicKey)
}
