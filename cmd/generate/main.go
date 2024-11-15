package main

import (
	"ed25519_keygen/src/keygen"
	"ed25519_keygen/src/mnemonic"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

// Prints the private and public keys in hexadecimal format.
func PrintKeyInfo(mnemonicPhrase string, privateKey, publicKey []byte) {
	fmt.Printf("Mnemonic phrase: %s\n", mnemonicPhrase)
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
	privateKey, err := keygen.GeneratePrivateKey(seed)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	publicKey, err := keygen.GeneratePublicKey(privateKey)
	if err != nil {
		log.Fatalf("Error generating public key: %v", err)
	}

	// Outputs the generated private and public keys
	PrintKeyInfo(mnemonicPhrase, privateKey, publicKey)
}
