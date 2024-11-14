package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey genera una chiave privata compatibile con Yggdrasil applicando il clamping.
func GeneratePrivateKey(seed []byte) []byte {
	privateKey := make([]byte, 32)
	copy(privateKey, seed)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	return privateKey
}

// GeneratePublicKey genera la chiave pubblica Curve25519 dalla chiave privata.
func GeneratePublicKey(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}

// GetMnemonic restituisce una frase mnemonica fornita come argomento o ne genera una nuova.
func GetMnemonic() string {
	if len(os.Args) > 1 {
		mnemonic := os.Args[1]
		if !bip39.IsMnemonicValid(mnemonic) {
			log.Fatalf("Frase mnemonica non valida")
		}
		return mnemonic
	}
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	fmt.Printf("Nuova Frase Mnemonica: %s\n", mnemonic)
	return mnemonic
}

func main() {
	// Genera o ottieni una frase mnemonica e calcola il seed
	mnemonic := GetMnemonic()
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := GeneratePrivateKey(seed)
	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		log.Fatalf("Errore nella generazione della chiave pubblica: %v", err)
	}

	// Stampa le chiavi
	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privateKey))
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(publicKey))
}
