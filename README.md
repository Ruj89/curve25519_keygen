# Curve25519 Key Generator

This project is a POC that provides utilities to generate cryptographic keys and seeds, leveraging Curve25519 for key derivation and AES-GCM for encryption. It includes modules for generating mnemonic phrases, seeds, private keys, and public keys.

## Table of Contents

- [Overview](#overview)
- [Usage](#usage)
- [Testing](#testing)
- [Dependencies](#dependencies)

## Overview

The application includes three main modules:

1. **Key Generation**: Generates private and public keys using Curve25519 and performs encryption and decryption with AES-GCM.
2. **Mnemonic Generation**: Generates mnemonic phrases for seed creation following the BIP-39 standard.
3. **Main Application**: Combines mnemonic-based seed generation and key derivation to produce and display a public-private key pair.

## Usage

To run the application, use:

```bash
go run main.go
```

If you want to specify a mnemonic phrase to generate the seed and keys, provide it as an argument. For example:

```bash
go run main.go "lake genuine grab onion skill tilt news decrease library finish update vehicle"
```

If a mnemonic phrase is provided, the application will use it to generate the seed and keys. If no phrase is provided, a new one will be generated and displayed in the console.

## Testing

The project includes a comprehensive set of test files.

To run the tests, execute:

```bash
go test ./... -v
```

### Test Coverage

- **Key Generation Tests**: Verify correct key length, clamping, and determinism for public key generation, as well as encryption and decryption.
- **Mnemonic Tests**: Validate mnemonic generation, seed derivation, and error handling for invalid mnemonics.

## Dependencies

This project uses Go modules to manage dependencies. The primary dependencies are:

- `github.com/tyler-smith/go-bip39`: Provides functions for BIP-39 mnemonic phrase generation and seed derivation.
- `golang.org/x/crypto`: Used for Curve25519 key generation and AES-GCM encryption.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.