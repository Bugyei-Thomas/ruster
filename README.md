# Ruster

A high-performance file encrypter/decrypter built with Rust. Uses ChaCha20 stream cipher for secure file encryption with password-based key derivation via SHA-256.

## Features

- ChaCha20 stream cipher encryption
- Password-based key generation with SHA-256
- Random 12-byte nonce per encryption (prepended to ciphertext)
- Interactive CLI for encrypt/decrypt operations

## Requirements

- Rust (see [rust installation guide](https://www.rust-lang.org/tools/install))

## Installation

```bash
git clone https://github.com/s4wbvnny/ruster
cd ruster
cargo build --release
```

## Usage

```bash
cd target/release
./file_encrypter_decrypter
```

Follow the prompts:
1. Select mode: `encrypt` or `decrypt`
2. Specify input file path
3. Specify output file path
4. Enter password

## How It Works

1. Derives a 256-bit key from the password using SHA-256.
2. Generates a random 12-byte nonce for each encryption.
3. Encrypts the file content using ChaCha20.
4. Writes nonce + ciphertext to the output file (nonce is prepended for decryption).

## License

MIT
