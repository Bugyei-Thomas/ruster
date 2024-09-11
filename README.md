# Rust Crypter/Decrypter

A high-performance crypter and decrypter built with rust. This tool uses aes-256 encryption in cbc mode to securely encrypt and decrypt files.

## Features
- Secure encryption and decryption using ChaCha20
- Password-based key generation with SHA-256

## Requirements
- Rust installed (see [rust installation guide](https://www.rust-lang.org/tools/install))

## Installation

### Clone the repository
Clone this repo to your local machine:
```
git clone https://github.com/Bugyei-Thomas/ruster
cd ruster
```
## Build the project
Build this in release mode for optimized performance
```
carg build --release
cd target/release
```
## Run the program
```
./file_encrypter_decrypter
```
