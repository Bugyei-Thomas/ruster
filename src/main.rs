use chacha20::{ChaCha20, Key, Nonce};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, stdin};
use std::str;

// this function hashes the password
fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// encryption function
fn encrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = hash_password(password);
    let key = Key::from_slice(&key);

    // generate a random nonce (12 bytes for ChaCha20)
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    // read input file
    let mut input_data = Vec::new();
    let mut file = File::open(input_file)?;
    file.read_to_end(&mut input_data)?;

    // create cipher and encrypt
    let mut cipher = ChaCha20::new(key, nonce);
    let mut ciphertext = input_data.clone();
    cipher.apply_keystream(&mut ciphertext);

    // write nonce + ciphertext to output file
    let mut output = OpenOptions::new().write(true).create(true).open(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&ciphertext)?;

    Ok(())
}

// function to check if file content is valid (readable ascii)
fn is_readable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
}

// decryption function
fn decrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = hash_password(password);
    let key = Key::from_slice(&key);

    // read the input file
    let mut input_data = Vec::new();
    let mut file = File::open(input_file)?;
    file.read_to_end(&mut input_data)?;

    // split nonce and ciphertext
    let (nonce, ciphertext) = input_data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    // create cipher and decrypt
    let mut cipher = ChaCha20::new(key, nonce);
    let mut decrypted_data = ciphertext.to_vec();
    cipher.apply_keystream(&mut decrypted_data);

    // check if decrypted data is readable ascii
    if is_readable_ascii(&decrypted_data) {
        // write decrypted data to output file
        let mut output = OpenOptions::new().write(true).create(true).open(output_file)?;
        output.write_all(&decrypted_data)?;

        Ok(())
    } else {
        Err(From::from("wrong password or file corrupted"))
    }
}

fn get_user_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);
    stdin().read_line(&mut input).expect("failed to read input");
    input.trim().to_string() // remove any leading/trailing whitespaces
}

fn main() {
    println!("Ruster");

    let mode = get_user_input("Select an Option: (type 'encrypt' or 'decrypt'):");
    let input_file = get_user_input("Specify path to the file:");
    let output_file = get_user_input("Specify path to store file:");
    let password = get_user_input("Password:");

    match mode.as_str() {
        "encrypt" => {
            if let Err(e) = encrypt_file(&input_file, &output_file, &password) {
                eprintln!("encryption failed: {}", e);
            } else {
                println!("🔥 File encrypted successfully!! 🔥");
            }
        }
        "decrypt" => {
            match decrypt_file(&input_file, &output_file, &password) {
                Ok(_) => println!("💥 File decrypted successfully!! 💥"),
                Err(e) => eprintln!("decryption failed: {}", e),
            }
        }
        _ => {
            eprintln!("❌ Unknown mode '{}' selected. type 'encrypt' or 'decrypt' only.", mode);
        }
    }
}
