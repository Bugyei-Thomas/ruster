use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::Rng;
use sha2::{Sha256, Digest};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, stdin};
use std::str;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// This function hashes the password
fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Encryption function
fn encrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = hash_password(password);
    
    // generate a random iv (initialization vector)
    let iv = rand::thread_rng().gen::<[u8; 16]>();

    // read input file
    let mut input_data = Vec::new();
    let mut file = File::open(input_file)?;
    file.read_to_end(&mut input_data)?;

    // create cipher and encrypt
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
    let ciphertext = cipher.encrypt_vec(&input_data);

    // write iv + ciphertext to output file
    let mut output = OpenOptions::new().write(true).create(true).open(output_file)?;
    output.write_all(&iv)?;
    output.write_all(&ciphertext)?;

    Ok(())
}

// Decryption function
fn decrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = hash_password(password);

    // read the input file
    let mut input_data = Vec::new();
    let mut file = File::open(input_file)?;
    file.read_to_end(&mut input_data)?;

    // split iv and ciphertext
    let (iv, ciphertext) = input_data.split_at(16);

    // create cipher and decrypt
    let cipher = Aes256Cbc::new_from_slices(&key, iv)?;
    let decrypted_data = cipher.decrypt_vec(ciphertext)?;

    // write decrypted data to output file
    let mut output = OpenOptions::new().write(true).create(true).open(output_file)?;
    output.write_all(&decrypted_data)?;

    Ok(())
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
            if let Err(e) = decrypt_file(&input_file, &output_file, &password) {
                eprintln!("decryption failed: {}", e);
            } else {
                println!("💥 File decrypted successfully!! 💥");
            }
        }
        _ => {
            eprintln!("❌ Unknown mode '{}' selected. type 'encrypt' or 'decrypt' only.", mode);
        }
    }
}
