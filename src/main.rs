extern crate clap;

use std::fs::File;
use std::io::{Read, Write};

use aes::aes;
use clap::{Parser, ArgEnum};

#[derive(PartialEq, Eq, Clone, ArgEnum)]
enum AesMode { Enc, Dec }

#[derive(Parser)]
#[clap(version)]
struct Args 
{
    #[clap(arg_enum)]
    pub mode: AesMode,

    /// The file to encrypt
    #[clap(short = 'i', long)]
    pub file: String,

    /// The output file name
    #[clap(short, long)]
    pub output: Option<String>,

    /// The AES key, 16 chars for AES128, 24 chars for AES192, 32 chars for AES256
    #[clap(short, long)]
    pub key: String,

    /// The AES key size. 128, 192 or 256
    #[clap(short = 's', long, default_value = "128")]
    pub key_size: usize,

    /// Whether to use hex string as the key
    #[clap(short = 'x', long)]
    pub hex: bool,
}

fn encrypt(key: aes::AesKey, plain: &[u8], output_file: &str)
{
    let mut output_file = File::create(output_file)
        .expect("Unable to create output file");
    let cipher = aes::aes_encrypt(plain, key);
    output_file.write_all(&cipher).expect("Unable to write output file");
}

fn decrypt(key: aes::AesKey, cipher: &[u8], output_file: &str)
{
    let mut output_file = File::create(output_file)
        .expect("Unable to create output file");
    let plain = aes::aes_decrypt(cipher, key);
    output_file.write_all(&plain).expect("Unable to write output file");
}

fn pad_key(key: &[u8], key_size: usize) -> Vec<u8>
{
    if key.len() >= key_size {
        Vec::from(&key[..= key_size])
    } else {
        aes::padding(key, key_size)
    }
}

fn aes_cipher(input_file: &str, output_file: &str, key: &[u8], key_size: usize, mode: AesMode)
{
    let mut text = Vec::<u8>::new();
    File::open(input_file)
        .expect(&format!("Unable to open file {}", &input_file))
        .read_to_end(&mut text)
        .expect(&format!("Unable to read file {}", &input_file));
    let key = match key_size {
        128 => {
            let mut key_128: [u8; 16] = [0u8; 16];
            key_128.copy_from_slice(&pad_key(key, 16));
            aes::AesKey::AesKey128(key_128)
        }
        192 => {
            let mut key_192: [u8; 24] = [0u8; 24];
            key_192.copy_from_slice(&pad_key(key, 24));
            aes::AesKey::AesKey192(key_192)
        }
        256 => {
            let mut key_256: [u8; 32] = [0u8; 32];
            key_256.copy_from_slice(&pad_key(key, 32));
            aes::AesKey::AesKey256(key_256)
        }
        _ => panic!("Unsupported key size {}", key_size),
    };
    match mode {
        AesMode::Enc => encrypt(key, &text, output_file),
        AesMode::Dec => decrypt(key, &text, output_file),
    }
}

fn main() 
{
    let args = Args::parse();
    let output_file = args.output.unwrap_or_else(||
        match args.mode {
            AesMode::Enc => args.file.to_string() + ".aes.enc",
            AesMode::Dec => String::from(args.file.trim_end_matches(".aes.enc")),
        }
    );
    let key = if !args.hex {
        Vec::from(args.key.as_bytes())
    } else {
        args.key.chars().collect::<Vec<char>>().chunks(2).map(|c| {
            u8::from_str_radix(&String::from_iter(c), 16).expect("Invalid hex string")
        }).collect::<Vec<u8>>()
    };
    aes_cipher(&args.file, &output_file, &key, args.key_size, args.mode);
}