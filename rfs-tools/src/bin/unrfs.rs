#[macro_use]
extern crate clap;

extern crate openssl;

extern crate rfs;
extern crate hex;

use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::fs;
use std::fs::File;
use std::io::prelude::*;

use openssl::sha;

fn main() {
    let matches = clap_app!(unrfs => 
        (version: "1.0.0")
        (author: "The Puzzlemaker <tpzker@thepuzzlemaker.info>")
        (about: "Decrypts and unpacks a ROSTER.FS filesystem into regular files")
        (@arg key: +required -K --key +takes_value "A hex-encoded key to use")
        (@arg out: -o --out +takes_value "The directory to output to (default: ./rfs_root/)")
        (@arg FILE: +required "The input file to decrypt and unpack")
        (@arg verbose: -v --verbose "Whether or not to list each file as it is decrypted")
    ).get_matches();

    let key_hex = matches.value_of("key").unwrap();
    let mut key: [u8; 16] = [0; 16];
    hex::decode_to_slice(key_hex, &mut key).expect("Could not hex decode key");
    let out = matches.value_of("out").unwrap_or("rfs_root");
    let file = matches.value_of("FILE").unwrap();
    let verbose = matches.is_present("verbose");

    let file_path = Path::new(file);
    let out_path_base = Path::new(out);

    if !file_path.exists() {
        eprintln!("ERROR: Input file '{}' does not exist!", file_path.display());
        exit(-1);
    }

    if out_path_base.is_file() {
        eprintln!("ERROR: Output directory '{}' is a file!", out_path_base.display());
    }

    if !out_path_base.exists() {
        fs::create_dir_all(out_path_base).expect("Failed to create output directory");
    }

    let file_cont = fs::read(file_path).expect("Failed to read input file");
    
    let fs = rfs::parse_fs(&file_cont).expect("Failed to parse filesystem");

    for node in fs.iter() {
        let data_enc = rfs::get_data(&node, &file_cont).iter().cloned().collect();
        let data_raw = rfs::decrypt_node(&node, &key, &data_enc).expect("Failed to decrypt data");
        let new_file_path: PathBuf = out_path_base.join(Path::new(&format!(".{}", node.name)));
        let mut file = File::create(new_file_path.as_path()).expect("Failed to create file");
        if verbose {
            println!("Decrypted {}", new_file_path.display());
        }
        file.write_all(&data_raw).expect("Failed to write data to file");
        let mut hasher = sha::Sha256::new();
        hasher.update(&data_raw);
        let hash = hasher.finish();
        if hash == node.checksum {
            if verbose {
                println!("Verified {}", new_file_path.display());
            }
        } else {
            eprintln!("WARNING: Failed to verify file '{}'\nGot      0x{}\nExpected 0x{}", new_file_path.display(), hex::encode(hash), hex::encode(node.checksum));
        }
    }
}