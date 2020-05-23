#[macro_use]
extern crate clap;

extern crate openssl;
extern crate rfs;

use rfs::RFSNode;

use std::path::Path;
use std::process::exit;
use std::fs;
use std::io::prelude::*;
use std::fs::File;

use openssl::sha;
use openssl::rand;

fn main() {
  let matches = clap_app!(mkrfs => 
    (version: "1.0.0")
    (author: "The Puzzlemaker <tpzker@thepuzzlemaker.info>")
    (about: "Encrypts and packs files into a ROSTER.FS filesystem")
    (@arg key: +required -K --key +takes_value "A hex-encoded key to use")
    (@arg out: -o --out +takes_value "The directory to output to (default: out.rfs)")
    (@arg verbose: -v --verbose "Enable verbose output")
    (@arg FILES: +required... "The input files to encrypt and pack")
    (@setting TrailingVarArg)
  ).get_matches();

  let key_hex = matches.value_of("key").unwrap();
  let mut key: [u8; 16] = [0; 16];
  hex::decode_to_slice(key_hex, &mut key).expect("Could not hex decode key");
  let out = matches.value_of("out").unwrap_or("out.rfs");
  let verbose = matches.is_present("verbose");
  let files: Vec<&str> = matches.values_of("FILES").unwrap().collect();
  let out_path = Path::new(out);

  if out_path.exists() {
    eprintln!("ERROR: Output file '{}' already exists!", out_path.display());
    exit(-1);
  }

  let mut nodes: Vec<RFSNode> = Vec::new();
  let mut data: Vec<Vec<u8>> = Vec::new();

  for file in files.iter() {
    let path = Path::new(file);
    if !path.exists() {
      eprintln!("ERROR: Input file '{}' does not exist!", path.display());
      exit(-1);
    }

    let cont = fs::read(path).expect(&format!("Failed to open input file '{}'", path.display()));

    let mut name = match path.to_str() {
      None => {
        eprintln!("ERROR: Failed to decode path '{}' to UTF-8.", path.display());
        exit(-1);
      },
      Some(n) => n.to_string()
    };

    if name.chars().next().unwrap() != '/' {
      name = format!("/{}", name);
    }

    let mut hasher = sha::Sha256::new();
    hasher.update(&cont);
    let hash = hasher.finish();

    let mut iv: [u8; 16] = [0; 16];
    rand::rand_bytes(&mut iv).expect("Failed to generate random data");

    let mut node = RFSNode {
      magic: *b"RFS",
      name: name.clone(),
      checksum: hash,
      iv,
      offset: 0,
      encrypted_size: 0
    };

    let encrypted_data = rfs::encrypt_node(&mut node, &key, &cont.iter().cloned().collect()).expect(&format!("Failed to encrypt node '{}'", name));

    if verbose {
      println!("Encrypted node '{}' with IV '0x{}' (size {})", name, hex::encode(node.iv), node.encrypted_size);
    }

    nodes.push(node);
    data.push(encrypted_data);

  }

  let serialized_nodes = rfs::serialize_fs(&nodes).expect("Failed to serialize filesystem");
  let mut new_nodes: Vec<RFSNode> = Vec::new();
  let mut new_index = serialized_nodes.len();
  for index in 0..data.len() {
    let node = &nodes[index];
    let new_node: RFSNode;
    let current_size = data[index].len();
    new_node = RFSNode {
      offset: new_index,
      name: node.name.clone(),
      ..*node
    };
    new_index = new_index + current_size;
    new_nodes.push(new_node);
  }

  let mut final_vec: Vec<u8> = Vec::new();

  final_vec.extend(rfs::serialize_fs(&new_nodes).expect("Failed to serialize filesystem"));
  
  for bytearr in data {
    final_vec.extend(bytearr);
  }
  
  let mut file = File::create(out_path).expect("Failed to create output file");

  file.write_all(&final_vec).expect("Failed to write to output file");

  if verbose {
    println!("Wrote {} bytes to '{}'", final_vec.len(), out_path.display());
  }

}