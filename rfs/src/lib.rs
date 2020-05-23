extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate bincode;

extern crate openssl;

use openssl::symm::Cipher;
use openssl::symm;
use openssl::error::ErrorStack;

/// A ROSTER.FS node
///
/// # Fields
///
/// * `magic` - The three-byte magic number
///
/// * `name` - The name of the node
///
/// * `checksum` - The SHA256 checksum of the decrypted contents of the node
///
/// * `iv` - The AES-CBC IV used for encryption and decryption
///
/// * `offset` - The offset in the filesystem at which the encrypted data for this node is stored
///
/// * `encrypted_size` - The size of the encrypted node
///
#[derive(Serialize, Deserialize)]
pub struct RFSNode {
    pub magic: [u8; 3],
    pub name: String,
    pub checksum: [u8; 32],
    pub iv: [u8; 16],
    pub offset: usize,
    pub encrypted_size: usize
}

/// Decrypts a ROSTER.FS node
///
/// # Arguments
///
/// * `node` - The RFSNode to decrypt
///
/// * `key` - The key to decrypt with
///
/// * `data` - The data to decrypt
///
pub fn decrypt_node(node: &RFSNode, key: &[u8; 16], data: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_cbc();
    let iv = node.iv;
    symm::decrypt(cipher, key, Some(&iv), data)
}

/// Encrypts a ROSTER.FS node and sets the correct `encrypted_size` on the node
/// 
/// # Arguments
///
/// * `node` - The RFSNode to encrypt
///
/// * `key` - The key to encrypt with
///
/// * `data` - The data to encrypt
///
pub fn encrypt_node(node: &mut RFSNode, key: &[u8; 16], data: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_cbc();
    let iv = node.iv;
    let ciphertext = symm::encrypt(cipher, key, Some(&iv), data)?;

    node.encrypted_size = ciphertext.len();

    Ok(ciphertext)
}

/// Gets the encrypted data for a node
///
/// # Arguments
///
/// * `node` - The RFSNode to get the data from
///
/// * `raw_fs` - The whole filesystem as bytes
///
pub fn get_data<'a>(node: &RFSNode, raw_fs: &'a Vec<u8>) -> &'a [u8] {
    let begin = node.offset;
    let end = node.offset + node.encrypted_size;
    &raw_fs[begin..end]
}

/// Parses a raw binary filesystem to a `Vec` of `RFSNode`s.
///
/// # Arguments
///
/// * `raw_fs` - The raw binary filesystem
///
pub fn parse_fs(raw_fs: &Vec<u8>) -> Result<Vec<RFSNode>, Box<bincode::ErrorKind>> {
    let mut def_conf = bincode::config();
    let conf = def_conf.big_endian();

    conf.deserialize(&raw_fs)
}

/// Serializes a `Vec` of `RFSNode`s into a raw binary filesystem.
pub fn serialize_fs(fs: &Vec<RFSNode>) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    let mut def_conf = bincode::config();
    let conf = def_conf.big_endian();
    
    conf.serialize(fs)
}

/// Serializes single node into its binary representation
pub fn serialize_node(node: &RFSNode) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    let mut def_conf = bincode::config();
    let conf = def_conf.big_endian();
    
    conf.serialize(node)
}