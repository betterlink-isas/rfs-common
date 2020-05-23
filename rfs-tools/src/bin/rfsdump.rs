extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate clap;

extern crate rfs;

use std::path::Path;
use std::process::exit;
use std::fs;

use rfs::RFSNode;

#[derive(Serialize, Deserialize, Debug)]
struct RFSNodeHuman {
    name: String,
    checksum: String,
    iv: String,
    offset: usize,
    encrypted_size: usize
}

fn raw_node_to_human(node: &RFSNode) -> RFSNodeHuman {
    let checksum = format!("0x{}", hex::encode(node.checksum));
    let iv = format!("0x{}", hex::encode(node.iv));

    RFSNodeHuman {
        name: node.name.to_string(),
        checksum,
        iv,
        offset: node.offset,
        encrypted_size: node.encrypted_size
    }
}

fn raw_fs_to_human(fs: &Vec<RFSNode>) -> Vec<RFSNodeHuman> {
    fs.iter().map(|node| raw_node_to_human(node)).collect()
}

fn main() {
    let matches = clap_app!(rfsdump => 
        (version: "0.1.0")
        (author: "The Puzzlemaker <tpzker@thepuzzlemaker.info>")
        (about: "Dumps all the nodes of a binary ROSTER.FS filesystem as JSON or a greppable text format")
        (@arg pretty: -p --pretty "Whether or not to pretty-print the JSON")
        (@arg json: -j --json "Whether or not to output JSON")
        (@arg INPUT: +required "Sets the input file to dump")
    ).get_matches();

    let pretty = matches.is_present("pretty");
    let json = matches.is_present("json");
    let file_path = Path::new(matches.value_of("INPUT").unwrap());

    if !file_path.exists() {
        println!("ERROR: Input file '{}' does not exist!", file_path.display());
        exit(-1);
    }

    let file_cont = fs::read(file_path).expect("Failed to read input file");

    let fs_raw: Vec<RFSNode> = rfs::parse_fs(&file_cont).expect("Failed to parse filesystem");

    let fs: Vec<RFSNodeHuman> = raw_fs_to_human(&fs_raw);

    let str_rep: String;

    if json {
        if pretty {
            str_rep = serde_json::to_string_pretty(&fs).expect("Failed to serialize filesystem");
        } else {
            str_rep = serde_json::to_string(&fs).expect("Failed to serialize filesystem");
        }
        println!("{}", str_rep);
    } else {
        for node in fs.iter() {
            println!("{}", node.name);
            println!("|- Checksum: {}", node.checksum);
            println!("|- IV: {}", node.iv);
            println!("|- Offset: {}, Size: {}", node.offset, node.encrypted_size);
        }
    }

    


}