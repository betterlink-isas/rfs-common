# rfs-common

Libraries and tools to manage ROSTER.FS filesystems, written in Rust

## `rfs`

A common library for ROSTER.FS utilities written in Rust

## `rfs-tools`

Tools for ROSTER.FS filesystems

### Tools

* `rfsdump` - Dumps all the nodes on a ROSTER.FS filesystem, printing their name, checksum, IV, offset, and encrypted size (optionally as JSON).

* `unrfs` - Decrypts and unpacks a ROSTER.FS filesystem

* `mkrfs` - Encrypts and packs files into a ROSTER.FS filesystem

All tools' arguments are parsed with [clap](https://crates.io/crates/clap), so you can simply run `<tool_name> -h` or `<tool_name> --help` to see the usage.