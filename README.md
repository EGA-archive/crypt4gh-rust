# crypt4gh-rust

[![Crates.io](https://img.shields.io/crates/v/crypt4gh)](https://crates.io/crates/crypt4gh)
[![Docs.rs](https://docs.rs/crypt4gh/badge.svg)](https://docs.rs/crypt4gh/latest/crypt4gh)
[![codecov](https://codecov.io/gh/EGA-archive/Crypt4gh-rust/branch/main/graph/badge.svg?token=MS2512UglC)](https://codecov.io/gh/EGA-archive/Crypt4gh-rust)
![GitHub](https://img.shields.io/github/license/EGA-archive/crypt4gh-rust)

Rust implementation for the Crypt4GH encryption format.

## CLI

### Installation

#### From source

> Requirements: [Rust](https://www.rust-lang.org/tools/install)

```sh
cargo install crypt4gh
```

#### Binaries

In the [releases page](https://github.com/EGA-archive/crypt4gh-rust/releases/latest), You can find compiled binaries for:

- [Linux (x86_64-unknown-linux-gnu)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.1.1/crypt4gh-x86_64-unknown-linux-gnu)
- [OS X (x86_64-apple-darwin)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.1.1/crypt4gh-x86_64-apple-darwin)
- [Windows (x86_64-pc-windows-msvc)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.1.1/crypt4gh-x86_64-pc-windows-msvc.exe)

### Usage

```text
Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

USAGE:
    crypt4gh [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -v, --verbose    Sets the level of verbosity
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt      Decrypts the input using your secret key and the (optional) public key of the sender.
    encrypt      Encrypts the input using your (optional) secret key and the public key of the recipient.
    help         Prints this message or the help of the given subcommand(s)
    keygen       Utility to create Crypt4GH-formatted keys.
    rearrange    Rearranges the input according to the edit list packet.
    reencrypt    Decrypts the input using your (optional) secret key and then it reencrypts it using the
                 public key of the recipient.
```

### Example

Alice and Bob generate both a pair of public/private keys.

```sh
crypt4gh keygen --sk alice.sec --pk alice.pub
crypt4gh keygen --sk bob.sec --pk bob.pub
```

Bob encrypts a file for Alice:

```sh
crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh
```

Alice decrypts the encrypted file:

```sh
crypt4gh decrypt --sk alice.sec < file.c4gh
```

## Library

### Library installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
crypt4gh = "0.1.1"
```

### Usage (in Rust)

Use the exposed functions:

```rust
pub fn encrypt(
    recipient_keys: &HashSet<Keys>,
    mut read_buffer: impl Read,
    write_callback: fn(&[u8]) -> Result<()>,
    range_start: usize,
    range_span: Option<usize>
) -> Result<()>

pub fn decrypt(
    keys: Vec<Keys>,
    mut read_buffer: impl Read,
    write_callback: fn(&[u8]) -> Result<()>,
    range_start: usize,
    range_span: Option<usize>,
    sender_pubkey: Option<Vec<u8>>,
) -> Result<()>

pub fn reencrypt(
    keys: Vec<Keys>,
    recipient_keys: HashSet<Keys>,
    mut read_buffer: impl Read,
    write_callback: fn(&[u8]) -> Result<()>,
    trim: bool,
) -> Result<()>

pub fn rearrange(
    keys: Vec<Keys>,
    mut read_buffer: impl Read,
    write_callback: fn(&[u8]) -> Result<()>,
    range_start: usize,
    range_span: Option<usize>,
) -> Result<()>
```

## Documentation

To learn more about Crypt4GH, see [the official documentation](https://crypt4gh.readthedocs.io/en/latest/).

## Troubleshooting

To build from source on Windows, you should first have installed the [MSVC Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).
