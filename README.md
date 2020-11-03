# crypt4gh-rust

[![Crates.io](https://img.shields.io/crates/v/crypt4gh)](https://crates.io/crates/crypt4gh)
[![Docs.rs](https://docs.rs/crypt4gh/badge.svg)](https://docs.rs/gym/latest/crypt4gh)
[![codecov](https://codecov.io/gh/EGA-archive/crypt4gh-rust/branch/master/graph/badge.svg)](https://codecov.io/gh/EGA-archive/crypt4gh-rust)
![GitHub](https://img.shields.io/github/license/EGA-archive/crypt4gh-rust)

Rust implementation for the Crypt4GH encryption format.

## CLI

### Installation

#### From source

> Requirements: [Rust](https://www.rust-lang.org/tools/install)

```sh
cargo install --git https://github.com/EGA-archive/Crypt4gh-rust.git
```

#### Binaries

In the [releases page](https://github.com/EGA-archive/Crypt4gh-rust/releases/latest), You can find compiled binaries for:

- Linux (.deb, .rpm)
- OS X
- Windows (.exe)

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
    decrypt
    encrypt
    help         Prints this message or the help of the given subcommand(s)
    rearrange
    reencrypt  
```

### Example

```sh
# TODO
```

## Library

### Library installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
crypt4gh = "0.1.0"
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

## Testing (devs only)

```sh
cargo test --release
```

## Troubleshooting

To build from source on Windows, you should first have installed the [MSVC Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).