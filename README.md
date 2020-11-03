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

## Troubleshooting

To build from source on Windows, you should first have installed the [MSVC Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).

## Testing (devs only)

```sh
cargo test --release
```

### Crypt4GH testsuite

We run the following tests:

These tests treat the system as a black box, only checking the expected output for a given input.

We use 2 users: Alice and Bob.

#### Full file Encryption/Decryption

We use a `testfile` containing the sequence of letters `abcd`, where each letter is repeated 65536 times.

- [x] Bob encrypts a 10MB file for Alice, and Alice decrypts it. Expected outcome: Alice reads the same content as Bob had.

- [x] Bob encrypts the testfile for Alice, and Alice decrypts it. Expected outcome: Alice reads the same content as testfile.

- [x] Bob encrypts the testfile for himself. Bob takes the resulting file and only changes the recipient to be Alice. Alice decrypts what she receives. Expected outcome: Alice reads the same content as testfile.

#### Segmenting an encrypted file

We use the testfile and Bob encrypts it for himself.

- [x] Bob encrypts only the "b"'s from the testfile for Alice, using the `--range` flag. Alice decrypts what she receives. Expected outcome: Alice reads 65536 "b"s.

- [x] Bob rerranges the encrypted file using the `--range 65536-131073` flag, to only the "b"s. Bob takes the resulting file and only changes the recipient to be Alice. Alice decrypts what she receives. Expected outcome: Alice reads 65536 "b"s.
  
- [x] Bob rerranges the encrypted file using the `--range 65535-131074` flag, for Alice, to match one "a", all the "b"s, and one "c". Expected outcome: Alice reads one "a", 65536 "b"s and one "c".

- [x] Bob sends the secret message `Let's have beers in the sauna! or Dinner at 7pm?` to Alice. The message is buried in the middle of some random data. Alice decrypts what she receives. Expected outcome: Alice reads `Let's have beers in the sauna! or Dinner at 7pm?`.

#### Using SSH keys

- [x] Bob encrypts a 10MB file for Alice, using his own SSH keypair, and Alice decrypts it, using her Crypt4GH keypair. Expected outcome: Alice reads the same content as Bob had.

- [x] Bob encrypts a 10MB file for Alice, using his own Crypt4GH keypair, and Alice decrypts it, using her SSH keypair. Expected outcome: Alice reads the same content as testfile.

- [x] Bob encrypts a 10MB file for Alice, and Alice decrypts it, both using their SSH keypair. Expected outcome: Alice reads the same content as testfile.

#### Multiple recipients

- [x] Bob sends the testfile secretly to himself and Alice. Expected outcome: They both can read the same content as Bob had.

- [x] Bob encrypts the testfile for himself and reencrypts it for himself and Alice. Expected outcome: They both can read the same content as Bob had.
