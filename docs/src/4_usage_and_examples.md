
# Usage & Examples

The usual `--help` flag shows you the different options that the tool accepts.

```text
$ crypt4gh --help

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

## Keygen

```text
$ crypt4gh keygen --help

crypt4gh-keygen
Utility to create Crypt4GH-formatted keys.

USAGE:
    crypt4gh keygen [FLAGS] [OPTIONS]

FLAGS:
    -f               Overwrite the destination files
    -h, --help       Prints help information
        --nocrypt    Do not encrypt the private key. Otherwise it is encrypted in the Crypt4GH key
                     format (See https://crypt4gh.readthedocs.io/en/latest/keys.html)
    -V, --version    Prints version information

OPTIONS:
    -C, --comment <comment>    Key's Comment
        --pk <keyfile>         Curve25519-based Public key [env: C4GH_PUBLIC_KEY] [default:
                               ~/.c4gh/key.pub]
        --sk <keyfile>         Curve25519-based Private key [env: C4GH_SECRET_KEY] [default:
                               ~/.c4gh/key]
```

Generate a Crypt4GH Key for Alice and Bob.

```sh
crypt4gh keygen --sk alice.sec --pk alice.pub
```

```sh
crypt4gh keygen --sk bob.sec --pk bob.pub
```

## Encrypt

```text
$ crypt4gh encrypt --help

crypt4gh-encrypt
Encrypts the input using your (optional) secret key and the public key of the recipient.

USAGE:
    crypt4gh encrypt [OPTIONS] --recipient_pk <path>...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --range <start-end>         Byte-range either as  <start-end> or just <start> (Start
                                    included, End excluded)
        --recipient_pk <path>...    Recipient's Curve25519-based Public key
        --sk <path>                 Curve25519-based Private key [env: C4GH_SECRET_KEY]
```

Alice encrypts a file `file.txt` for Bob:

```sh
crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub < original_file.txt > encrypted_file.c4gh
```

## Decrypt

```text
$ crypt4gh decrypt --help

crypt4gh-decrypt
Decrypts the input using your secret key and the (optional) public key of the sender.

USAGE:
    crypt4gh decrypt [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --sender_pk <path>    Peer's Curve25519-based Public key to verify provenance (akin to
                              signature)
        --sk <path>           Curve25519-based Private key. [env: C4GH_SECRET_KEY]
```

Bob decrypts an encrypted file:

```sh
crypt4gh decrypt --sk bob.sec < encrypted_file.c4gh > decrypted_file.txt
```

If Bob wants to, optionally, verify that the message indeed comes from Alice, he needs to fetch Alice's public key via another trusted channel. He can then decrypt and check the provenance of the file with:

```sh
crypt4gh decrypt --sk bob.sec --sender_pk alice.pub < encrypted_file.c4gh > decrypted_file.txt
```

## Reencrypt

```text
$ crypt4gh reencrypt --help

crypt4gh-reencrypt
Decrypts the input using your (optional) secret key and then it reencrypts it using the public key
of the recipient.

USAGE:
    crypt4gh reencrypt [FLAGS] [OPTIONS] --recipient_pk <path>...

FLAGS:
    -h, --help       Prints help information
    -t, --trim       Keep only header packets that you can decrypt
    -V, --version    Prints version information

OPTIONS:
        --recipient_pk <path>...    Recipient's Curve25519-based Public key
        --sk <path>                 Curve25519-based Private key [env: C4GH_SECRET_KEY]
```

Bob reencrypts a file for alice and for himself:

```sh
crypt4gh reencrypt --sk bob.sec --recipient_pk alice.pub bob.pub < encrypted_file.c4gh > reencrypted_file.c4gh
```

## Rearrange

```text
$ crypt4gh rearrange --help

crypt4gh-rearrange
Rearranges the input according to the edit list packet.

USAGE:
    crypt4gh rearrange [OPTIONS] --range <start-end>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included,
                               End excluded)
        --sk <path>            Curve25519-based Private key [env: C4GH_SECRET_KEY]
```

Bob rearranges an encrypted file with the bytes from 65535 to 131074:

```sh
crypt4gh rearrange --sk bob.sec --range 65535-131074 < encrypted_file.c4gh > rearranged_file.c4gh
```
