
# Crypt4GH utility

## Introduction

Bob wants to send a message to Alice, containing sensitive data. Bob uses [Crypt4GH, the Global Alliance approved secure method for sharing human genetic data](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/)

crypt4gh, a Rust tool to encrypt, decrypt or re-encrypt files, according to the [GA4GH encryption file format](http://samtools.github.io/hts-specs/crypt4gh.pdf). [![How Crypt4GH works](https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png)](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/)

## Basic example

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
