
# Installation

## Requirements

You need to install Rust in order to compile the source code.

> To build from source on **Windows**, you should first have installed the [MSVC Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).

### Linux, MacOS or another Unix-like OS

To download Rustup and install Rust, run the following in your terminal, then follow the on-screen instructions.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Windows

Download and run the following executable: [rustup-init.exe](https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe)

### Other ways to install Rust

If you prefer not to use the shell script, you may directly download rustup-init for the platform of your choice [here](https://forge.rust-lang.org/infra/other-installation-methods.html#other-ways-to-install-rustup).

## Building from source (recommended)

Once installed, you can install `crypt4gh` executing the following in your terminal:

```sh
cargo install crypt4gh
```

## Standalone binaries

In the [releases page](https://github.com/EGA-archive/crypt4gh-rust/releases/latest), You can find compiled binaries for:

- [Linux (x86_64-unknown-linux-gnu)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.2.0/crypt4gh-x86_64-unknown-linux-gnu)
- [OS X (x86_64-apple-darwin)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.2.0/crypt4gh-x86_64-apple-darwin)
- [Windows (x86_64-pc-windows-msvc)](https://github.com/EGA-archive/crypt4gh-rust/releases/download/v0.2.0/crypt4gh-x86_64-pc-windows-msvc.exe)

## Issues

If you have any issue with the installation please [create an issue on Github](https://github.com/EGA-archive/crypt4gh-rust/issues/new).
