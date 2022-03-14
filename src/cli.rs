use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
	/// Encrypts the input using your (optional) secret key and the public key of the recipient.
	Encrypt {
		/// Curve25519-based Private key
		#[clap(long, env = "C4GH_SECRET_KEY")]
		sk: Option<PathBuf>,

		/// Recipient's Curve25519-based Public key
		#[clap(long = "recipient_pk", multiple_values = true)]
		recipient_pk: Vec<PathBuf>,

		/// Byte-range either as  <start-end> or just <start> (Start included, End excluded)
		#[clap(long)]
		range: Option<String>,
	},
	/// Decrypts the input using your secret key and the (optional) public key of the sender.
	Decrypt {
		/// Curve25519-based Private key
		#[clap(long, env = "C4GH_SECRET_KEY")]
		sk: Option<PathBuf>,

		/// Peer's Curve25519-based Public key to verify provenance (akin to signature)
		#[clap(long)]
		sender_pk: Option<PathBuf>,

		/// Byte-range either as  <start-end> or just <start> (Start included, End excluded)
		#[clap(long)]
		range: Option<String>,
	},
	/// Rearranges the input according to the edit list packet.
	Rearrange {
		/// Curve25519-based Private key
		#[clap(long, env = "C4GH_SECRET_KEY")]
		sk: Option<PathBuf>,

		/// Byte-range either as  <start-end> or just <start> (Start included, End excluded)
		#[clap(long)]
		range: Option<String>,
	},
	/// Decrypts the input using your (optional) secret key and then it reencrypts it using the public key of the recipient.
	Reencrypt {
		/// Curve25519-based Private key
		#[clap(long, env = "C4GH_SECRET_KEY")]
		sk: Option<PathBuf>,

		/// Recipient's Curve25519-based Public key
		#[clap(long = "recipient_pk", multiple_values = true)]
		recipient_pk: Vec<PathBuf>,

		/// Keep only header packets that you can decrypt
		#[clap(short, long)]
		trim: bool,
	},
	/// Utility to create Crypt4GH-formatted keys.
	Keygen {
		/// Curve25519-based Private key
		#[clap(long, env, default_value = "~/.c4gh/key")]
		sk: PathBuf,

		/// Curve25519-based Public key
		#[clap(long, env, default_value = "~/.c4gh/key.pub")]
		pk: PathBuf,

		/// Key's Comment
		#[clap(short, long)]
		comment: Option<String>,

		/// Do not encrypt the private key. Otherwise it is encrypted in the Crypt4GH key format (See https://crypt4gh.readthedocs.io/en/latest/keys.html)
		#[clap(long)]
		nocrypt: bool,

		/// Overwrite the destination files
		#[clap(short, long)]
		force: bool,
	},
}

/// Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.
#[derive(clap::Parser)]
#[clap(about, version, author)]
pub struct Args {
	/// Sets the level of verbosity
	#[clap(short, long)]
	pub verbose: bool,

	#[clap(subcommand)]
	pub subcommand: Command,
}
