#![allow(
	clippy::missing_errors_doc,
	clippy::missing_panics_doc,
	clippy::module_name_repetitions,
	clippy::must_use_candidate,
	clippy::cast_possible_truncation,
	clippy::similar_names,
	clippy::implicit_hasher,
	clippy::redundant_else
)]

use std::collections::HashSet;
use std::fs::remove_file;
use std::io;
use std::io::stdin;
use std::path::{Path, PathBuf};

use clap::Parser;
use cli::{Args, Command};
use crypt4gh::error::Crypt4GHError;
use crypt4gh::keys::{get_private_key, get_public_key};
use crypt4gh::{self, keys, Keys};
use itertools::Itertools;
use regex::Regex;
use rpassword::prompt_password;

mod cli;

const PASSPHRASE: &str = "C4GH_PASSPHRASE";

fn parse_range(arg: Option<String>) -> Result<(usize, Option<usize>), Crypt4GHError> {
	match arg {
		Some(range) => {
			// Capture regex <start-span>
			let range_regex = Regex::new(r"(?P<start>[\d]+)-?(?P<end>[\d]+)?").expect("Bad range regex");

			match range_regex.captures(&range) {
				Some(matched_range) => {
					// Get start
					let range_start = matched_range
						.name("start")
						.ok_or(Crypt4GHError::ParseRangeError)?
						.as_str()
						.parse::<usize>()
						.map_err(|_| Crypt4GHError::ParseRangeError)?;

					// Get span
					let range_span = match matched_range.name("end") {
						Some(end) => {
							let range_end = end
								.as_str()
								.parse::<usize>()
								.map_err(|_| Crypt4GHError::ParseRangeError)?;

							if range_start >= range_end {
								return Err(Crypt4GHError::ParseRangeError);
							}

							Some(range_end - range_start - 1)
						},
						None => None,
					};

					Ok((range_start, range_span))
				},
				None => Err(Crypt4GHError::ParseRangeError),
			}
		},
		None => Ok((0, None)),
	}
}

fn retrieve_private_key(sk: Option<PathBuf>, generate: bool) -> Result<Vec<u8>, Crypt4GHError> {
	let seckey_path = sk;

	if generate && seckey_path.is_none() {
		let skey = keys::generate_private_key()?;
		log::info!("Generating Private Key: {:02x?}", skey.iter().format(""));
		Ok(skey)
	}
	else {
		let path = seckey_path.expect("Unable to extract the secret key");
		if !path.is_file() {
			return Err(Crypt4GHError::ReadSecretKeyFileError(path));
		}

		let callback: Box<dyn Fn() -> Result<String, Crypt4GHError>> = match std::env::var(PASSPHRASE) {
			Ok(_) => {
				log::warn!("Warning: Using a passphrase in an environment variable is insecure");
				Box::new(|| std::env::var(PASSPHRASE).map_err(|e| Crypt4GHError::NoPassphrase(e.into())))
			},
			Err(_) => Box::new(|| {
				prompt_password(format!("Passphrase for {:?}: ", path))
					.map_err(|e| Crypt4GHError::NoPassphrase(e.into()))
			}),
		};

		get_private_key(path.to_owned(), callback)
	}
}

fn build_recipients(recipient_pk: &[PathBuf], sk: &[u8]) -> Result<HashSet<Keys>, Crypt4GHError> {
	if recipient_pk.is_empty() {
		Err(Crypt4GHError::NoRecipients)
	}
	else {
		recipient_pk
			.iter()
			.filter(|&pk| Path::new(pk).exists())
			.map(|pk| {
				Ok(Keys {
					method: 0,
					privkey: sk.to_vec(),
					recipient_pubkey: get_public_key(PathBuf::from(pk))?,
				})
			})
			.collect()
	}
}

fn run_encrypt(sk: Option<PathBuf>, recipient_pk: &[PathBuf], range: Option<String>) -> Result<(), Crypt4GHError> {
	let (range_start, range_span) = parse_range(range)?;
	let seckey = retrieve_private_key(sk, true)?;
	let recipient_keys = build_recipients(recipient_pk, &seckey)?;

	if recipient_keys.is_empty() {
		return Err(Crypt4GHError::NoRecipients);
	}

	crypt4gh::encrypt(
		&recipient_keys,
		&mut io::stdin(),
		&mut io::stdout(),
		range_start,
		range_span,
	)
}

fn run_decrypt(sk: Option<PathBuf>, sender_pk: Option<PathBuf>, range: Option<String>) -> Result<(), Crypt4GHError> {
	let sender_pubkey = match sender_pk {
		Some(path) => Some(keys::get_public_key(path)?),
		None => None,
	};

	let (range_start, range_span) = parse_range(range)?;

	let seckey = retrieve_private_key(sk, false)?;

	let keys = vec![Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey: vec![],
	}];

	crypt4gh::decrypt(
		&keys,
		&mut io::stdin(),
		&mut io::stdout(),
		range_start,
		range_span,
		&sender_pubkey,
	)
}

fn run_rearrange(sk: Option<PathBuf>, range: Option<String>) -> Result<(), Crypt4GHError> {
	let (range_start, range_span) = parse_range(range)?;
	let seckey = retrieve_private_key(sk, false)?;
	let pubkey = keys::get_public_key_from_private_key(&seckey)?;

	let keys = vec![Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey: pubkey,
	}];

	crypt4gh::rearrange(keys, &mut io::stdin(), &mut io::stdout(), range_start, range_span)
}

fn run_reencrypt(sk: Option<PathBuf>, recipient_pk: &[PathBuf], trim: bool) -> Result<(), Crypt4GHError> {
	let seckey = retrieve_private_key(sk, false)?;
	let recipient_keys = build_recipients(recipient_pk, &seckey)?;

	if recipient_keys.is_empty() {
		return Err(Crypt4GHError::NoRecipients);
	}

	let keys = vec![Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey: vec![],
	}];

	crypt4gh::reencrypt(&keys, &recipient_keys, &mut io::stdin(), &mut io::stdout(), trim)
}

fn run_keygen(sk: PathBuf, pk: PathBuf, comment: Option<String>, nocrypt: bool, force: bool) -> Result<(), Crypt4GHError> {
	// Prepare key files

	let seckey = sk;
	let pubkey = pk;

	for key in &[seckey.to_owned(), pubkey.to_owned()] {
		// If key exists and it is a file
		if key.is_file() {
			// Force overwrite?
			if !force {
				eprint!("{} already exists. Do you want to overwrite it? (y/n): ", key.display());
				let mut input = String::new();
				stdin()
					.read_line(&mut input)
					.map_err(|e| Crypt4GHError::NotEnoughInput(1, e.into()))?;
				if input.trim() != "y" {
					log::info!("Ok. Exiting.");
					return Ok(());
				}
			}
			remove_file(key).unwrap_or_else(|_| panic!("Unable to remove key file (ERROR = {:?})", key));
		}
	}

	// Comment
	let comment = comment;
	let do_crypt = !nocrypt;
	let seckey_display = PathBuf::from(&seckey);

	let passphrase = {
		if do_crypt {
			prompt_password(format!("Passphrase for {}: ", seckey_display.display()))
				.map_err(|e| Crypt4GHError::NoPassphrase(e.into()))
	
		} else {
			Ok(String::new())
		}
	};

	crypt4gh::keys::generate_keys(seckey, pubkey, passphrase, comment)
}

fn run() -> Result<(), Crypt4GHError> {
	let matches = Args::parse();

	if std::env::var("RUST_LOG").is_err() {
		if matches.verbose {
			std::env::set_var("RUST_LOG", "trace");
		}
		else {
			std::env::set_var("RUST_LOG", "warn");
		}
	}

	pretty_env_logger::init();

	match matches.subcommand {
		Command::Encrypt {
			sk,
			recipient_pk,
			range,
		} => run_encrypt(sk, &recipient_pk, range)?,
		Command::Decrypt { sk, sender_pk, range } => run_decrypt(sk, sender_pk, range)?,
		Command::Rearrange { sk, range } => run_rearrange(sk, range)?,
		Command::Reencrypt { sk, recipient_pk, trim } => run_reencrypt(sk, &recipient_pk, trim)?,
		Command::Keygen {
			sk,
			pk,
			comment,
			nocrypt,
			force,
		} => run_keygen(sk, pk, comment, nocrypt, force)?,
	}

	Ok(())
}

fn main() {
	if let Err(err) = run() {
		log::error!("{}", err);
		std::process::exit(1);
	}
}
