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
use std::path::Path;

use clap::{crate_authors, crate_version, load_yaml, App, AppSettings, ArgMatches};
use crypt4gh::error::Crypt4GHError;
use crypt4gh::keys::{get_private_key, get_public_key};
use crypt4gh::{self, keys, Keys};
use itertools::Itertools;
use regex::Regex;
use rpassword::read_password_from_tty;

const DEFAULT_SK: &str = "C4GH_SECRET_KEY";
const PASSPHRASE: &str = "C4GH_PASSPHRASE";

fn parse_range(args: &ArgMatches) -> Result<(usize, Option<usize>), Crypt4GHError> {
	match args.value_of("range") {
		Some(range) => {
			// Capture regex <start-span>
			let range_regex = Regex::new(r"(?P<start>[\d]+)-?(?P<end>[\d]+)?").expect("Bad range regex");

			match range_regex.captures(range) {
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

fn retrieve_private_key(args: &ArgMatches, generate: bool) -> Result<Vec<u8>, Crypt4GHError> {
	let seckey_path = match args.value_of("sk") {
		Some(sk) => Some(sk.to_string()),
		None => std::env::var(DEFAULT_SK).ok(),
	};

	if generate && seckey_path.is_none() {
		let skey = keys::generate_private_key();
		log::info!("Generating Private Key: {:02x?}", skey.iter().format(""));
		Ok(skey)
	}
	else {
		let path = seckey_path.expect("Unable to extract the secret key");
		if !Path::new(&path).is_file() {
			return Err(Crypt4GHError::ReadSecretKeyFileError(Path::new(&path).into()));
		}

		let callback: Box<dyn Fn() -> Result<String, Crypt4GHError>> = match std::env::var(PASSPHRASE) {
			Ok(_) => {
				log::warn!("Warning: Using a passphrase in an environment variable is insecure");
				Box::new(|| std::env::var(PASSPHRASE).map_err(|e| Crypt4GHError::NoPassphrase(e.into())))
			},
			Err(_) => Box::new(|| {
				read_password_from_tty(Some(format!("Passphrase for {}: ", path).as_str()))
					.map_err(|e| Crypt4GHError::NoPassphrase(e.into()))
			}),
		};

		get_private_key(Path::new(&path), callback)
	}
}

fn build_recipients(args: &ArgMatches, sk: &[u8]) -> Result<HashSet<Keys>, Crypt4GHError> {
	match args.values_of("recipient_pk") {
		Some(pks) => pks
			.filter(|&pk| Path::new(pk).exists())
			.map(|pk| {
				Ok(Keys {
					method: 0,
					privkey: sk.to_vec(),
					recipient_pubkey: get_public_key(Path::new(pk))?,
				})
			})
			.collect(),
		None => Err(Crypt4GHError::NoRecipients),
	}
}

fn run_encrypt(args: &ArgMatches) -> Result<(), Crypt4GHError> {
	let (range_start, range_span) = parse_range(args)?;
	let seckey = retrieve_private_key(args, true)?;
	let recipient_keys = build_recipients(args, &seckey)?;

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

fn run_decrypt(args: &ArgMatches) -> Result<(), Crypt4GHError> {
	let sender_pubkey = match args.value_of("sender_pk") {
		Some(path) => Some(keys::get_public_key(Path::new(path))?),
		None => None,
	};

	let (range_start, range_span) = parse_range(args)?;

	let seckey = retrieve_private_key(args, false)?;

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

fn run_rearrange(args: &ArgMatches) -> Result<(), Crypt4GHError> {
	let (range_start, range_span) = parse_range(args)?;
	let seckey = retrieve_private_key(args, false)?;
	let pubkey = keys::get_public_key_from_private_key(&seckey)?;

	let keys = vec![Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey: pubkey,
	}];

	crypt4gh::rearrange(keys, &mut io::stdin(), &mut io::stdout(), range_start, range_span)
}

fn run_reencrypt(args: &ArgMatches) -> Result<(), Crypt4GHError> {
	let seckey = retrieve_private_key(args, false)?;
	let recipient_keys = build_recipients(args, &seckey)?;
	let trim = args.is_present("trim");

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

fn run_keygen(args: &ArgMatches) -> Result<(), Crypt4GHError> {
	// Prepare key files

	let seckey = Path::new(args.value_of("sk").expect("No sk value"));
	let pubkey = Path::new(args.value_of("pk").expect("No pk value"));

	for key in &[seckey, pubkey] {
		// If key exists and it is a file
		if key.is_file() {
			// Force overwrite?
			if !args.is_present("force") {
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
	let comment = args.value_of("comment");
	let do_crypt = !args.is_present("nocrypt");
	let passphrase_callback = move || {
		if do_crypt {
			read_password_from_tty(Some(format!("Passphrase for {}: ", seckey.display()).as_str()))
				.map_err(|e| Crypt4GHError::NoPassphrase(e.into()))
		}
		else {
			Ok(String::new())
		}
	};

	crypt4gh::keys::generate_keys(seckey, pubkey, passphrase_callback, comment)
}

fn run() -> Result<(), Crypt4GHError> {
	let yaml = load_yaml!("../app.yaml");
	let matches = App::from(yaml)
		.version(crate_version!())
		.author(crate_authors!())
		.global_setting(AppSettings::ArgRequiredElseHelp)
		.global_setting(AppSettings::ColorAlways)
		.global_setting(AppSettings::ColoredHelp)
		.get_matches();

	if std::env::var("RUST_LOG").is_err() {
		if matches.is_present("verbose") {
			std::env::set_var("RUST_LOG", "trace");
		}
		else {
			std::env::set_var("RUST_LOG", "warn");
		}
	}

	pretty_env_logger::init();

	match matches.subcommand() {
		Some(("encrypt", args)) => run_encrypt(args)?,
		Some(("decrypt", args)) => run_decrypt(args)?,
		Some(("rearrange", args)) => run_rearrange(args)?,
		Some(("reencrypt", args)) => run_reencrypt(args)?,
		Some(("keygen", args)) => run_keygen(args)?,
		_ => {},
	}

	Ok(())
}

fn main() {
	if let Err(err) = run() {
		log::error!("{}", err);
		std::process::exit(1);
	}
}
