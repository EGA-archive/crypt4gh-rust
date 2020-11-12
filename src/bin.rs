use anyhow::Result;
use anyhow::{anyhow, bail};
use clap::{crate_authors, crate_version, load_yaml, App, AppSettings, ArgMatches};
use crypt4gh::{self, Keys};
use keys::{get_private_key, get_public_key};
use pretty_env_logger::{self};
use regex::Regex;
use rpassword::read_password_from_tty;
use std::{collections::HashSet, fs::remove_file, io, io::stdin, path::Path};

pub mod keys;

const DEFAULT_SK: &str = "C4GH_SECRET_KEY";
const PASSPHRASE: &str = "C4GH_PASSPHRASE";

fn parse_range(args: &ArgMatches) -> Result<(usize, Option<usize>)> {
	match args.value_of("range") {
		Some(range) => {
			// Capture regex <start-span>
			let range_regex = Regex::new(r"(?P<start>[\d]+)-?(?P<end>[\d]+)?")?;

			match range_regex.captures(range) {
				Some(matched_range) => {
					// Get start
					let range_start = matched_range
						.name("start")
						.ok_or_else(|| anyhow!("Unable to parse the start of the range"))?
						.as_str()
						.parse::<usize>()
						.map_err(|_| anyhow!("Unable to parse range to an integer (u32)"))?;

					// Get span
					let range_span = match matched_range.name("end") {
						Some(end) => {
							let range_end = end
								.as_str()
								.parse::<usize>()
								.map_err(|_| anyhow!("Unable to parse range to an integer (u32)"))?;

							if range_start >= range_end {
								return Err(anyhow!("Invalid range: from {} to {}", range_start, range_end));
							}

							Some(range_end - range_start - 1)
						},
						None => None,
					};

					Ok((range_start, range_span))
				},
				None => Err(anyhow!("Unable to parse range: {}", range)),
			}
		},
		None => Ok((0, None)),
	}
}

fn retrieve_private_key(args: &ArgMatches, generate: bool) -> Result<Vec<u8>> {
	let seckey_path = match args.value_of("sk") {
		Some(sk) => Some(sk.to_string()),
		None => std::env::var(DEFAULT_SK).ok(),
	};

	if generate && seckey_path.is_none() {
		let skey = keys::generate_private_key();
		log::info!("Generating Private Key: {:02x?}", skey);
		Ok(skey)
	}
	else {
		let path = seckey_path.expect("Unable to extract the secret key");
		if !Path::new(&path).is_file() {
			bail!("Secret key not found: {}", path);
		}

		let callback: Box<dyn Fn() -> Result<String>> = match std::env::var(PASSPHRASE) {
			Ok(_) => {
				log::warn!("Warning: Using a passphrase in an environment variable is insecure");
				Box::new(|| {
					std::env::var(PASSPHRASE).map_err(|e| {
						anyhow!(
							"Unable to get the passphrase from the env variable C4GH_PASSPHRASE ({})",
							e
						)
					})
				})
			},
			Err(_) => Box::new(|| {
				read_password_from_tty(Some(format!("Passphrase for {}: ", path).as_str()))
					.map_err(|e| anyhow!("Unable to read password from TTY: {}", e))
			}),
		};

		get_private_key(&Path::new(&path), callback)
	}
}

fn build_recipients(args: &ArgMatches, sk: &[u8]) -> Result<HashSet<Keys>> {
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
		None => Err(anyhow!("Missing recipient public key(s)")),
	}
}

fn run() -> Result<()> {
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
		// Encrypt
		Some(("encrypt", args)) => {
			let (range_start, range_span) = parse_range(args)?;
			let seckey = retrieve_private_key(args, true)?;
			let recipient_keys = build_recipients(args, &seckey)?;

			if recipient_keys.is_empty() {
				return Err(anyhow!("No Recipients' Public Key found"));
			}

			crypt4gh::encrypt(
				&recipient_keys,
				&mut io::stdin(),
				&mut io::stdout(),
				range_start,
				range_span,
			)?;
		},

		// Decrypt
		Some(("decrypt", args)) => {
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
				sender_pubkey,
			)?;
		},

		// Rearrange
		Some(("rearrange", args)) => {
			let (range_start, range_span) = parse_range(args)?;
			let seckey = retrieve_private_key(args, false)?;
			let scalar = sodiumoxide::crypto::scalarmult::Scalar::from_slice(&seckey[0..32])
				.ok_or_else(|| anyhow!("Unable to extract public key"))?;
			let pubkey = sodiumoxide::crypto::scalarmult::scalarmult_base(&scalar).0;

			let keys = vec![Keys {
				method: 0,
				privkey: seckey,
				recipient_pubkey: pubkey.to_vec(),
			}];

			crypt4gh::rearrange(keys, &mut io::stdin(), &mut io::stdout(), range_start, range_span)?;
		},

		// Reencrypt
		Some(("reencrypt", args)) => {
			let seckey = retrieve_private_key(args, false)?;
			let recipient_keys = build_recipients(args, &seckey)?;

			if recipient_keys.is_empty() {
				return Err(anyhow!("No Recipients' Public Key found"));
			}

			let keys = vec![Keys {
				method: 0,
				privkey: seckey,
				recipient_pubkey: vec![],
			}];

			let trim = matches.is_present("trim");

			crypt4gh::reencrypt(keys, recipient_keys, &mut io::stdin(), &mut io::stdout(), trim)?;
		},

		Some(("keygen", args)) => {
			// Prepare key files

			let seckey = Path::new(args.value_of("sk").ok_or_else(|| anyhow!("No sk path"))?);
			let pubkey = Path::new(args.value_of("pk").ok_or_else(|| anyhow!("No pk path"))?);

			for key in [seckey, pubkey].iter() {
				// If key exists and it is a file
				if key.is_file() {
					// Force overwrite?
					if !args.is_present("force") {
						eprint!("{} already exists. Do you want to overwrite it? (y/n): ", key.display());
						let mut input = String::new();
						stdin()
							.read_line(&mut input)
							.map_err(|e| anyhow!("Unable to read from stdin (ERROR = {})", e))?;
						if input.trim() != "y" {
							log::info!("Ok. Exiting.");
							return Ok(());
						}
					}
					remove_file(key).map_err(|e| anyhow!("Unable to remove key file (ERROR = {})", e))?;
				}
			}

			// Comment
			let comment = args.value_of("comment");
			let do_crypt = !args.is_present("nocrypt");
			let passphrase_callback = move || {
				if do_crypt {
					read_password_from_tty(Some(format!("Passphrase for {}: ", seckey.display()).as_str()))
						.map_err(|e| anyhow!("Unable to read password from TTY: {}", e))
				}
				else {
					Ok(String::new())
				}
			};

			crypt4gh::keys::generate_keys(seckey, pubkey, passphrase_callback, comment)?;
		},

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
