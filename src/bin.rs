use clap::{crate_authors, crate_version, load_yaml, App, AppSettings, ArgMatches};
use crypt4gh::{self, Keys};
use keys::{get_private_key, get_public_key};
use log;
use pretty_env_logger::{self};
use regex::Regex;
use rpassword::read_password_from_tty;
use std::{
	collections::HashSet,
	io::{self, Write},
	path::Path,
};

mod keys;

const DEFAULT_SK: &str = "C4GH_SECRET_KEY";
const PASSPHRASE: &str = "C4GH_PASSPHRASE";

fn parse_range(args: &ArgMatches) -> (usize, Option<usize>) {
	let mut range_start = 0;
	let mut range_span = None;

	if args.is_present("range") {
		// Capture regex <start-span>
		let range_regex = Regex::new(r"(?P<start>[\d]+)-?(?P<end>[\d]+)?").unwrap();
		let m = range_regex.captures(args.value_of("range").unwrap()).unwrap();

		if m.len() == 0 {
			panic!("Invalid range: {}", args.value_of("range").unwrap());
		}

		range_start = m.name("start").unwrap().as_str().parse::<usize>().unwrap();
		range_span = match m.name("end") {
			Some(end) => Some(end.as_str().parse::<usize>().unwrap() - range_start - 1),
			None => None,
		}
	}

	(range_start, range_span)
}

fn generate_private_key() -> String {
	unimplemented!()
}

fn retrieve_private_key(args: &ArgMatches, generate: bool) -> Vec<u8> {
	let seckey_path = match args.value_of("sk") {
		Some(sk) => Some(sk.to_string()),
		None => std::env::var(DEFAULT_SK).ok(),
	};

	if generate && seckey_path.is_none() {
		let skey = generate_private_key();
		// TODO: create a logger
		log::info!("Generating Private Key: {:#X?}", skey);
		skey.into_bytes()
	}
	else {
		// TODO: os.path.expanduser?
		let path = seckey_path.unwrap();
		if !Path::new(&path).exists() {
			panic!("Secret key not found: {}", path);
		}

		let callback: Box<dyn Fn() -> io::Result<String>> = match std::env::var(PASSPHRASE) {
			Ok(_) => {
				log::warn!("Warning: Using a passphrase in an environment variable is insecure");
				Box::new(|| Ok(std::env::var(PASSPHRASE).unwrap()))
			},
			Err(_) => Box::new(|| read_password_from_tty(Some("Password: "))),
		};

		get_private_key(&Path::new(&path), callback)
	}
}

fn build_recipients(args: &ArgMatches, sk: Vec<u8>) -> HashSet<Keys> {
	args.values_of("recipient_pk")
		.unwrap()
		.filter(|&pk| Path::new(pk).exists())
		.map(|pk| Keys {
			method: 0,
			privkey: sk.clone(),
			recipient_pubkey: get_public_key(Path::new(pk)),
		})
		.collect::<HashSet<Keys>>()
}

fn write_to_stdout(data: &[u8]) -> io::Result<()> {
	io::stdout().write_all(data)
}

fn main() {
	let yaml = load_yaml!("../app.yaml");
	let matches = App::from(yaml)
		.version(crate_version!())
		.author(crate_authors!())
		.setting(AppSettings::ArgRequiredElseHelp)
		.setting(AppSettings::ColorAlways)
		.setting(AppSettings::ColoredHelp)
		.get_matches();

	if matches.is_present("verbose") {
		std::env::set_var("RUST_LOG", "trace");
		pretty_env_logger::init();
	}

	match matches.subcommand() {
		// Encrypt
		Some(("encrypt", args)) => {
			let (range_start, range_span) = parse_range(args);
			let seckey = retrieve_private_key(args, true);
			let recipient_keys = build_recipients(args, seckey);

			if recipient_keys.is_empty() {
				panic!("No Recipients' Public Key found");
			}

			crypt4gh::encrypt(&recipient_keys, io::stdin(), write_to_stdout, range_start, range_span);
		},

		// Decrypt
		Some(("decrypt", args)) => {
			let sender_pubkey = match args.value_of("sender_pk") {
				Some(path) => Some(keys::get_public_key(Path::new(path))),
				None => None,
			};

			let (range_start, range_span) = parse_range(args);

			let seckey = retrieve_private_key(args, false);

			let keys = vec![Keys {
				method: 0,
				privkey: seckey,
				recipient_pubkey: vec![],
			}];

			crypt4gh::decrypt(
				keys,
				io::stdin(),
				write_to_stdout,
				range_start,
				range_span,
				sender_pubkey,
			);
		},
		_ => (),
	}
}
