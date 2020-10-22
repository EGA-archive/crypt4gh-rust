use clap::{load_yaml, App, ArgMatches};
use crypt4gh::{self, Keys};
use keys::{get_private_key, get_public_key};
use regex::Regex;
use rpassword::read_password;
use std::{
	collections::HashSet,
	io::{self},
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
		eprintln!("Generating Private Key: {:#X?}", skey);
		skey.into_bytes()
	}
	else {
		// TODO: os.path.expanduser?
		let path = seckey_path.unwrap();
		if !Path::new(&path).exists() {
			panic!("Secret key not found");
		}

		let passphrase = match std::env::var(PASSPHRASE) {
			Ok(pass) => {
				eprintln!("Warning: Using a passphrase in an environment variable is insecure");
				pass
			},
			Err(_) => {
				eprint!("Passphrase for {}: ", &path);
				read_password().unwrap()
			},
		};

		get_private_key(&Path::new(&path), passphrase)
	}
}

fn build_recipients(args: &ArgMatches, sk: Vec<u8>) -> HashSet<Keys> {
	args.values_of("recipient_pk")
		.unwrap()
		.filter(|&pk| Path::new(pk).exists())
		.map(|pk| {
			println!("Recipient pubkey: {}", pk);
			pk
		})
		.map(|pk| Keys {
			method: 0,
			privkey: sk.clone(),
			recipient_pubkey: get_public_key(Path::new(pk)),
		})
		.collect::<HashSet<Keys>>()
}

fn main() {
	let yaml = load_yaml!("../app.yaml");
	let matches = App::from(yaml).get_matches();
	match matches.subcommand() {
		// Encrypt
		Some(("encrypt", args)) => {
			let (range_start, range_span) = parse_range(args);
			let sk = retrieve_private_key(args, true);
			let recipient_keys = build_recipients(args, sk);

			if recipient_keys.is_empty() {
				panic!("No Recipients' Public Key found");
			}

			crypt4gh::encrypt(&recipient_keys, io::stdin(), io::stdout(), range_start, range_span);
		},

		// Decrypt
		Some(("decrypt", _args)) => {
			crypt4gh::decrypt();
		},
		_ => (),
	}
}
