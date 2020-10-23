use base64;
use crypto::{self, scrypt::ScryptParams};
use lazy_static::lazy_static;
use std::{
	collections::HashMap,
	fs::File,
	io::{BufRead, BufReader, Read, Result},
	path::Path,
};

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";
const DKLEN: usize = 32;

lazy_static! {
	static ref KDFS: HashMap<&'static str, (u64, u64)> = [
		("scrypt", (16, 0)),
		("bcrypt", (16, 100)),
		("pbkdf2_hmac_sha256", (16, 100_000)),
	]
	.iter()
	.copied()
	.collect();
}

fn read_lines<P>(filename: P) -> Result<Vec<String>>
where
	P: AsRef<Path>,
{
	let file = File::open(filename)?;
	Ok(BufReader::new(file).lines().filter_map(|line| line.ok()).collect())
}

fn load_from_pem(filepath: &Path) -> Vec<u8> {
	let lines = read_lines(filepath).unwrap();
	assert!(lines.first().unwrap().starts_with("-----BEGIN "));
	assert!(lines.last().unwrap().starts_with("-----END "));
	base64::decode(&lines[1]).unwrap()
}

fn decode_string(stream: &mut impl BufRead) -> Vec<u8> {
	// Get data len
	let mut slen = [0u8; 2];
	stream.read_exact(&mut slen).unwrap();
	let len = u16::from_be_bytes(slen);

	// Get data
	let mut data = vec![0u8; len as usize];
	stream.read_exact(data.as_mut_slice()).unwrap();

	data
}

fn derive_key(alg: String, passphrase: String, salt: Option<&[u8]>, rounds: Option<u32>) -> [u8; 32] {
	let mut output = [0u8; DKLEN];

	match alg.as_str() {
		"scrypt" => {
			let params = ScryptParams::new(14, 8, 1);
			crypto::scrypt::scrypt(passphrase.as_bytes(), salt.unwrap_or(&[0u8; 0]), &params, &mut output);
		},
		"bcrypt" => {
			crypto::bcrypt_pbkdf::bcrypt_pbkdf(
				passphrase.as_bytes(),
				&salt.unwrap_or(&[0u8; 0]),
				rounds.unwrap_or(0),
				&mut output,
			);
		},
		"pbkdf2_hmac_sha256" => {
			// let mac = Hmac::new(digest, key); ???
			// crypto::pbkdf2::pbkdf2(mac, salt.unwrap_or("").as_bytes(), rounds.unwrap_or(0), &mut output)
			unimplemented!()
		},
		unsupported_alg => panic!("Unsupported KDF: {}", unsupported_alg),
	};

	output
}

fn parse_c4gh_private_key(mut stream: impl BufRead, callback: impl Fn() -> Result<String>) -> Vec<u8> {
	let kdfname = String::from_utf8(decode_string(&mut stream)).unwrap();
	eprintln!("KDF: {}", kdfname);

	if kdfname != "none" && !KDFS.contains_key(kdfname.as_str()) {
		panic!("Invalid Crypt4GH Key format")
	}

	let mut rounds = None;
	let mut salt = None;
	let kdfoptions: Vec<u8>;

	if kdfname != "none" {
		kdfoptions = decode_string(&mut stream);
		rounds = Some(u32::from_be_bytes([
			kdfoptions[0],
			kdfoptions[1],
			kdfoptions[2],
			kdfoptions[3],
		]));
		salt = Some(&kdfoptions[4..]);
		eprintln!("Salt: {:X?}", salt.unwrap());
		eprintln!("Rounds: {}", rounds.unwrap());
	}
	else {
		eprintln!("Not Encrypted");
	}

	let ciphername = String::from_utf8(decode_string(&mut stream)).unwrap();
	eprintln!("Ciphername: {}", ciphername);

	let private_data = decode_string(&mut stream);

	if ciphername == "none" {
		return private_data.into();
	}

	// Else, the data was encrypted
	if ciphername != "chacha20_poly1305" {
		panic!("Invalid Crypt4GH Key format (Unsupported Cipher: {})", ciphername);
	}

	let passphrase = callback().unwrap();

	let shared_key = derive_key(kdfname, passphrase, salt, rounds);
	eprintln!("Shared Key: {:X?}", shared_key);

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&private_data[0..12]).unwrap();
	let key = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key::from_slice(&shared_key).unwrap();
	let encrypted_data = &private_data[12..];

	sodiumoxide::crypto::aead::chacha20poly1305_ietf::seal(&encrypted_data, None, &nonce, &key)
}

pub fn get_private_key(key_path: &Path, callback: impl Fn() -> Result<String>) -> Vec<u8> {
	let data = load_from_pem(key_path);

	if data.starts_with(C4GH_MAGIC_WORD) {
		eprintln!("Loading a Crypt4GH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream.read_exact(&mut [0u8; C4GH_MAGIC_WORD.len()]).unwrap();
		parse_c4gh_private_key(stream, callback)
	}
	else if data.starts_with(SSH_MAGIC_WORD) {
		eprintln!("Loading an OpenSSH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream.consume(SSH_MAGIC_WORD.len());

		unimplemented!()
	}
	else {
		panic!("Unsupported key format")
	}
}

pub fn get_public_key(key_path: &Path) -> Vec<u8> {
	let lines = read_lines(key_path);

	match lines {
		Ok(lines_vec) => {
			if lines_vec.len() == 0 {
				panic!("Empty public key at {:?}", key_path);
			}

			if lines_vec[0].find("CRYPT4GH").is_some() {
				eprintln!("Loading a Crypt4GH public key");
				return base64::decode(&lines_vec[1]).unwrap();
			}

			if lines_vec[0].get(0..4).unwrap() == "ssh-" {
				eprintln!("Loading an OpenSSH public key");
				unimplemented!()
			}

			panic!("Unsupported key format");
		},
		Err(err) => {
			panic!("Error reading public key at {:?}: {:?}", key_path, err);
		},
	}
}
