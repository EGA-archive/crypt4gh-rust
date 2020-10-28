use base64;
use crypto::{self, blockmodes::NoPadding, buffer::{RefReadBuffer, RefWriteBuffer}, scrypt::ScryptParams, symmetriccipher::Decryptor};
use lazy_static::lazy_static;
use rpassword::read_password_from_tty;
use std::{collections::HashMap, fs::File, io::{BufRead, BufReader, Cursor, Read, Result}, path::Path};

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

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

lazy_static! {
	static ref CIPHER_INFO: HashMap<&'static str, (u64, u64)> = [
		("aes128-ctr", (16, 16)),
		("aes192-ctr", (16, 24)),
		("aes256-ctr", (16, 32)),
		("aes128-cbc", (16, 16)),
		("aes192-cbc", (16, 24)),
		("aes256-cbc", (16, 32)),
		("3des-cbc",   ( 8, 24)),
		//("blowfish-cbc", (8, 16)),
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

	// TODO: Return Result<Vec<u8>>
	data
}

fn derive_key(alg: String, passphrase: String, salt: Option<Vec<u8>>, rounds: Option<u32>, dklen: usize) -> Vec<u8> {
	let mut output = vec![0u8; dklen];

	match alg.as_str() {
		"scrypt" => {
			let params = ScryptParams::new(14, 8, 1);
			crypto::scrypt::scrypt(passphrase.as_bytes(), &salt.unwrap_or(vec![0u8; 0]), &params, &mut output);
		},
		"bcrypt" => {
			crypto::bcrypt_pbkdf::bcrypt_pbkdf(
				passphrase.as_bytes(),
				&salt.unwrap_or(vec![0u8; 0]),
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
	log::debug!("KDF: {}", kdfname);

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
		salt = Some(kdfoptions[4..].to_vec());
		log::debug!("Salt: {:02x?}", salt);
		log::debug!("Rounds: {}", rounds.unwrap());
	}
	else {
		log::error!("Not Encrypted");
	}

	let ciphername = String::from_utf8(decode_string(&mut stream)).unwrap();
	log::debug!("Ciphername: {}", ciphername);

	let private_data = decode_string(&mut stream);

	if ciphername == "none" {
		return private_data.into();
	}

	// Else, the data was encrypted
	if ciphername != "chacha20_poly1305" {
		panic!("Invalid Crypt4GH Key format (Unsupported Cipher: {})", ciphername);
	}

	let passphrase = callback().unwrap();

	let shared_key = derive_key(kdfname, passphrase, salt, rounds, 32);
	log::debug!("Shared Key: {:02x?}", shared_key);

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&private_data[0..12]).unwrap();
	let key = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key::from_slice(&shared_key).unwrap();
	let encrypted_data = &private_data[12..];

	sodiumoxide::crypto::aead::chacha20poly1305_ietf::seal(&encrypted_data, None, &nonce, &key)
}

fn parse_ssh_private_key(mut stream: impl BufRead, _callback: impl Fn() -> Result<String>) -> ([u8; 32], [u8; 32]) {
	let ciphername = String::from_utf8(decode_string(&mut stream)).unwrap();
	let kdfname = String::from_utf8(decode_string(&mut stream)).unwrap();
	let kdfoptions = decode_string(&mut stream);

	log::debug!("KDF: {}", kdfname);
	log::debug!("Ciphername: {}", ciphername);

	let mut salt = None;
	let mut rounds = None;

	match kdfname.as_str() {
		"none" => {
			log::info!("Not Encrypted");
		},
		"bcrypt" => {
			match ciphername.as_str() {
				"none" => panic!("Invalid SSH Key format"),
				_ => {
					// Get salt
					let mut kdfoptions_cursor = Cursor::new(kdfoptions);
					salt = Some(decode_string(&mut kdfoptions_cursor));

					// Get rounds
					rounds = Some(bincode::deserialize_from(&mut kdfoptions_cursor).unwrap());

					// Assert
					assert!(kdfoptions_cursor.read_exact(&mut [0u8]).is_err());

					// Log
					log::debug!("Salt: {:02x?}", salt);
					log::debug!("Rounds: {:?}", rounds);
				}
			}
		},
		_ => panic!("Invalid SSH Key format"),
	}

	// N keys
	let n: u32 = bincode::deserialize_from(&mut stream).unwrap();
	log::debug!("Number of keys: {}", n);
	
	//  Apparently always 1: https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3857
	assert!(n == 1);	

	// Ignore public keys
	decode_string(&mut stream);

	// Padded list of private keys
	let private_ciphertext = decode_string(&mut stream);

	// There should be no more data to read
	assert!(stream.read_exact(&mut [0u8]).is_err(), "There should be no trailing data");

	if ciphername == "none" {
		// No need to unpad
		get_skpk_from_decrypted_private_blob(private_ciphertext)
	}
	else {
		// Encrypted
		assert!(salt.is_some() && rounds.is_some());

		let passphrase = read_password_from_tty(Some("Password: "))
			.expect("Passphrase required");

		let dklen = get_derived_key_length(&ciphername);
		log::debug!("Derived Key len: {}", dklen);

		let derived_key = derive_key(kdfname, passphrase, salt, rounds, dklen);
		log::debug!("Derived Key: {:?}", derived_key);

		let private_data = descipher(&ciphername, derived_key, private_ciphertext);
		get_skpk_from_decrypted_private_blob(private_data)
	}
}

fn descipher(ciphername: &String, derived_key: Vec<u8>, private_ciphertext: Vec<u8>) -> Vec<u8> {
	
	let (ivlen, keylen) = CIPHER_INFO.get(ciphername.as_str()).expect("Unsupported cipher");

	// Asserts
	assert!(derived_key.len() == (ivlen + keylen) as usize);

	// Get params
	let key = &derived_key[..*keylen as usize];
	let iv = &derived_key[*keylen as usize..];

	log::debug!("Decryptiong Key ({}): {:02x?}", key.len(), key);
	log::debug!("IV ({}): {:02x?}", iv.len(), iv);

	let mut output = vec![0u8; derived_key.len()];
	let mut reader = RefReadBuffer::new(&derived_key);
	let mut writer = RefWriteBuffer::new(&mut output);

	assert!(private_ciphertext.len() % block_size(&ciphername) == 0);

	// Descipher
	match ciphername.as_str() {
		"aes128-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize128, key, iv).decrypt(&mut reader, &mut writer, true).unwrap(),
		"aes192-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize192, key, iv).decrypt(&mut reader, &mut writer, true).unwrap(),
		"aes256-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize256, key, iv).decrypt(&mut reader, &mut writer, true).unwrap(),
		"aes128-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize128, key, iv, NoPadding).decrypt(&mut reader, &mut writer, true).unwrap(),
		"aes192-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize192, key, iv, NoPadding).decrypt(&mut reader, &mut writer, true).unwrap(),
		"aes256-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize256, key, iv, NoPadding).decrypt(&mut reader, &mut writer, true).unwrap(),
		"3des-cbc" => unimplemented!(),
		_ => panic!("Unsupported cipher"),
	};

	output
}

fn block_size(ciphername: &String) -> usize {
	CIPHER_INFO.get(ciphername.as_str()).expect("Unsupported cipher").0 as usize
}

fn get_derived_key_length(ciphername: &String) -> usize {
	let (ivlen, keylen) = CIPHER_INFO.get(ciphername.as_str()).expect("Unsupported cipher");
	(ivlen + keylen) as usize
}

fn get_skpk_from_decrypted_private_blob(blob: Vec<u8>) -> ([u8; 32], [u8; 32]) {
	let mut stream = Cursor::new(blob.as_slice());
	
	let check_number_1: u32 = bincode::deserialize_from(&mut stream).unwrap();
	let check_number_2: u32 = bincode::deserialize_from(&mut stream).unwrap();
	assert!(check_number_1 == check_number_2, "Check: {} != {}", check_number_1, check_number_2);

	// We should parse n keys, but n is 1
	decode_string(&mut stream);	// ignore key name
	decode_string(&mut stream);	// ignore pubkey

	let skpk = decode_string(&mut stream);
	log::debug!("Private Key blob: {:02x?}", skpk);
	assert!(skpk.len() == 64);

	let (sk, pk) = skpk.split_at(32);
	log::debug!("ed25519 sk: {:02x?}", sk);
	log::debug!("ed25519 pk: {:02x?}", pk);

	let seckey = crypto::curve25519::curve25519_base(sk);
	log::debug!("x25519 sk: {:02x?}", seckey);

	let pubkey = crypto::curve25519::curve25519_base(pk);
	log::debug!("x25519 pk: {:02x?}", pubkey);

	(seckey, pubkey)
}

pub fn get_private_key(key_path: &Path, callback: impl Fn() -> Result<String>) -> Vec<u8> {
	let data = load_from_pem(key_path);

	if data.starts_with(C4GH_MAGIC_WORD) {
		log::info!("Loading a Crypt4GH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream.read_exact(&mut [0u8; C4GH_MAGIC_WORD.len()]).unwrap();
		parse_c4gh_private_key(stream, callback)
	}
	else if data.starts_with(SSH_MAGIC_WORD) {
		log::info!("Loading an OpenSSH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream.read_exact(&mut [0u8; SSH_MAGIC_WORD.len()]).unwrap();
		let (seckey, pubkey) = parse_ssh_private_key(stream, callback);
		vec![seckey, pubkey].concat()
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
				log::info!("Loading a Crypt4GH public key");
				return base64::decode(&lines_vec[1]).unwrap();
			}

			if lines_vec[0].get(0..4).unwrap() == "ssh-" {
				log::info!("Loading an OpenSSH public key");
				return ssh_get_public_key(&lines_vec[0]).to_vec()
			}

			panic!("Unsupported key format");
		},
		Err(err) => {
			panic!("Error reading public key at {:?}: {:?}", key_path, err);
		},
	}
}

fn ssh_get_public_key(line: &str) -> [u8; 32] {
	if &line[4..12] != "ed25519" {
		panic!("Unsupported SSH key format: {}", &line[0..11]);
	}

	let pkey = base64::decode(line[12..].split(' ').take(1).next().unwrap()).unwrap();
	let mut pkey_stream = Cursor::new(pkey);

	let key_type = decode_string(&mut pkey_stream);
	assert!(key_type == "ssh-ed25519".as_bytes());

	let pubkey_bytes = decode_string(&mut pkey_stream);
	crypto::curve25519::curve25519_base(&pubkey_bytes)
}
