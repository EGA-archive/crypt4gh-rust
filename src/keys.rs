#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

use aes::cipher::{StreamCipher, generic_array::GenericArray};
use rand::{SeedableRng, Rng};
use rand_chacha;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write, BufWriter};
use std::path::Path;

use base64::engine::general_purpose;
use base64::Engine;

use itertools::Itertools;
use lazy_static::lazy_static;

use aes::cipher::KeyIvInit;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{self, ChaCha20Poly1305, KeyInit, AeadCore, consts::U12};

use ctr;
//use cbc;

use crate::error::Crypt4GHError;

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

lazy_static! {
	static ref KDFS: HashMap<&'static str, (usize, u32)> = [
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

fn read_lines<P>(filename: P) -> Result<Vec<String>, Crypt4GHError>
where
	P: AsRef<Path>,
{
	let file = File::open(filename)?;
	Ok(BufReader::new(file)
		.lines()
		.filter_map(std::result::Result::ok)
		.collect())
}

fn load_from_pem(filepath: &'static Path) -> Result<Vec<u8>, Crypt4GHError> {
	// Read lines
	let lines = read_lines(filepath).map_err(|e| Crypt4GHError::ReadLinesError(filepath.into(), e.into()))?;

	// Check format
	if lines.len() < 3 {
		return Err(Crypt4GHError::InvalidPEMFormatLength(filepath));
	}

	if lines.first().unwrap().starts_with("-----BEGIN ") ||
	   lines.last().unwrap().starts_with("-----END ")  {
		return Err(Crypt4GHError::InvalidPEMHeaderOrFooter);
	}

	// Decode with base64
	general_purpose::STANDARD.decode(&lines[1..lines.len() - 1].join("")).map_err(|e| Crypt4GHError::BadBase64Error(e.into()))
}

fn decode_string_ssh(stream: &mut impl BufRead) -> Result<Vec<u8>, Crypt4GHError> {
	// Get data len
	let mut slen = [0_u8; 4];
	stream.read_exact(&mut slen)?;
	let len = u32::from_be_bytes(slen);

	// Get data
	let mut data = vec![0_u8; len as usize];
	stream.read_exact(data.as_mut_slice())?;

	Ok(data)
}

fn decode_string_c4gh(stream: &mut impl BufRead) -> Result<Vec<u8>, Crypt4GHError> {
	// Get data len
	let mut slen = [0_u8; 2];
	stream.read_exact(&mut slen)?;
	let len = u16::from_be_bytes(slen);

	// Get data
	let mut data = vec![0_u8; len as usize];
	stream.read_exact(data.as_mut_slice())?;

	Ok(data)
}

fn derive_key(
	alg: &str,
	passphrase: &str,
	salt: Option<Vec<u8>>,
	rounds: Option<u32>,
	dklen: usize,
) -> Result<Vec<u8>, Crypt4GHError> {
	let mut output = vec![0_u8; dklen];

	match alg {
		"scrypt" => {
			// TODO: Review last param of ScryptParams (length of what, exactly?) carefully. 
			// Added "dklen" for now since it seemed fitting, but needs proper review.
			let params = scrypt::Params::new(14, 8, 1, dklen);
			scrypt::scrypt(
				passphrase.as_bytes(),
				&salt.unwrap_or_else(|| {
					log::warn!("Using default salt = [0_u8; 8]");
					vec![0_u8; 0]
				}),
				&params.unwrap(), //TODO: .map_err() this to GA4GHError
				&mut output,
			);
		},
		"bcrypt" => {
			bcrypt_pbkdf::bcrypt_pbkdf(
				passphrase.as_bytes(),
				&salt.unwrap_or_else(|| {
					log::warn!("Using default salt = [0_u8; 8]");
					vec![0_u8; 0]
				}),
				rounds.unwrap_or_else(|| {
					log::warn!("Using default rounds = 0");
					0
				}),
				&mut output,
			);
		},
		"pbkdf2_hmac_sha256" => unimplemented!(),
		unsupported_alg => return Err(Crypt4GHError::UnsupportedKdf(unsupported_alg.into())),
	};

	Ok(output)
}

fn parse_c4gh_private_key(
	mut stream: impl BufRead,
	callback: impl Fn() -> Result<String, Crypt4GHError>,
) -> Result<Vec<u8>, Crypt4GHError> {
	let kdfname = String::from_utf8(decode_string_c4gh(&mut stream)?)
		.map_err(|e| Crypt4GHError::UnsupportedKdf(e.to_string()))?;
	log::debug!("KDF: {}", kdfname);

	if kdfname != "none" && !KDFS.contains_key(kdfname.as_str()) {
		return Err(Crypt4GHError::InvalidCrypt4GHKey);
	}

	let mut rounds = None;
	let mut salt = None;
	let kdfoptions: Vec<u8>;

	if kdfname == "none" {
		log::debug!("Not Encrypted");
	}
	else {
		kdfoptions = decode_string_c4gh(&mut stream)?;
		rounds = Some(u32::from_be_bytes([
			kdfoptions[0],
			kdfoptions[1],
			kdfoptions[2],
			kdfoptions[3],
		]));
		salt = Some(kdfoptions[4..].to_vec());
		log::debug!("Salt: {:02x?}", salt.iter().format(""));
		log::debug!("Rounds: {}", rounds.unwrap());
	}

	let ciphername =
		String::from_utf8(decode_string_c4gh(&mut stream)?).map_err(|e| Crypt4GHError::BadCiphername(e.to_string()))?;
	log::debug!("Ciphername: {}", ciphername);

	let private_data = decode_string_c4gh(&mut stream)?;

	if ciphername == "none" {
		return Ok(private_data);
	}

	// Else, the data was encrypted
	if ciphername != "chacha20_poly1305" {
		return Err(Crypt4GHError::BadCiphername(ciphername));
	}

	let passphrase = callback()?;

	let shared_key = derive_key(&kdfname, &passphrase, salt, rounds, 32)?;
	log::debug!("Shared Key: {:02x?}", shared_key.iter().format(""));
	log::debug!("Nonce: {:02x?}", &private_data[0..12].iter().format(""));

	let nonce = chacha20poly1305::Nonce::from_slice(&private_data[0..12]);//.ok_or(Crypt4GHError::NoNonce)?;
	let key = chacha20poly1305::Key::from_slice(&shared_key);//.ok_or(Crypt4GHError::BadKey)?;
	let encrypted_data = &private_data[12..];

	let privkey_plain = ChaCha20Poly1305::new(key).decrypt(nonce, encrypted_data)
		.map_err(|_| Crypt4GHError::InvalidKeyFormat)?;

	Ok(privkey_plain)
}

fn parse_ssh_private_key(
	mut stream: impl BufRead,
	callback: impl Fn() -> Result<String, Crypt4GHError>,
) -> Result<([u8; 32], [u8; 32]), Crypt4GHError> {
	let ciphername =
		String::from_utf8(decode_string_ssh(&mut stream)?).map_err(|e| Crypt4GHError::BadCiphername(e.to_string()))?;
	let kdfname =
		String::from_utf8(decode_string_ssh(&mut stream)?).map_err(|e| Crypt4GHError::BadKdfName(e.into()))?;
	let kdfoptions = decode_string_ssh(&mut stream)?;

	log::debug!("KDF: {}", kdfname);
	log::debug!("Ciphername: {}", ciphername);

	let mut salt: Option<Vec<u8>> = None;
	let mut rounds: Option<u32> = None;

	match kdfname.as_str() {
		"none" => {
			log::info!("Not Encrypted");
		},
		"bcrypt" => {
			if ciphername.as_str() == "none" {
				return Err(Crypt4GHError::InvalidSSHKey);
			}
			else {
				// Get salt
				let mut kdfoptions_cursor = Cursor::new(kdfoptions);
				salt = Some(decode_string_ssh(&mut kdfoptions_cursor)?);

				// Get rounds
				let mut buf = [0_u8; 4];
				kdfoptions_cursor
					.read_exact(&mut buf)
					.map_err(|_| Crypt4GHError::ReadRoundsError)?;
				rounds = Some(u32::from_be_bytes(buf));

				// Make sure kdfoptions are initialized to other values than 0
				if kdfoptions_cursor.read_exact(&mut [0_u8]).is_ok() {
					return Err(Crypt4GHError::BadKey);
				} 
				//assert!(kdfoptions_cursor.read_exact(&mut [0_u8]).is_err());

				// Log
				log::debug!("Salt: {:02x?}", salt.iter().format(""));
				log::debug!("Rounds: {:?}", rounds);
			}
		},
		_ => return Err(Crypt4GHError::InvalidSSHKey),
	}

	// N keys
	let mut buf = [0_u8; 4];
	stream.read_exact(&mut buf).map_err(|_| Crypt4GHError::ReadSSHKeys)?;
	let n: u32 = u32::from_be_bytes(buf);
	log::debug!("Number of keys: {}", n);

	//  Apparently always 1: https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3857
	assert!(n == 1);

	// Ignore public keys
	decode_string_ssh(&mut stream)?;

	// Padded list of private keys
	let private_ciphertext = decode_string_ssh(&mut stream)?;

	// There should be no more data to read
	assert!(
		stream.read_exact(&mut [0_u8; 1]).is_err(),
		"There should be no trailing data"
	);

	if ciphername == "none" {
		// No need to unpad
		get_skpk_from_decrypted_private_blob(&private_ciphertext)
	}
	else {
		// Encrypted
		assert!(salt.is_some() && rounds.is_some());

		let passphrase = callback().map_err(|e| Crypt4GHError::NoPassphrase(e.into()))?;

		let dklen = get_derived_key_length(&ciphername)?;
		log::debug!("Derived Key len: {}", dklen);

		let derived_key = derive_key(&kdfname, &passphrase, salt, rounds, dklen)?;
		log::debug!("Derived Key: {:02x?}", derived_key.iter().format(""));

		let private_data = decipher(&ciphername, &derived_key, &private_ciphertext)?;
		get_skpk_from_decrypted_private_blob(&private_data)
	}
}

fn decipher(ciphername: &str, data: &[u8], private_ciphertext: &[u8]) -> Result<Vec<u8>, Crypt4GHError> {
	let (ivlen, keylen) = CIPHER_INFO
		.get(ciphername)
		.ok_or_else(|| Crypt4GHError::BadCiphername(ciphername.into()))?;

	// Asserts
	assert!(data.len() == (ivlen + keylen) as usize);

	// Get params
	let key = &data[..*keylen as usize];
	let iv = &data[*keylen as usize..];

	log::debug!("Decryption Key ({}): {:02x?}", key.len(), key);
	log::debug!("IV ({}): {:02x?}", iv.len(), iv.iter().format(""));

	let mut output = vec![0_u8; private_ciphertext.len()];
	let reader = BufReader::new(private_ciphertext);
	let writer = BufWriter::new(&mut output);

	assert!((private_ciphertext.len() % block_size(ciphername)?) == 0);

	// Decipher
	match ciphername {
		"aes128-ctr" => {
			type Aes128Ctr = ctr::Ctr128LE<aes::Aes128>;
			let iv_ga = GenericArray::from_slice(iv);

			let mut cipher = Aes128Ctr::new(key.into(), iv_ga);
			cipher.apply_keystream_b2b(reader.buffer(), writer.buffer())
		},
		"aes192-ctr" => {
			//type Aes192Ctr = ctr::Ctr192<aes::Aes192>;  // Ctr192 not implemented in RustCrypto ctr crate!
			unimplemented!()
		},
		"aes256-ctr" => {
			//type Aes256Ctr = ctr::Ctr256<aes::Aes256>;   // Ctr256 not implemented in RustCrypto ctr crate!
			unimplemented!()
		},
		"aes128-cbc" => {
			//type Aes128Cbc = cbc::cipher::BlockCipher::  // No analogous type?
			unimplemented!()
		},
		"aes192-cbc" => {
			unimplemented!() // Ditto above
		},
		"aes256-cbc" => {
			unimplemented!() // Ditto above
		},
		"3des-cbc" => unimplemented!(),
		unknown_cipher => return Err(Crypt4GHError::BadCiphername(unknown_cipher.into())),
	};
	Ok(output)
}

fn block_size(ciphername: &str) -> Result<usize, Crypt4GHError> {
	let (block_sz, _) = CIPHER_INFO
		.get(ciphername)
		.ok_or_else(|| Crypt4GHError::BadCiphername(ciphername.into()))?;
	Ok(*block_sz as usize)
}

fn get_derived_key_length(ciphername: &str) -> Result<usize, Crypt4GHError> {
	let (ivlen, keylen) = CIPHER_INFO
		.get(ciphername)
		.ok_or_else(|| Crypt4GHError::BadCiphername(ciphername.into()))?;
	Ok((ivlen + keylen) as usize)
}

fn get_skpk_from_decrypted_private_blob(blob: &[u8]) -> Result<([u8; 32], [u8; 32]), Crypt4GHError> {
	let check_number_1: u32 = bincode::deserialize(&blob[0..4]).map_err(|_| Crypt4GHError::ReadCheckNumber1Error)?;
	let check_number_2: u32 = bincode::deserialize(&blob[4..8]).map_err(|_| Crypt4GHError::ReadCheckNumber2Error)?;
	assert!(
		check_number_1 == check_number_2,
		"Check numbers: {} != {}",
		check_number_1,
		check_number_2
	);

	let mut stream = Cursor::new(&blob[8..]);

	// We should parse n keys, but n is 1
	decode_string_ssh(&mut stream)?; // ignore key name
	decode_string_ssh(&mut stream)?; // ignore pubkey

	let skpk = decode_string_ssh(&mut stream)?;
	log::debug!("Private Key blob: {:02x?}", skpk.iter().format(""));
	assert!(skpk.len() == 64, "The length of the private key blob must be 64");

	let (sk, pk) = skpk.split_at(32);
	log::debug!("ed25519 sk: {:02x?}", sk.iter().format(""));
	log::debug!("ed25519 pk: {:02x?}", pk.iter().format(""));

	let seckey = convert_ed25519_sk_to_curve25519(sk)?;
	log::debug!("x25519 sk: {:02x?}", seckey.iter().format(""));

	let pubkey = convert_ed25519_pk_to_curve25519(pk)?;
	log::debug!("x25519 pk: {:02x?}", pubkey.iter().format(""));

	Ok((seckey, pubkey))
}

/// Reads and decodes the private key stored in `key_path`.
///
/// It supports `Crypt4GH` and OpenSSH private keys. Fails if it can not read the file
/// or if the key is not one of the two supported formats. Returns the decode key.
/// If the key is encrypted, the `callback` should return the passphrase of the key.
pub fn get_private_key(
	key_path: &Path,
	callback: impl Fn() -> Result<String, Crypt4GHError>,
) -> Result<Vec<u8>, Crypt4GHError> {
	let data = load_from_pem(key_path)?;

	if data.starts_with(C4GH_MAGIC_WORD) {
		log::info!("Loading a Crypt4GH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream
			.read_exact(&mut [0_u8; C4GH_MAGIC_WORD.len()])
			.map_err(|e| Crypt4GHError::ReadMagicWord(e.into()))?;
		parse_c4gh_private_key(stream, callback)
	}
	else if data.starts_with(SSH_MAGIC_WORD) {
		log::info!("Loading an OpenSSH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream
			.read_exact(&mut [0_u8; SSH_MAGIC_WORD.len()])
			.map_err(|e| Crypt4GHError::ReadMagicWord(e.into()))?;
		let (seckey, pubkey) = parse_ssh_private_key(stream, callback)?;
		Ok(vec![seckey, pubkey].concat())
	}
	else {
		Err(Crypt4GHError::InvalidKeyFormat)
	}
}

/// Reads and decodes the public key stored in `key_path`.
///
/// It supports `Crypt4GH` and OpenSSH public keys. Fails if it can not read the file
/// or if the key is not one of the two supported formats. Returns the decoded key.
pub fn get_public_key(key_path: &Path) -> Result<Vec<u8>, Crypt4GHError> {
	// Read lines from public key file
	match read_lines(key_path) {
		Ok(lines_vec) => {
			// Empty key
			if lines_vec.is_empty() {
				Err(Crypt4GHError::EmptyPublicKey(key_path.into()))
			}
			// CRYPT4GH key
			else if lines_vec[0].contains("CRYPT4GH") {
				log::info!("Loading a Crypt4GH public key");
				general_purpose::STANDARD.decode(&lines_vec[1]).map_err(|e| Crypt4GHError::BadBase64Error(e.into()))
			}
			// SSH key
			else if lines_vec[0].len() >= 4 && lines_vec[0].get(0..4).unwrap() == "ssh-" {
				log::info!("Loading an OpenSSH public key");
				Ok(ssh_get_public_key(&lines_vec[0])?.to_vec())
			}
			// Unsupported key
			else {
				Err(Crypt4GHError::InvalidKeyFormat)
			}
		},
		Err(_) => {
			// Could not read lines
			Err(Crypt4GHError::ReadPublicKeyError)
		},
	}
}

fn ssh_get_public_key(line: &str) -> Result<[u8; 32], Crypt4GHError> {
	if &line[4..11] != "ed25519" {
		return Err(Crypt4GHError::InvalidSSHKey);
	}

	let pkey = general_purpose::STANDARD.decode(
		line[12..]
			.split(' ')
			.take(1)
			.next()
			.ok_or(Crypt4GHError::InvalidSSHKey)?,
	)
	.map_err(|e| Crypt4GHError::BadBase64Error(e.into()))?;
	let mut pkey_stream = Cursor::new(pkey);

	let key_type = decode_string_ssh(&mut pkey_stream)?;
	assert!(key_type == b"ssh-ed25519", "Unsupported public key type");

	let pubkey_bytes = decode_string_ssh(&mut pkey_stream)?;
	convert_ed25519_pk_to_curve25519(&pubkey_bytes)
}

fn convert_ed25519_pk_to_curve25519(ed25519_pk: &[u8]) -> Result<[u8; 32], Crypt4GHError> {
	todo!()
}

fn convert_ed25519_sk_to_curve25519(ed25519_sk: &[u8]) -> Result<[u8; 32], Crypt4GHError> {
	todo!()
}

/// Generates a random privary key.
///
/// It generates 32 random bytes and calculates the public key using the curve25519 algorithm.
/// The resulting private key has a length of 64. The first 32 bytes belong to the secret key,
/// the last 32 bytes belong to the public key.
pub fn generate_private_key() -> Result<Vec<u8>, Crypt4GHError> {
	let seckey = ChaCha20Poly1305::generate_key(OsRng).to_vec();
	let pubkey = get_public_key_from_private_key(&seckey)?;
	assert_eq!(seckey.len(), pubkey.len());
	Ok(vec![seckey, pubkey].concat())
}

/// Generates a pair of `Crypt4GH` keys.
///
/// It creates two files, one for the public key and another for the private key. It stores the
/// keys following the [`Crypt4GH` format](https://ega-archive.github.io/crypt4gh-rust/3_key_format.html).
/// The passphrase callback should return a string that will be used to encode the keys. You can add
/// an optional comment at the end of the keys.
pub fn generate_keys(
	seckey: &Path,
	pubkey: &Path,
	passphrase_callback: impl Fn() -> Result<String, Crypt4GHError>,
	comment: Option<String>,
) -> Result<(), Crypt4GHError> {
	let skpk = generate_private_key()?;
	log::debug!("Private Key: {:02x?}", skpk.iter().format(""));

	// Public key permissions (read & write)
	let mut pk_file = File::create(pubkey).expect("Unable to create public key file");
	let mut permissions = pk_file.metadata().unwrap().permissions();
	permissions.set_readonly(false);
	pk_file.set_permissions(permissions).unwrap();

	// Write public key
	let (sk, pk) = skpk.split_at(32);
	log::debug!("Public Key: {:02x?}", pk.iter().format(""));
	pk_file.write_all(b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n").unwrap();
	pk_file.write_all(general_purpose::STANDARD.encode(pk).as_bytes()).unwrap();
	pk_file.write_all(b"\n-----END CRYPT4GH PUBLIC KEY-----\n").unwrap();

	// Secret key file open
	let mut sk_file = File::create(seckey).unwrap();

	// Write secret key
	let passphrase = passphrase_callback().unwrap();
	let sk_encrypted = encode_private_key(sk, &passphrase, comment)?;
	log::debug!(
		"Encoded Private Key ({}): {:02x?}",
		sk_encrypted.len(),
		sk.iter().format("")
	);
	sk_file.write_all(b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n").unwrap();
	sk_file.write_all(general_purpose::STANDARD.encode(sk_encrypted).as_bytes()).unwrap();
	sk_file.write_all(b"\n-----END CRYPT4GH PRIVATE KEY-----\n").unwrap();

	// Secret key file permissions (read only)
	let mut permissions = sk_file.metadata().unwrap().permissions();
	permissions.set_readonly(true);
	sk_file.set_permissions(permissions).unwrap();

	Ok(())
}

fn encode_string_c4gh(s: Option<&[u8]>) -> Vec<u8> {
	let string = s.unwrap_or(b"none");
	vec![(string.len() as u16).to_be_bytes().to_vec(), string.to_vec()].concat()
}

fn encode_private_key(skpk: &[u8], passphrase: &str, comment: Option<String>) -> Result<Vec<u8>, Crypt4GHError> {
	Ok(if passphrase.is_empty() {
		log::warn!("The private key is not encrypted");
		vec![
			C4GH_MAGIC_WORD.to_vec(),
			encode_string_c4gh(None), // KDF = None
			encode_string_c4gh(None), // Cipher = None
			encode_string_c4gh(Some(skpk)),
			match comment {
				Some(c) => encode_string_c4gh(Some(c.as_bytes())),
				None => [].to_vec(),
			},
		]
		.concat()
	}
	else {
		let kdfname = "scrypt";
		let (salt_size, rounds) = get_kdf(kdfname)?;
		let salt = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(rounds)).gen::<[u8;10]>(); // TODO: This is wrong X"D

		let derived_key = derive_key(kdfname, passphrase, Some(salt.clone().to_vec()), Some(rounds), 32)?;
		let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
		let key = chacha20poly1305::Key::from_slice(&derived_key);
		let salt_ga = GenericArray::from_slice(salt.as_slice());

		let encrypted_key = ChaCha20Poly1305::new(&key)
			.encrypt(salt_ga, skpk)
			.map_err(|_| Crypt4GHError::BadKey)?;

		let encrypted_key_ga = GenericArray::<u8, U12>::from_slice(encrypted_key.as_slice());

		log::debug!("Derived Key: {:02x?}", derived_key);
		log::debug!("Salt: {:02x?}", salt);
		log::debug!("Nonce: {:02x?}", nonce);

		vec![
			C4GH_MAGIC_WORD.to_vec(),
			encode_string_c4gh(Some(kdfname.as_bytes())),
			encode_string_c4gh(Some(&vec![(rounds as u32).to_be_bytes().to_vec(), salt.to_vec()].concat())),
			encode_string_c4gh(Some(b"chacha20_poly1305")),
			encode_string_c4gh(Some(&vec![nonce, *encrypted_key_ga].concat())),
			match comment {
				Some(c) => encode_string_c4gh(Some(c.as_bytes())),
				None => [].to_vec(),
			},
		]
		.concat()
	})
}

fn get_kdf(kdfname: &str) -> Result<(usize, u32), Crypt4GHError> {
	KDFS.get(kdfname)
		.copied()
		.ok_or_else(|| Crypt4GHError::UnsupportedKdf(kdfname.into()))
}

/// Gets the public key from a private key
///
/// Computes the curve25519 `scalarmult_base` to the first 32 bytes of `sk`.
/// `sk` must be at least 32 bytes.
pub fn get_public_key_from_private_key(sk: &[u8]) -> Result<Vec<u8>, Crypt4GHError> {
	todo!()
}