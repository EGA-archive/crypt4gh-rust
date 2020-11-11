use anyhow::{anyhow, bail};
use anyhow::{ensure, Result};
use base64;
use crypto::{
	self,
	blockmodes::NoPadding,
	buffer::{RefReadBuffer, RefWriteBuffer},
	scrypt::ScryptParams,
	symmetriccipher::Decryptor,
};
use lazy_static::lazy_static;
use sodiumoxide::{crypto::aead::chacha20poly1305_ietf, randombytes::randombytes};
use std::{
	collections::HashMap,
	fs::File,
	io::Write,
	io::{BufRead, BufReader, Cursor, Read},
	path::Path,
};

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

fn read_lines<P>(filename: P) -> Result<Vec<String>>
where
	P: AsRef<Path>,
{
	let file = File::open(filename)?;
	Ok(BufReader::new(file).lines().filter_map(|line| line.ok()).collect())
}

fn load_from_pem(filepath: &Path) -> Result<Vec<u8>> {
	// Read lines
	let lines =
		read_lines(filepath).map_err(|e| anyhow!("Unable to read lines from {:?} (ERROR = {:?})", filepath, e))?;

	// Check format
	ensure!(lines.len() >= 3, "The file ({:?}) is not 3 lines long", filepath);
	ensure!(
		lines.first().unwrap().starts_with("-----BEGIN "),
		"The file ({:?}) does not start with -----BEGIN",
		filepath
	);
	ensure!(
		lines.last().unwrap().starts_with("-----END "),
		"The file ({:?}) does not end with -----END",
		filepath
	);

	// Decode with base64
	base64::decode(&lines[1..lines.len() - 1].join(""))
		.map_err(|e| anyhow!("Unable to decode with base64 the key (ERROR = {:?})", e))
}

fn decode_string_ssh(stream: &mut impl BufRead) -> Result<Vec<u8>> {
	// Get data len
	let mut slen = [0u8; 4];
	stream.read_exact(&mut slen)?;
	let len = u32::from_be_bytes(slen);

	// Get data
	let mut data = vec![0u8; len as usize];
	stream.read_exact(data.as_mut_slice())?;

	Ok(data)
}

fn decode_string_c4gh(stream: &mut impl BufRead) -> Result<Vec<u8>> {
	// Get data len
	let mut slen = [0u8; 2];
	stream.read_exact(&mut slen)?;
	let len = u16::from_be_bytes(slen);

	// Get data
	let mut data = vec![0u8; len as usize];
	stream.read_exact(data.as_mut_slice())?;

	Ok(data)
}

fn derive_key(
	alg: String,
	passphrase: String,
	salt: Option<Vec<u8>>,
	rounds: Option<u32>,
	dklen: usize,
) -> Result<Vec<u8>> {
	let mut output = vec![0u8; dklen];

	match alg.as_str() {
		"scrypt" => {
			let params = ScryptParams::new(14, 8, 1);
			crypto::scrypt::scrypt(
				passphrase.as_bytes(),
				&salt.unwrap_or_else(|| {
					log::warn!("Using default salt = [0u8; 8]");
					vec![0u8; 0]
				}),
				&params,
				&mut output,
			);
		},
		"bcrypt" => {
			crypto::bcrypt_pbkdf::bcrypt_pbkdf(
				passphrase.as_bytes(),
				&salt.unwrap_or_else(|| {
					log::warn!("Using default salt = [0u8; 8]");
					vec![0u8; 0]
				}),
				rounds.unwrap_or_else(|| {
					log::warn!("Using default rounds = 0");
					0
				}),
				&mut output,
			);
		},
		"pbkdf2_hmac_sha256" => unimplemented!(),
		unsupported_alg => return Err(anyhow!("Unsupported KDF: {}", unsupported_alg)),
	};

	Ok(output)
}

fn parse_c4gh_private_key(mut stream: impl BufRead, callback: impl Fn() -> Result<String>) -> Result<Vec<u8>> {
	let kdfname = String::from_utf8(decode_string_c4gh(&mut stream)?)?;
	log::debug!("KDF: {}", kdfname);

	if kdfname != "none" && !KDFS.contains_key(kdfname.as_str()) {
		bail!("Invalid Crypt4GH Key format")
	}

	let mut rounds = None;
	let mut salt = None;
	let kdfoptions: Vec<u8>;

	if kdfname != "none" {
		kdfoptions = decode_string_c4gh(&mut stream)?;
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
		log::debug!("Not Encrypted");
	}

	let ciphername = String::from_utf8(decode_string_c4gh(&mut stream)?)
		.map_err(|e| anyhow!("Unable to parse UTF8 String from ciphername ({:?})", e))?;
	log::debug!("Ciphername: {}", ciphername);

	let private_data = decode_string_c4gh(&mut stream)?;

	if ciphername == "none" {
		return Ok(private_data.into());
	}

	// Else, the data was encrypted
	if ciphername != "chacha20_poly1305" {
		bail!("Invalid Crypt4GH Key format (Unsupported Cipher: {})", ciphername);
	}

	let passphrase = callback()?;

	let shared_key = derive_key(kdfname, passphrase, salt, rounds, 32)?;
	log::debug!("Shared Key: {:02x?}", shared_key);
	log::debug!("Nonce: {:02x?}", &private_data[0..12]);

	let nonce = chacha20poly1305_ietf::Nonce::from_slice(&private_data[0..12])
		.ok_or_else(|| anyhow!("Parsing private key failed -> Unable to extract nonce"))?;
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key)
		.ok_or_else(|| anyhow!("Parsing private key failed -> Unable to wrap key"))?;
	let encrypted_data = &private_data[12..];

	Ok(chacha20poly1305_ietf::seal(&encrypted_data, None, &nonce, &key))
}

fn parse_ssh_private_key(
	mut stream: impl BufRead,
	callback: impl Fn() -> Result<String>,
) -> Result<([u8; 32], [u8; 32])> {
	let ciphername = String::from_utf8(decode_string_ssh(&mut stream)?)
		.map_err(|e| anyhow!("Unable to parse UTF8 String from ciphername ({:?})", e))?;
	let kdfname = String::from_utf8(decode_string_ssh(&mut stream)?)
		.map_err(|e| anyhow!("Unable to parse UTF8 String from kdfname ({:?})", e))?;
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
			match ciphername.as_str() {
				"none" => bail!("Invalid SSH Key format"),
				_ => {
					// Get salt
					let mut kdfoptions_cursor = Cursor::new(kdfoptions);
					salt = Some(decode_string_ssh(&mut kdfoptions_cursor)?);

					// Get rounds
					let mut buf = [0u8; 4];
					kdfoptions_cursor
						.read_exact(&mut buf)
						.map_err(|_| anyhow!("Unable to deserialize rounds from private key"))?;
					rounds = Some(u32::from_be_bytes(buf));

					// Assert
					assert!(kdfoptions_cursor.read_exact(&mut [0u8]).is_err());

					// Log
					log::debug!("Salt: {:02x?}", salt);
					log::debug!("Rounds: {:?}", rounds);
				},
			}
		},
		_ => bail!("Invalid SSH Key format"),
	}

	// N keys
	let mut buf = [0u8; 4];
	stream
		.read_exact(&mut buf)
		.map_err(|_| anyhow!("Unable to deserialize N keys from private key"))?;
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
		stream.read_exact(&mut [0u8; 1]).is_err(),
		"There should be no trailing data"
	);

	if ciphername == "none" {
		// No need to unpad
		get_skpk_from_decrypted_private_blob(private_ciphertext)
	}
	else {
		// Encrypted
		assert!(salt.is_some() && rounds.is_some());

		let passphrase = callback().map_err(|e| anyhow!("Passphrase required (ERROR = {:?})", e))?;

		let dklen = get_derived_key_length(&ciphername)?;
		log::debug!("Derived Key len: {}", dklen);

		let derived_key = derive_key(kdfname, passphrase, salt, rounds, dklen)?;
		log::debug!("Derived Key: {:02x?}", derived_key);

		let private_data = decipher(&ciphername, derived_key, private_ciphertext)?;
		get_skpk_from_decrypted_private_blob(private_data)
	}
}

fn decipher(ciphername: &String, data: Vec<u8>, private_ciphertext: Vec<u8>) -> Result<Vec<u8>> {
	let (ivlen, keylen) = CIPHER_INFO
		.get(ciphername.as_str())
		.ok_or_else(|| anyhow!("Unsupported cipher"))?;

	// Asserts
	assert!(data.len() == (ivlen + keylen) as usize);

	// Get params
	let key = &data[..*keylen as usize];
	let iv = &data[*keylen as usize..];

	log::debug!("Decryption Key ({}): {:02x?}", key.len(), key);
	log::debug!("IV ({}): {:02x?}", iv.len(), iv);

	let mut output = vec![0u8; private_ciphertext.len()];
	let mut reader = RefReadBuffer::new(&private_ciphertext);
	let mut writer = RefWriteBuffer::new(&mut output);

	assert!((private_ciphertext.len() % block_size(&ciphername)?) == 0);

	// Decipher
	match ciphername.as_str() {
		"aes128-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize128, key, iv)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"aes192-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize192, key, iv)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"aes256-ctr" => crypto::aes::ctr(crypto::aes::KeySize::KeySize256, key, iv)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"aes128-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize128, key, iv, NoPadding)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"aes192-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize192, key, iv, NoPadding)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"aes256-cbc" => crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize256, key, iv, NoPadding)
			.decrypt(&mut reader, &mut writer, true)
			.map_err(|e| anyhow!("Unable to decrypt key (ERROR = {:?})", e))?,
		"3des-cbc" => unimplemented!(),
		unknown_cipher => return Err(anyhow!("Unsupported cipher {}", unknown_cipher)),
	};

	Ok(output)
}

fn block_size(ciphername: &String) -> Result<usize> {
	let (block_sz, _) = CIPHER_INFO
		.get(ciphername.as_str())
		.ok_or_else(|| anyhow!("Unsupported cipher"))?;
	Ok(*block_sz as usize)
}

fn get_derived_key_length(ciphername: &String) -> Result<usize> {
	let (ivlen, keylen) = CIPHER_INFO
		.get(ciphername.as_str())
		.ok_or_else(|| anyhow!("Unsupported cipher"))?;
	Ok((ivlen + keylen) as usize)
}

fn get_skpk_from_decrypted_private_blob(blob: Vec<u8>) -> Result<([u8; 32], [u8; 32])> {
	let check_number_1: u32 = bincode::deserialize(&blob[0..4])
		.map_err(|_| anyhow!("Unable to deserialize check number 1 from private blob"))?;
	let check_number_2: u32 = bincode::deserialize(&blob[4..8])
		.map_err(|_| anyhow!("Unable to deserialize check number 2 from private blob"))?;
	ensure!(
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
	log::debug!("Private Key blob: {:02x?}", skpk);
	ensure!(skpk.len() == 64, "The length of the private key blob must be 64");

	let (sk, pk) = skpk.split_at(32);
	log::debug!("ed25519 sk: {:02x?}", sk);
	log::debug!("ed25519 pk: {:02x?}", pk);

	let seckey = convert_ed25519_sk_to_curve25519(sk)?;
	log::debug!("x25519 sk: {:02x?}", seckey);

	let pubkey = convert_ed25519_pk_to_curve25519(pk)?;
	log::debug!("x25519 pk: {:02x?}", pubkey);

	Ok((seckey, pubkey))
}

/// Reads and decodes the private key stored in `key_path`.
///
/// It supports Crypt4GH and OpenSSH private keys. Fails if it can not read the file
/// or if the key is not one of the two supported formats. Returns the decode key.
/// If the key is encrypted, the `callback` should return the passphrase of the key.
///
pub fn get_private_key(key_path: &Path, callback: impl Fn() -> Result<String>) -> Result<Vec<u8>> {
	let data = load_from_pem(key_path)?;

	if data.starts_with(C4GH_MAGIC_WORD) {
		log::info!("Loading a Crypt4GH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream
			.read_exact(&mut [0u8; C4GH_MAGIC_WORD.len()])
			.map_err(|e| anyhow!("Unable to read magic word from private key (ERROR = {:?})", e))?;
		parse_c4gh_private_key(stream, callback)
	}
	else if data.starts_with(SSH_MAGIC_WORD) {
		log::info!("Loading an OpenSSH private key");
		let mut stream = BufReader::new(data.as_slice());
		stream
			.read_exact(&mut [0u8; SSH_MAGIC_WORD.len()])
			.map_err(|e| anyhow!("Unable to read magic word from private key (ERROR = {:?})", e))?;
		let (seckey, pubkey) = parse_ssh_private_key(stream, callback)?;
		Ok(vec![seckey, pubkey].concat())
	}
	else {
		Err(anyhow!("Unsupported key format"))
	}
}

/// Reads and decodes the public key stored in `key_path`.
///
/// It supports Crypt4GH and OpenSSH public keys. Fails if it can not read the file
/// or if the key is not one of the two supported formats. Returns the decoded key.
///
pub fn get_public_key(key_path: &Path) -> Result<Vec<u8>> {
	// Read lines from public key file
	match read_lines(key_path) {
		Ok(lines_vec) => {
			// Empty key
			if lines_vec.len() == 0 {
				Err(anyhow!("Empty public key at {:?}", key_path))
			}
			// CRYPT4GH key
			else if lines_vec[0].find("CRYPT4GH").is_some() {
				log::info!("Loading a Crypt4GH public key");
				base64::decode(&lines_vec[1])
					.map_err(|e| anyhow!("Unable to decode with base64 the public key (ERROR = {:?})", e))
			}
			// SSH key
			else if lines_vec[0].len() >= 4 && lines_vec[0].get(0..4).unwrap() == "ssh-" {
				log::info!("Loading an OpenSSH public key");
				Ok(ssh_get_public_key(&lines_vec[0])?.to_vec())
			}
			// Unsupported key
			else {
				Err(anyhow!("Unsupported key format"))
			}
		},
		Err(err) => {
			// Could not read lines
			Err(anyhow!("Error reading public key at {:?}: {:?}", key_path, err))
		},
	}
}

fn ssh_get_public_key(line: &str) -> Result<[u8; 32]> {
	if &line[4..11] != "ed25519" {
		bail!("Unsupported SSH key format: {}", &line[0..11]);
	}

	let pkey = base64::decode(
		line[12..]
			.split(' ')
			.take(1)
			.next()
			.ok_or_else(|| anyhow!("Unable to parse ssh public key"))?,
	)
	.map_err(|e| anyhow!("Unable to decode with base64 the public key (ERROR = {:?})", e))?;
	let mut pkey_stream = Cursor::new(pkey);

	let key_type = decode_string_ssh(&mut pkey_stream)?;
	ensure!(key_type == "ssh-ed25519".as_bytes(), "Unsupported public key type");

	let pubkey_bytes = decode_string_ssh(&mut pkey_stream)?;
	convert_ed25519_pk_to_curve25519(&pubkey_bytes)
}

fn convert_ed25519_pk_to_curve25519(ed25519_pk: &[u8]) -> Result<[u8; 32]> {
	let mut curve_pk = [0u8; 32];
	let ok =
		unsafe { libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(curve_pk.as_mut_ptr(), ed25519_pk.as_ptr()) == 0 };
	if ok {
		Ok(curve_pk)
	}
	else {
		Err(anyhow!("Conversion from ed25519 to curve25519 failed"))
	}
}

fn convert_ed25519_sk_to_curve25519(ed25519_sk: &[u8]) -> Result<[u8; 32]> {
	let mut curve_sk = [0u8; 32];
	let ok =
		unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(curve_sk.as_mut_ptr(), ed25519_sk.as_ptr()) == 0 };
	if ok {
		Ok(curve_sk)
	}
	else {
		Err(anyhow!("Conversion from ed25519 to curve25519 failed"))
	}
}

/// Generates a random privary key.
///
/// It generates 32 random bytes and calculates the public key using the curve25519 algorithm.
/// The resulting private key has a length of 64. The first 32 bytes belong to the secret key,
/// the last 32 bytes belong to the public key.
///
pub fn generate_private_key() -> Vec<u8> {
	let seckey = randombytes(32);
	let scalar = sodiumoxide::crypto::scalarmult::Scalar::from_slice(&seckey[0..32])
		.expect("Decryption failed -> Unable to extract public key");
	let pubkey = sodiumoxide::crypto::scalarmult::scalarmult_base(&scalar).0.to_vec();
	vec![seckey, pubkey].concat()
}

/// Generates a pair of Crypt4GH keys.
///
/// It creates two files, one for the public key and another for the private key. It stores the
/// keys following the [Crypt4GH format](https://ega-archive.github.io/crypt4gh-rust/3_key_format.html).
/// The passphrase callback should return a string that will be used to encode the keys. You can add
/// an optional comment at the end of the keys.
///
pub fn generate_keys(
	seckey: &Path,
	pubkey: &Path,
	passphrase_callback: impl Fn() -> Result<String>,
	comment: Option<&str>,
) -> Result<()> {
	let skpk = generate_private_key();
	log::debug!("Private Key: {:02x?}", skpk);

	// Public key permissions (read & write)
	let mut pk_file = File::create(pubkey).expect("Unable to create public key file");
	let mut permissions = pk_file.metadata().unwrap().permissions();
	permissions.set_readonly(false);
	pk_file.set_permissions(permissions).unwrap();

	// Write public key
	let (_, pk) = skpk.split_at(32);
	log::debug!("Public Key: {:02x?}", pk);
	pk_file.write_all(b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n").unwrap();
	pk_file.write_all(base64::encode(pk).as_bytes()).unwrap();
	pk_file.write_all(b"\n-----END CRYPT4GH PUBLIC KEY-----\n").unwrap();

	// Secret key file open
	let mut sk_file = File::create(seckey).unwrap();

	// Write secret key
	let passphrase = passphrase_callback().unwrap();
	let sk = encode_private_key(skpk, passphrase, comment)?;
	log::debug!("Encoded Private Key: {:02x?}", sk);
	sk_file.write_all(b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n").unwrap();
	sk_file.write_all(base64::encode(sk).as_bytes()).unwrap();
	sk_file.write_all(b"\n-----END CRYPT4GH PRIVATE KEY-----\n").unwrap();

	// Secret key file permissions (read only)
	let mut permissions = sk_file.metadata().unwrap().permissions();
	permissions.set_readonly(true);
	sk_file.set_permissions(permissions).unwrap();

	Ok(())
}

fn encode_string_c4gh(s: Option<&[u8]>) -> Vec<u8> {
	let string = s.unwrap_or("none".as_bytes());
	vec![(string.len() as u16).to_be_bytes().to_vec(), string.to_vec()].concat()
}

fn encode_private_key(skpk: Vec<u8>, passphrase: String, comment: Option<&str>) -> Result<Vec<u8>> {
	assert!(skpk.len() == 64);

	Ok(if passphrase.is_empty() {
		log::warn!("The private key is not encrypted");
		vec![
			C4GH_MAGIC_WORD.to_vec(),
			encode_string_c4gh(None), // KDF = None
			encode_string_c4gh(None), // Cipher = None
			encode_string_c4gh(Some(&skpk)),
			match comment {
				Some(c) => encode_string_c4gh(Some(c.as_bytes())),
				None => encode_string_c4gh(Some("".as_bytes())),
			},
		]
		.concat()
	}
	else {
		let kdfname = "scrypt";
		let (salt_size, rounds) = get_kdf(kdfname)?;
		let salt = randombytes(salt_size);
		let derived_key = derive_key(kdfname.to_string(), passphrase, Some(salt.clone()), Some(rounds), 32)?;
		let nonce_bytes = randombytes(12);
		let nonce = chacha20poly1305_ietf::Nonce::from_slice(&nonce_bytes).unwrap();
		let key = chacha20poly1305_ietf::Key::from_slice(&derived_key).unwrap();
		let encrypted_key = chacha20poly1305_ietf::seal(&skpk, None, &nonce, &key);

		log::debug!("Derived Key: {:02x?}", derived_key);
		log::debug!("Salt: {:02x?}", salt);
		log::debug!("Nonce: {:02x?}", nonce.0.to_vec());

		vec![
			C4GH_MAGIC_WORD.to_vec(),
			encode_string_c4gh(Some(kdfname.as_bytes())),
			encode_string_c4gh(Some(&vec![(rounds as u32).to_be_bytes().to_vec(), salt].concat())),
			encode_string_c4gh(Some("chacha20_poly1305".as_bytes())),
			encode_string_c4gh(Some(&vec![nonce.0.to_vec(), encrypted_key].concat())),
			match comment {
				Some(c) => encode_string_c4gh(Some(c.as_bytes())),
				None => [].to_vec(),
			},
		]
		.concat()
	})
}

fn get_kdf(kdfname: &str) -> Result<(usize, u32)> {
	KDFS.get(kdfname).cloned().ok_or_else(|| anyhow!("Unsupported KDF"))
}
