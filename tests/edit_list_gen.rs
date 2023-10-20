#![allow(clippy::missing_panics_doc)]

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use crypt4gh::error::Crypt4GHError;
use chacha20poly1305::{ self, Key, Nonce };
use rand_chacha;
use rand::{Rng, SeedableRng};

pub fn generate(sk: &str, recipient_pk: &str, input: &str, outfile: &mut File, passphrase: &str) -> Result<(), Crypt4GHError> {
	let mut rng = rand::thread_rng();

	let parts = input.lines().collect::<Vec<_>>();
	let skips = parts.iter().copied().map(|_| rng.gen_range(10_000..100_000));

	let mut message = Vec::new();
	let mut edits = Vec::new();

	for (skip, part) in skips.into_iter().zip(parts.iter()) {
		message.extend((0..skip).map(|_| rand::random::<u8>()));
		message.extend(part.as_bytes().iter());
		edits.push(skip);
		edits.push(part.len());
	}

	log::debug!("Edits: {:?}", edits);

	// Fetch the keys

	log::debug!("SK: {:?}", sk);
	assert!(Path::new(sk).exists()); // TODO: Migrate to Crypt4GHError
	log::debug!("Recipient PK: {:?}", recipient_pk);
	assert!(Path::new(recipient_pk).exists(), "Edit list gen key not found"); // TODO: Migrate to Crypt4GHError

	let callback = Ok(passphrase.to_string());
	let seckey = crypt4gh::keys::get_private_key(PathBuf::from(sk), callback)?;
	let recipient_pubkey = crypt4gh::keys::get_public_key(PathBuf::from(recipient_pk))?;

	log::debug!("Sec: {:?}\n with length: {:?}", seckey, seckey.len());
	log::debug!("Pub: {:?}\n with length: {:?}", recipient_pubkey, recipient_pubkey.len());

	let keys = vec![crypt4gh::Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey,
	}]
	.into_iter()
	.collect();

	// Prepare encryption engine

	let encryption_method = 0; // Only choice for this version
	let session_key: [u8; 32] = rng.gen(); // We use one session key for all blocks

	// Output the header

	let packets = vec![
		crypt4gh::header::make_packet_data_enc(encryption_method, &session_key),
		crypt4gh::header::make_packet_data_edit_list(edits),
	];

	let header_packets = packets
		.into_iter()
		.flat_map(|packet| crypt4gh::header::encrypt(&packet, &keys).unwrap())
		.collect();
	let header_bytes = crypt4gh::header::serialize(header_packets);
	outfile.write_all(&header_bytes)?;

	log::debug!("header length: {}", header_bytes.len());

	// TODO: Perhaps migrate rest of this file to rnd instead of rng (crypto-safe PRNG?)
	let rnd = rand_chacha::ChaCha20Rng::from_entropy();
	let seed = &rnd.get_seed()[..12]; // TODO: Reasonable to cut seed like this?
	// Output the message
	for segment in message.chunks(crypt4gh::SEGMENT_SIZE) {
		let nonce = Nonce::from_slice(seed);
		let key = Key::from_slice(&session_key);
		let encrypted_segment = crypt4gh::encrypt_segment(segment, *nonce, &key)?;
		outfile.write_all(&encrypted_segment)?;
	}

	Ok(())
}
