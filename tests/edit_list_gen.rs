#![allow(clippy::missing_panics_doc)]

use std::fs::File;
use std::io::Write;
use std::path::Path;

use rand::Rng;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;

pub fn generate(sk: &str, recipient_pk: &str, input: &str, outfile: &mut File, passphrase: &str) {
	let mut rng = rand::thread_rng();

	let parts = input.lines().collect::<Vec<_>>();
	let skips = parts.iter().copied().map(|_| rng.gen_range(10_000..100_000));

	let mut message = Vec::new();
	let mut edits = Vec::new();

	for (skip, part) in skips.into_iter().zip(parts.iter()) {
		message.extend((0..skip).map(|_| rand::random::<u8>()));
		message.extend(part.as_bytes().iter());
		edits.push(skip);
		edits.push(part.len())
	}

	eprintln!("Edits: {:?}", edits);

	// Fetch the keys

	assert!(Path::new(sk).exists());
	assert!(Path::new(recipient_pk).exists(), "Secret key not found");

	let callback = || Ok(passphrase.to_string());
	let seckey = crypt4gh::keys::get_private_key(Path::new(sk), callback).unwrap();
	let recipient_pubkey = crypt4gh::keys::get_public_key(Path::new(recipient_pk)).unwrap();

	eprintln!("Sec: {:?}", seckey);
	eprintln!("Pub: {:?}", recipient_pubkey);

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
	outfile.write_all(&header_bytes).unwrap();

	log::debug!("header length: {}", header_bytes.len());

	// Output the message
	sodiumoxide::init().expect("Unable to initialize libsodium");
	for segment in message.chunks(crypt4gh::SEGMENT_SIZE) {
		let nonce_bytes = sodiumoxide::randombytes::randombytes(12);
		let nonce = chacha20poly1305_ietf::Nonce::from_slice(&nonce_bytes).unwrap();
		let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
		let encrypted_segment = crypt4gh::encrypt_segment(segment, nonce, &key);
		outfile.write_all(&encrypted_segment).unwrap();
	}
}
