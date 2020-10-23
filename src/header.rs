use std::collections::HashSet;

use crate::Keys;
use sodiumoxide::crypto::{
	aead::chacha20poly1305_ietf,
	kx::{PublicKey, SecretKey},
};
use sodiumoxide::{crypto::kx::x25519blake2b, randombytes};

const PACKET_TYPE_DATA_ENC: [u8; 4] = 0u32.to_le_bytes();
const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

pub fn make_packet_data_enc(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
	vec![
		PACKET_TYPE_DATA_ENC.to_vec(),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_key.to_vec(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(data: &Vec<u8>, seckey: &Vec<u8>, recipient_pubkey: &Vec<u8>) -> Vec<u8> {
	let pubkey = crypto::curve25519::curve25519_base(seckey);

	// Log
	eprintln!("   packed data({}): {:x?}", data.len(), data);
	eprintln!("   my public key({}): {:x?}", pubkey.len(), pubkey);
	eprintln!("   my private key({}): {:x?}", seckey[0..32].len(), &seckey[0..32]);
	eprintln!(
		"   recipient public key({}): {:x?}",
		recipient_pubkey.len(),
		recipient_pubkey
	);

	// X25519 shared key
	let server_pk = PublicKey::from_slice(pubkey.as_ref()).unwrap();
	let server_sk = SecretKey::from_slice(&seckey[0..32]).unwrap();
	let client_pk = PublicKey::from_slice(recipient_pubkey).unwrap();
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk).unwrap();
	eprintln!("   shared key: {:x?}", shared_key.0);

	// Nonce & chacha20 key
	let nonce = chacha20poly1305_ietf::Nonce::from_slice(&randombytes::randombytes(12)).unwrap();
	let key = chacha20poly1305_ietf::Key::from_slice(shared_key.as_ref()).unwrap();

	vec![
		pubkey.to_vec(),
		nonce.0.to_vec(),
		chacha20poly1305_ietf::seal(data, None, &nonce, &key),
	]
	.concat()
}

pub fn encrypt(packet: Vec<u8>, recipient_keys: &HashSet<Keys>) -> Vec<Vec<u8>> {
	recipient_keys
		.iter()
		.filter(|key| key.method == 0)
		.map(|key| {
			vec![
				(key.method as u32).to_le_bytes().to_vec(),
				encrypt_x25519_chacha20_poly1305(&packet, &key.privkey, &key.recipient_pubkey),
			]
			.concat()
		})
		.collect()
}

pub fn serialize(packets: Vec<Vec<u8>>) -> Vec<u8> {
	eprintln!("Serializing the header ({} packets)", packets.len());
	vec![
		MAGIC_NUMBER.to_vec(),
		(VERSION as u32).to_le_bytes().to_vec(),
		(packets.len() as u32).to_le_bytes().to_vec(),
		packets
			.into_iter()
			.map(|packet| vec![((packet.len() + 4) as u32).to_le_bytes().to_vec(), packet].concat())
			.flatten()
			.collect::<Vec<u8>>(),
	]
	.concat()
}
