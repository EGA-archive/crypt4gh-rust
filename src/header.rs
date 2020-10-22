use std::collections::HashSet;

use crate::Keys;
use rand::Rng;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305;
use sodiumoxide::crypto::kx::x25519blake2b;
use sodiumoxide::crypto::{
	aead::chacha20poly1305_ietf,
	kx::{PublicKey, SecretKey},
};

const PACKET_TYPE_DATA_ENC: [u8; 4] = [b'\x00', b'\x00', b'\x00', b'\x00'];
const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

pub fn make_packet_data_enc(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
	vec![
		PACKET_TYPE_DATA_ENC.to_vec(),
		encryption_method.to_le_bytes().to_vec(),
		session_key.to_vec(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(data: &Vec<u8>, seckey: &Vec<u8>, recipient_pubkey: &Vec<u8>) -> Vec<u8> {
	let pubkey = curve25519xsalsa20poly1305::SecretKey::from_slice(seckey)
		.unwrap()
		.public_key();

	// Log
	eprintln!("   packed data: {:x?}", data);
	eprintln!("   my public key: {:x?}", pubkey);
	eprintln!("   my private key: {:x?}", seckey);
	eprintln!("   recipient public key: {:x?}", recipient_pubkey);

	// X25519 shared key
	let server_pk = PublicKey::from_slice(pubkey.as_ref()).unwrap();
	let server_sk = SecretKey::from_slice(seckey).unwrap();
	let client_pk = PublicKey::from_slice(recipient_pubkey).unwrap();
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk).unwrap();
	eprintln!("   shared key: {:x?}", shared_key.0);

	// Nonce & chacha20 key
	let nonce = chacha20poly1305_ietf::Nonce::from_slice(&rand::thread_rng().gen::<[u8; 12]>()).unwrap();
	let key = chacha20poly1305_ietf::Key::from_slice(shared_key.as_ref()).unwrap();

	chacha20poly1305_ietf::seal(data, None, &nonce, &key)
}

pub fn encrypt(packet: Vec<u8>, recipient_keys: &HashSet<Keys>) -> Vec<Vec<u8>> {
	recipient_keys
		.iter()
		.filter(|key| key.method == 0)
		.map(|key| {
			vec![
				key.method.to_le_bytes().to_vec(),
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
		VERSION.to_le_bytes().to_vec(),
		packets.len().to_le_bytes().to_vec(),
		packets
			.into_iter()
			.map(|packet| vec![(packet.len() + 4).to_le_bytes().to_vec(), packet].concat())
			.flatten()
			.collect::<Vec<u8>>(),
	]
	.concat()
}
