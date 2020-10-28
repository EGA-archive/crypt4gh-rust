use std::collections::HashSet;

use crate::Keys;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
	aead::chacha20poly1305_ietf,
	kx::{PublicKey, SecretKey},
};
use sodiumoxide::{crypto::kx::x25519blake2b, randombytes};

const PACKET_TYPE_DATA_ENC: &[u8] = &0u32.to_le_bytes(); // 4 bytes
const PACKET_TYPE_EDIT_LIST: &[u8] = &1u32.to_le_bytes(); // 4 bytes
const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderInfo {
	pub magic_number: [u8; 8],
	pub version: u32,
	pub packets_count: u32,
}

pub fn make_packet_data_enc(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
	vec![
		PACKET_TYPE_DATA_ENC.to_vec(),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_key.to_vec(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(data: &Vec<u8>, seckey: &Vec<u8>, recipient_pubkey: &Vec<u8>) -> Vec<u8> {
	let pubkey = crypto::curve25519::curve25519_base(&seckey[..32]);

	// Log
	log::debug!("   packed data({}): {:02x?}", data.len(), data);
	log::debug!("   my public key({}): {:02x?}", pubkey.len(), pubkey);
	log::debug!("   my private key({}): {:02x?}", seckey[0..32].len(), &seckey[0..32]);
	log::debug!(
		"   recipient public key({}): {:02x?}",
		recipient_pubkey.len(),
		recipient_pubkey
	);

	// X25519 shared key
	let server_pk = PublicKey::from_slice(pubkey.as_ref()).unwrap();
	let server_sk = SecretKey::from_slice(&seckey[0..32]).unwrap();
	let client_pk = PublicKey::from_slice(recipient_pubkey).unwrap();
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk).unwrap();
	log::debug!("   shared key: {:02x?}", shared_key.0);

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
	log::info!("Serializing the header ({} packets)", packets.len());
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

fn decrypt(
	encrypted_packets: Vec<Vec<u8>>,
	keys: Vec<Keys>,
	sender_pubkey: Option<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	let mut decrypted_packets = Vec::new();
	let mut ignored_packets = Vec::new();

	for packet in encrypted_packets.into_iter() {
		match decrypt_packet(&packet, &keys, &sender_pubkey) {
			Some(decrypted_packet) => decrypted_packets.push(decrypted_packet),
			None => ignored_packets.push(packet),
		}
	}

	(decrypted_packets, ignored_packets)
}

fn decrypt_packet(packet: &Vec<u8>, keys: &Vec<Keys>, sender_pubkey: &Option<Vec<u8>>) -> Option<Vec<u8>> {
	let packet_encryption_method = bincode::deserialize::<u32>(packet).unwrap();
	log::debug!("Header Packet Encryption Method: {}", packet_encryption_method);

	for key in keys {
		if packet_encryption_method != (key.method as u32) {
			continue;
		}

		match packet_encryption_method {
			0 => {
				return Some(decrypt_x25519_chacha20_poly1305(
					&packet[4..],
					key.privkey.to_owned(),
					&sender_pubkey,
				));
				// TODO: Error handling
			},
			1 => unimplemented!("AES-256-GCM support is not implemented"),
			n => panic!("Unsupported Header Encryption Method: {}", n),
		}
	}

	None
}

fn decrypt_x25519_chacha20_poly1305(
	encrypted_part: &[u8],
	privkey: Vec<u8>,
	sender_pubkey: &Option<Vec<u8>>,
) -> Vec<u8> {
	log::debug!("    my secret key: {:02x?}", &privkey[0..32]);

	let peer_pubkey = &encrypted_part[0..32];

	if sender_pubkey.is_some() && sender_pubkey.to_owned().unwrap().as_slice() != peer_pubkey {
		panic!("Invalid Peer's Public Key")
	}

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&encrypted_part[32..44]).unwrap();
	let packet_data = &encrypted_part[44..];

	log::debug!("    peer pubkey: {:02x?}", peer_pubkey);
	log::debug!("    nonce: {:02x?}", nonce.0);
	log::debug!("    encrypted data ({}): {:02x?}", packet_data.len(), packet_data);

	// X25519 shared key
	let pubkey = crypto::curve25519::curve25519_base(&privkey[0..32]);
	let client_pk = PublicKey::from_slice(&pubkey).unwrap();
	let client_sk = SecretKey::from_slice(&privkey[0..32]).unwrap();
	let server_pk = PublicKey::from_slice(&peer_pubkey).unwrap();
	let (shared_key, _) = x25519blake2b::client_session_keys(&client_pk, &client_sk, &server_pk).unwrap();
	log::debug!("shared key: {:02x?}", shared_key.0);

	// Chacha20_Poly1305
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0).unwrap();
	chacha20poly1305_ietf::open(packet_data, None, &nonce, &key).unwrap()
}

fn partition_packets(packets: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
	let mut enc_packets = Vec::new();
	let mut edits = None;

	for packet in packets.into_iter() {
		match &packet[0..4] {
			PACKET_TYPE_DATA_ENC => {
				enc_packets.push(packet[4..].to_vec());
			},
			PACKET_TYPE_EDIT_LIST => {
				match edits {
					Some(_) => panic!("Invalid file: Too many edit list packets"),
					None => edits = Some(packet[4..].to_vec()),
				};
			},
			packet_type => {
				let packet_type_u32: u32 = bincode::deserialize(packet_type).unwrap();
				panic!("Invalid packet type {}", packet_type_u32);
			},
		}
	}

	(enc_packets, edits)
}

fn parse_enc_packet(packet: Vec<u8>) -> Vec<u8> {
	if packet[0..4] != [0, 0, 0, 0] {
		panic!(
			"Unsupported bulk encryption method: {}",
			bincode::deserialize::<u32>(&packet).unwrap()
		)
	}

	packet[4..].to_vec()
}

fn parse_edit_list_packet(packet: Vec<u8>) -> Vec<u64> {
	let nb_lengths: u32 = bincode::deserialize(&packet).unwrap();

	log::info!("Edit list length: {}", nb_lengths);
	log::info!("packet content length: {}", packet.len() - 4);

	if packet.len() as u32 - 4 < 8 * nb_lengths {
		panic!("Invalid edit list")
	}

	(4..nb_lengths * 8)
		.step_by(8)
		.map(|i| bincode::deserialize::<u64>(&packet[i as usize..]).unwrap())
		.collect()
}

pub fn deconstruct_header_body(
	encrypted_packets: Vec<Vec<u8>>,
	keys: Vec<Keys>,
	sender_pubkey: Option<Vec<u8>>,
) -> (Vec<Vec<u8>>, Option<Vec<u64>>) {
	let (packets, _) = decrypt(encrypted_packets, keys, sender_pubkey);

	if packets.is_empty() {
		panic!("No supported encryption method");
	}

	let (data_packets, edit_packet) = partition_packets(packets);

	let session_keys = data_packets
		.into_iter()
		.map(|packet| parse_enc_packet(packet))
		.collect::<Vec<_>>();

	let edit_list = match edit_packet {
		Some(packet) => Some(parse_edit_list_packet(packet)),
		None => None,
	};

	(session_keys, edit_list)
}

pub fn deconstruct_header_info(header_info_file: &[u8; std::mem::size_of::<HeaderInfo>()]) -> HeaderInfo {
	let header_info: HeaderInfo = bincode::deserialize(header_info_file).unwrap();

	assert_eq!(&header_info.magic_number, MAGIC_NUMBER, "Not a CRYPT4GH formatted file");
	assert_eq!(
		header_info.version, VERSION,
		"Unsupported CRYPT4GH version (version = {})",
		header_info.version
	);

	header_info
}
