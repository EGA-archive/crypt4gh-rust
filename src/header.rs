use std::collections::HashSet;

use crate::Keys;
use anyhow::{anyhow, ensure};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
	aead::chacha20poly1305_ietf,
	kx::{PublicKey, SecretKey},
};
use sodiumoxide::{crypto::kx::x25519blake2b, randombytes};

const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, PartialEq)]
enum PacketType {
	DataEnc = 0,
	EditList = 1,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderInfo {
	pub magic_number: [u8; 8],
	pub version: u32,
	pub packets_count: u32,
}

pub fn make_packet_data_enc(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
	vec![
		bincode::serialize(&PacketType::DataEnc).expect("Unable to serialize packet type"),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_key.to_vec(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(data: &Vec<u8>, seckey: &Vec<u8>, recipient_pubkey: &Vec<u8>) -> Result<Vec<u8>> {
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
	let server_pk = PublicKey::from_slice(pubkey.as_ref())
		.ok_or_else(|| anyhow!("Excryption failed -> Unable to extract public server key"))?;
	let server_sk = SecretKey::from_slice(&seckey[0..32])
		.ok_or_else(|| anyhow!("Excryption failed -> Unable to extract private server key"))?;
	let client_pk = PublicKey::from_slice(recipient_pubkey)
		.ok_or_else(|| anyhow!("Excryption failed -> Unable to extract public client key"))?;
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk)
		.map_err(|_| anyhow!("Excryption failed -> Unable to create shared key"))?;
	log::debug!("   shared key: {:02x?}", shared_key.0);

	// Nonce & chacha20 key
	let nonce = chacha20poly1305_ietf::Nonce::from_slice(&randombytes::randombytes(12))
		.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
	let key = chacha20poly1305_ietf::Key::from_slice(shared_key.as_ref())
		.ok_or_else(|| anyhow!("Excryption failed -> Unable to wrap shared key"))?;

	Ok(vec![
		pubkey.to_vec(),
		nonce.0.to_vec(),
		chacha20poly1305_ietf::seal(data, None, &nonce, &key),
	]
	.concat())
}

pub fn encrypt(packet: Vec<u8>, recipient_keys: &HashSet<Keys>) -> Result<Vec<Vec<u8>>> {
	recipient_keys
		.iter()
		.filter(|key| key.method == 0)
		.map(
			|key| match encrypt_x25519_chacha20_poly1305(&packet, &key.privkey, &key.recipient_pubkey) {
				Ok(session_key) => Ok(vec![(key.method as u32).to_le_bytes().to_vec(), session_key].concat()),
				Err(e) => Err(e),
			},
		)
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
	let (decrypted_packets_pairs, ignored_packets_pairs): (Vec<(bool, Vec<u8>)>, Vec<(bool, Vec<u8>)>) =
		encrypted_packets
			.into_iter()
			.map(|packet| match decrypt_packet(&packet, &keys, &sender_pubkey) {
				Ok(decrypted_packet) => (true, decrypted_packet),
				Err(_) => (false, packet),
			})
			.partition(|(is_decrypted, _)| *is_decrypted);

	let decrypted_packets = decrypted_packets_pairs
		.into_iter()
		.map(|(_, packet)| packet)
		.collect();

	let ignored_packets = ignored_packets_pairs
		.into_iter()
		.map(|(_, packet)| packet)
		.collect();

	(decrypted_packets, ignored_packets)
}

fn decrypt_packet(packet: &Vec<u8>, keys: &Vec<Keys>, sender_pubkey: &Option<Vec<u8>>) -> Result<Vec<u8>> {
	let packet_encryption_method = bincode::deserialize::<u32>(packet)?;
	log::debug!("Header Packet Encryption Method: {}", packet_encryption_method);

	for key in keys {
		if packet_encryption_method != (key.method as u32) {
			continue;
		}

		match packet_encryption_method {
			0 => return decrypt_x25519_chacha20_poly1305(&packet[4..], key.privkey.to_owned(), &sender_pubkey),
			1 => unimplemented!("AES-256-GCM support is not implemented"),
			n => bail!("Unsupported Header Encryption Method: {}", n),
		}
	}

	Err(anyhow!("Unable to encrypt packet"))
}

fn decrypt_x25519_chacha20_poly1305(
	encrypted_part: &[u8],
	privkey: Vec<u8>,
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>> {
	log::debug!("    my secret key: {:02x?}", &privkey[0..32]);

	let peer_pubkey = &encrypted_part[0..32];

	if sender_pubkey.is_some() && sender_pubkey.to_owned().unwrap().as_slice() != peer_pubkey {
		return Err(anyhow!("Invalid Peer's Public Key"));
	}

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&encrypted_part[32..44])
		.ok_or_else(|| anyhow!("Decryption failed -> Unable to extract nonce"))?;
	let packet_data = &encrypted_part[44..];

	log::debug!("    peer pubkey: {:02x?}", peer_pubkey);
	log::debug!("    nonce: {:02x?}", nonce.0);
	log::debug!("    encrypted data ({}): {:02x?}", packet_data.len(), packet_data);

	// X25519 shared key
	let pubkey = crypto::curve25519::curve25519_base(&privkey[0..32]);
	let client_pk = PublicKey::from_slice(&pubkey)
		.ok_or_else(|| anyhow!("Decryption failed -> Unable to extract public client key"))?;
	let client_sk = SecretKey::from_slice(&privkey[0..32])
		.ok_or_else(|| anyhow!("Decryption failed -> Unable to extract private client key"))?;
	let server_pk = PublicKey::from_slice(&peer_pubkey)
		.ok_or_else(|| anyhow!("Decryption failed -> Unable to extract public server key"))?;
	let (shared_key, _) = x25519blake2b::client_session_keys(&client_pk, &client_sk, &server_pk)
		.map_err(|_| anyhow!("Decryption failed -> Unable to create shared key"))?;
	log::debug!("shared key: {:02x?}", shared_key.0);

	// Chacha20_Poly1305
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0)
		.ok_or_else(|| anyhow!("Decryption failed -> Unable to wrap shared key"))?;
	chacha20poly1305_ietf::open(packet_data, None, &nonce, &key)
		.map_err(|_| anyhow!("Decryption failed -> Invalid data"))
}

fn partition_packets(packets: Vec<Vec<u8>>) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>)> {
	let mut enc_packets = Vec::new();
	let mut edits = None;

	for packet in packets.into_iter() {
		let packet_type =
			bincode::deserialize::<PacketType>(&packet[0..4]).map_err(|_| anyhow!("Invalid packet type"))?;

		match packet_type {
			PacketType::DataEnc => {
				enc_packets.push(packet[4..].to_vec());
			},
			PacketType::EditList => {
				match edits {
					None => edits = Some(packet[4..].to_vec()),
					Some(_) => return Err(anyhow!("Invalid file: Too many edit list packets")),
				};
			},
		}
	}

	Ok((enc_packets, edits))
}

fn parse_enc_packet(packet: Vec<u8>) -> Result<Vec<u8>> {
	match packet[0..4] {
		[0, 0, 0, 0] => Ok(packet[4..].to_vec()),
		_ => Err(anyhow!(
			"Unsupported bulk encryption method: {}",
			bincode::deserialize::<u32>(&packet[0..4]).expect("Unable to deserialize bulk encryption method")
		)),
	}
}

fn parse_edit_list_packet(packet: Vec<u8>) -> Result<Vec<u64>> {
	let nb_lengths: u32 = bincode::deserialize(&packet)
		.map_err(|_| anyhow!("Edit list packet did not contain the length of the list"))?;

	log::info!("Edit list length: {}", nb_lengths);
	log::info!("packet content length: {}", packet.len() - 4);

	if packet.len() as u32 - 4 < 8 * nb_lengths {
		bail!("Invalid edit list")
	}

	(4..nb_lengths * 8)
		.step_by(8)
		.map(|i| {
			bincode::deserialize::<u64>(&packet[i as usize..])
				.map_err(|_| anyhow!("Unable to parse content of the edit list packet"))
		})
		.collect()
}

pub fn deconstruct_header_body(
	encrypted_packets: Vec<Vec<u8>>,
	keys: Vec<Keys>,
	sender_pubkey: Option<Vec<u8>>,
) -> Result<(Vec<Vec<u8>>, Option<Vec<u64>>)> {
	let (packets, _) = decrypt(encrypted_packets, keys, sender_pubkey);

	if packets.is_empty() {
		bail!("No supported encryption method");
	}

	let (data_packets, edit_packet) = partition_packets(packets)?;

	let session_keys = data_packets
		.into_iter()
		.map(|packet| parse_enc_packet(packet))
		.collect::<Result<Vec<_>>>()?;

	let edit_list = match edit_packet {
		Some(packet) => Some(parse_edit_list_packet(packet)?),
		None => None,
	};

	Ok((session_keys, edit_list))
}

pub fn deconstruct_header_info(header_info_file: &[u8; std::mem::size_of::<HeaderInfo>()]) -> Result<HeaderInfo> {
	let header_info: HeaderInfo =
		bincode::deserialize(header_info_file).map_err(|_| anyhow!("Unable to deconstruct header info"))?;

	ensure!(
		&header_info.magic_number == MAGIC_NUMBER,
		"Not a CRYPT4GH formatted file"
	);
	ensure!(
		header_info.version == VERSION,
		"Unsupported CRYPT4GH version (version = {})",
		header_info.version
	);

	Ok(header_info)
}
