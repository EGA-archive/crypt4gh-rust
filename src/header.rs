use std::collections::HashSet;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::kx::{x25519blake2b, PublicKey, SecretKey};
use sodiumoxide::randombytes;

use super::SEGMENT_SIZE;
use crate::error::Crypt4GHError;
use crate::keys::get_public_key_from_private_key;
use crate::Keys;
const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, PartialEq)]
enum HeaderPacketType {
	DataEnc = 0,
	EditList = 1,
}

struct HeaderPackets {
	data_enc_packets: Vec<Vec<u8>>,
	edit_list_packet: Option<Vec<u8>>,
}

/// Contains the parsed data of the packets
pub struct DecryptedHeaderPackets {
	/// The packets that are coded as data
	pub data_enc_packets: Vec<Vec<u8>>,
	/// The packets that are an edit list
	pub edit_list_packet: Option<Vec<u64>>,
}

/// Contains the basic information of the header.
#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderInfo {
	/// A “magic” string for file type identification. It should be the ASCII representation of the string "crypt4gh".
	pub magic_number: [u8; 8],
	/// A version number (four-byte little-endian). The current version is 1.
	pub version: u32,
	/// The number of packets that the header contains.
	pub packets_count: u32,
}

/// Constructs an encrypted data packet
pub fn make_packet_data_enc(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
	vec![
		bincode::serialize(&HeaderPacketType::DataEnc).expect("Unable to serialize packet type"),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_key.to_vec(),
	]
	.concat()
}

/// Constructs an edit list packet
pub fn make_packet_data_edit_list(edit_list: Vec<usize>) -> Vec<u8> {
	vec![
		bincode::serialize(&HeaderPacketType::EditList).unwrap(),
		(edit_list.len() as u32).to_le_bytes().to_vec(),
		edit_list
			.into_iter()
			.flat_map(|n| (n as u64).to_le_bytes().to_vec())
			.collect(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(
	data: &[u8],
	seckey: &[u8],
	recipient_pubkey: &[u8],
) -> Result<Vec<u8>, Crypt4GHError> {
	crate::init();
	let pubkey = get_public_key_from_private_key(seckey)?;

	// Log
	log::debug!("   packed data({}): {:02x?}", data.len(), data.iter().format(""));
	log::debug!("   my public key({}): {:02x?}", pubkey.len(), pubkey.iter().format(""));
	log::debug!(
		"   my private key({}): {:02x?}",
		seckey[0..32].len(),
		&seckey[0..32].iter().format("")
	);
	log::debug!(
		"   recipient public key({}): {:02x?}",
		recipient_pubkey.len(),
		recipient_pubkey.iter().format("")
	);

	// X25519 shared key
	let server_pk = PublicKey::from_slice(pubkey.as_ref()).ok_or(Crypt4GHError::BadServerPublicKey)?;
	let server_sk = SecretKey::from_slice(&seckey[0..32]).ok_or(Crypt4GHError::BadServerPrivateKey)?;
	let client_pk = PublicKey::from_slice(recipient_pubkey).ok_or(Crypt4GHError::BadClientPublicKey)?;
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk)
		.map_err(|_| Crypt4GHError::BadSharedKey)?;
	log::debug!("   shared key: {:02x?}", shared_key.0.iter().format(""));

	// Nonce & chacha20 key
	let nonce =
		chacha20poly1305_ietf::Nonce::from_slice(&randombytes::randombytes(12)).ok_or(Crypt4GHError::NoRandomNonce)?;
	let key = chacha20poly1305_ietf::Key::from_slice(shared_key.as_ref()).ok_or(Crypt4GHError::BadKey)?;

	Ok(vec![
		pubkey,
		nonce.0.to_vec(),
		chacha20poly1305_ietf::seal(data, None, &nonce, &key),
	]
	.concat())
}

/// Computes the encrypted part, using all keys
///
/// Given a set of keys and a vector of bytes, it iterates the keys and for every valid key (key.method == 0), it encrypts the packet.
/// It uses chacha20 and poly1305 to encrypt the packet. It returns a set of encrypted segments that represent the packet for every key.
///
/// * `packet` is a vector of bytes of information to be encrypted
/// * `keys` is a unique collection of keys with `key.method` == 0
pub fn encrypt(packet: &[u8], keys: &HashSet<Keys>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
	keys.iter()
		.filter(|key| key.method == 0)
		.map(
			|key| match encrypt_x25519_chacha20_poly1305(packet, &key.privkey, &key.recipient_pubkey) {
				Ok(session_key) => Ok(vec![u32::from(key.method).to_le_bytes().to_vec(), session_key].concat()),
				Err(e) => Err(e),
			},
		)
		.collect()
}

/// Serializes the header.
///
/// Returns [ Magic "crypt4gh" + version + packet count + header packets... ] serialized.
pub fn serialize(packets: Vec<Vec<u8>>) -> Vec<u8> {
	log::info!("Serializing the header ({} packets)", packets.len());
	vec![
		MAGIC_NUMBER.to_vec(),
		(VERSION as u32).to_le_bytes().to_vec(),
		(packets.len() as u32).to_le_bytes().to_vec(),
		packets
			.into_iter()
			.flat_map(|packet| vec![((packet.len() + 4) as u32).to_le_bytes().to_vec(), packet].concat())
			.collect::<Vec<u8>>(),
	]
	.concat()
}

fn decrypt(
	encrypted_packets: Vec<Vec<u8>>,
	keys: &[Keys],
	sender_pubkey: &Option<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	let mut decrypted_packets = Vec::new();
	let mut ignored_packets = Vec::new();

	for packet in encrypted_packets {
		match decrypt_packet(&packet, keys, sender_pubkey) {
			Ok(decrypted_packet) => decrypted_packets.push(decrypted_packet),
			Err(e) => {
				log::warn!("Ignoring packet because: {}", e);
				ignored_packets.push(packet)
			},
		}
	}

	(decrypted_packets, ignored_packets)
}

fn decrypt_packet(packet: &[u8], keys: &[Keys], sender_pubkey: &Option<Vec<u8>>) -> Result<Vec<u8>, Crypt4GHError> {
	let packet_encryption_method =
		bincode::deserialize::<u32>(packet).map_err(|_| Crypt4GHError::ReadPacketEncryptionMethod)?;
	log::debug!("Header Packet Encryption Method: {}", packet_encryption_method);

	for key in keys {
		if packet_encryption_method != u32::from(key.method) {
			continue;
		}

		match packet_encryption_method {
			0 => return decrypt_x25519_chacha20_poly1305(&packet[4..], &key.privkey, sender_pubkey),
			1 => unimplemented!("AES-256-GCM support is not implemented"),
			n => return Err(Crypt4GHError::BadHeaderEncryptionMethod(n)),
		}
	}

	Err(Crypt4GHError::UnableToEncryptPacket)
}

fn decrypt_x25519_chacha20_poly1305(
	encrypted_part: &[u8],
	privkey: &[u8],
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Crypt4GHError> {
	log::debug!("    my secret key: {:02x?}", &privkey[0..32].iter().format(""));

	let peer_pubkey = &encrypted_part[0..32];

	if sender_pubkey.is_some() && sender_pubkey.clone().unwrap().as_slice() != peer_pubkey {
		return Err(Crypt4GHError::InvalidPeerPubPkey);
	}

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&encrypted_part[32..44])
		.ok_or(Crypt4GHError::NoNonce)?;
	let packet_data = &encrypted_part[44..];

	log::debug!("    peer pubkey: {:02x?}", peer_pubkey.iter().format(""));
	log::debug!("    nonce: {:02x?}", nonce.0.iter().format(""));
	log::debug!(
		"    encrypted data ({}): {:02x?}",
		packet_data.len(),
		packet_data.iter().format("")
	);

	// X25519 shared key
	let pubkey = get_public_key_from_private_key(privkey)?;
	let client_pk = PublicKey::from_slice(&pubkey).ok_or(Crypt4GHError::BadClientPublicKey)?;
	let client_sk = SecretKey::from_slice(&privkey[0..32]).ok_or(Crypt4GHError::BadClientPrivateKey)?;
	let server_pk = PublicKey::from_slice(peer_pubkey).ok_or(Crypt4GHError::BadServerPublicKey)?;
	let (shared_key, _) = x25519blake2b::client_session_keys(&client_pk, &client_sk, &server_pk)
		.map_err(|_| Crypt4GHError::BadSharedKey)?;
	log::debug!("shared key: {:02x?}", shared_key.0.iter().format(""));

	// Chacha20_Poly1305
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0).ok_or(Crypt4GHError::BadSharedKey)?;
	chacha20poly1305_ietf::open(packet_data, None, &nonce, &key).map_err(|_| Crypt4GHError::InvalidData)
}

fn partition_packets(packets: Vec<Vec<u8>>) -> Result<HeaderPackets, Crypt4GHError> {
	let mut enc_packets = Vec::new();
	let mut edits = None;

	for packet in packets {
		let packet_type =
			bincode::deserialize::<HeaderPacketType>(&packet[0..4]).map_err(|_| Crypt4GHError::InvalidPacketType)?;

		match packet_type {
			HeaderPacketType::DataEnc => {
				enc_packets.push(packet[4..].to_vec());
			},
			HeaderPacketType::EditList => {
				match edits {
					None => edits = Some(packet[4..].to_vec()),
					Some(_) => return Err(Crypt4GHError::TooManyEditListPackets),
				};
			},
		}
	}

	Ok(HeaderPackets {
		data_enc_packets: enc_packets,
		edit_list_packet: edits,
	})
}

fn parse_enc_packet(packet: &[u8]) -> Result<Vec<u8>, Crypt4GHError> {
	match packet[0..4] {
		[0, 0, 0, 0] => Ok(packet[4..].to_vec()),
		_ => Err(Crypt4GHError::UnsupportedEncryptionMethod(
			bincode::deserialize::<u32>(&packet[0..4]).expect("Unable to deserialize bulk encryption method"),
		)),
	}
}

fn parse_edit_list_packet(packet: &[u8]) -> Result<Vec<u64>, Crypt4GHError> {
	let nb_lengths: u32 = bincode::deserialize::<u32>(packet).map_err(|_| Crypt4GHError::NoEditListLength)?;

	log::info!("Edit list length: {}", nb_lengths);
	log::info!("packet content length: {}", packet.len() - 4);

	if ((packet.len() as u32) - 4) < (8 * nb_lengths) {
		return Err(Crypt4GHError::InvalidEditList);
	}

	(4..nb_lengths * 8)
		.step_by(8)
		.map(|i| bincode::deserialize::<u64>(&packet[i as usize..]).map_err(|_| Crypt4GHError::InvalidEditList))
		.collect()
}

/// Gets data packets and edit list packets from the encrypted packets.
///
/// Decrypts the encrypted packets and partitions the encrypted packets in two groups,
/// the data packets and the edit list packets. Finally, it parses the packets.
pub fn deconstruct_header_body(
	encrypted_packets: Vec<Vec<u8>>,
	keys: &[Keys],
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<DecryptedHeaderPackets, Crypt4GHError> {
	let (packets, _) = decrypt(encrypted_packets, keys, sender_pubkey);

	if packets.is_empty() {
		return Err(Crypt4GHError::NoSupportedEncryptionMethod);
	}

	let HeaderPackets {
		data_enc_packets,
		edit_list_packet,
	} = partition_packets(packets)?;

	let session_keys = data_enc_packets
		.into_iter()
		.map(|d| parse_enc_packet(&d))
		.collect::<Result<Vec<_>, Crypt4GHError>>()?;

	let edit_list = match edit_list_packet {
		Some(packet) => Some(parse_edit_list_packet(&packet)?),
		None => None,
	};

	Ok(DecryptedHeaderPackets {
		data_enc_packets: session_keys,
		edit_list_packet: edit_list,
	})
}

/// Deserializes the data info from the header bytes.
///
/// Reads the magic number, the version and the number of packets from the bytes.
pub fn deconstruct_header_info(
	header_info_file: &[u8; std::mem::size_of::<HeaderInfo>()],
) -> Result<HeaderInfo, Crypt4GHError> {
	let header_info =
		bincode::deserialize::<HeaderInfo>(header_info_file).map_err(|e| Crypt4GHError::ReadHeaderError(e))?;

	assert!(
		&header_info.magic_number == MAGIC_NUMBER,
		"Not a CRYPT4GH formatted file"
	);
	assert!(
		header_info.version == VERSION,
		"Unsupported CRYPT4GH version (version = {})",
		header_info.version
	);

	Ok(header_info)
}

/// Reencrypts the header.
///
/// Decrypts the header using the `keys` and then, encrypts the content again for every
/// key in `recipient_keys`. If trim is specified, the packets that cannot be decrypted are discarded.
pub fn reencrypt(
	header_packets: Vec<Vec<u8>>,
	keys: &[Keys],
	recipient_keys: &HashSet<Keys>,
	trim: bool,
) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
	log::info!("Reencrypting the header");

	let (decrypted_packets, mut ignored_packets) = decrypt(header_packets, keys, &None);

	if decrypted_packets.is_empty() {
		Err(Crypt4GHError::NoValidHeaderPacket)
	}
	else {
		let mut packets: Vec<Vec<u8>> = decrypted_packets
			.into_iter()
			.flat_map(|packet| encrypt(&packet, recipient_keys).unwrap())
			.collect();

		if !trim {
			packets.append(&mut ignored_packets);
		}

		Ok(packets)
	}
}

/// Gets the packages to rearrange.
///
/// Rearranges the edit list in accordance to the range. It returns the data packets
/// along with an oracle that decides if the next packet should be kept (starting by the first).
pub fn rearrange<'a>(
	header_packets: Vec<Vec<u8>>,
	keys: Vec<Keys>,
	range_start: usize,
	range_span: Option<usize>,
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<(Vec<Vec<u8>>, impl Iterator<Item = bool> + 'a), Crypt4GHError> {
	log::info!("Rearranging the header");

	log::debug!("    Start coordinate: {}", range_start);
	if let Some(span) = range_span {
		log::debug!("    End coordinate: {}", range_start + span);
		assert!(span > 0, "Span should be greater than 0")
	}
	else {
		log::debug!("    End coordinate: EOF")
	}
	log::debug!("    Segment size: {}", SEGMENT_SIZE);

	if range_start == 0 && range_span.is_none() {
		return Err(Crypt4GHError::Done);
	}

	let (decrypted_packets, _) = decrypt(header_packets, &keys, sender_pubkey);

	if decrypted_packets.is_empty() {
		return Err(Crypt4GHError::NoValidHeaderPacket);
	}

	let HeaderPackets {
		data_enc_packets,
		edit_list_packet,
	} = partition_packets(decrypted_packets)?;

	if edit_list_packet.is_some() {
		unimplemented!()
	}

	log::info!("No edit list present: making one");

	let start_segment = range_start / SEGMENT_SIZE;
	let start_offset = range_start % SEGMENT_SIZE;
	let end_segment = range_span.map(|span| (range_start + span) / SEGMENT_SIZE);
	let end_offset = range_span.map(|span| (range_start + span) % SEGMENT_SIZE);

	log::debug!("Start segment: {} | Offset: {}", start_segment, start_offset);
	log::debug!("End segment: {:?} | Offset: {:?}", end_segment, end_offset);

	let segment_oracle = (0..).map(move |count| {
		if count < start_segment {
			false
		}
		else {
			match end_segment {
				Some(end) => count < end || (count == end && end_offset.unwrap() > 0),
				None => true,
			}
		}
	});

	let mut edit_list = vec![start_offset];
	if let Some(span) = range_span {
		edit_list.push(span);
	}

	log::debug!("New edit list: {:?}", edit_list);
	let edit_packet = make_packet_data_edit_list(edit_list);

	log::info!("Reencrypting all packets");

	let mut packets = data_enc_packets
		.into_iter()
		.map(|packet| vec![bincode::serialize(&HeaderPacketType::DataEnc).unwrap(), packet].concat())
		.collect::<Vec<Vec<u8>>>();

	packets.push(edit_packet);

	let hash_keys = keys.into_iter().collect::<HashSet<Keys>>();

	let final_packets = packets
		.into_iter()
		.map(|packet| encrypt(&packet, &hash_keys).map(|encrypted_packets| encrypted_packets.concat()))
		.collect::<Result<Vec<Vec<u8>>, Crypt4GHError>>()?;

	Ok((final_packets, segment_oracle))
}

#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	fn enum_serialization_0() {
		assert_eq!(
			bincode::serialize(&HeaderPacketType::DataEnc).unwrap(),
			0_u32.to_le_bytes()
		);
	}

	#[test]
	fn enum_serialization_1() {
		assert_eq!(
			bincode::serialize(&HeaderPacketType::EditList).unwrap(),
			1_u32.to_le_bytes()
		);
	}
}
