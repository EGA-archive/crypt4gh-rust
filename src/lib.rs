use sodiumoxide::crypto::aead::chacha20poly1305_ietf::{self, Key, Nonce};
use std::{
	collections::HashSet,
	io::{self, Read, Seek, SeekFrom, Write},
};

mod header;

const SEGMENT_SIZE: usize = 65536;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Keys {
	pub method: u8,
	pub privkey: Vec<u8>,
	pub recipient_pubkey: Vec<u8>,
}

pub fn encrypt(
	recipient_keys: &HashSet<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> io::Result<()>,
	range_start: usize,
	range_span: Option<usize>,
) {
	eprintln!("RECIPIENT KEYS");
	for key in recipient_keys {
		eprintln!("{:?}", key);
	}
	eprintln!("");

	eprintln!("Start: {}, Span: {:?}", range_start, range_span);

	if recipient_keys.is_empty() {
		panic!("No Recipients' Public Key found")
	}

	eprintln!("Encrypting the file");
	eprintln!("    Start Coordinate: {}", range_start);

	// Seek
	if range_start > 0 {
		eprintln!("Forwarding to position: {}", range_start);
	}
	// TODO: read_buffer.seek(SeekFrom::Start(range_start as u64)).unwrap();
	let mut temp_buff = Vec::with_capacity(range_start);
	read_buffer.read_exact(&mut temp_buff).unwrap();

	eprintln!("    Span: {:?}", range_span);

	let encryption_method = 0;
	let mut session_key = [0u8; 32];
	sodiumoxide::randombytes::randombytes_into(&mut session_key);

	eprintln!("Creating Crypt4GH header");

	let header_content = header::make_packet_data_enc(encryption_method, &session_key);
	let header_packets = header::encrypt(header_content, recipient_keys);
	let header_bytes = header::serialize(header_packets);

	eprintln!("header length: {}", header_bytes.len());

	write_callback(&header_bytes).unwrap();

	eprintln!("Streaming content");

	let mut segment = [0u8; SEGMENT_SIZE];

	// The whole file
	if range_span.is_none() || range_span.unwrap() == 0 {
		loop {
			let segment_result = read_buffer.read(&mut segment);
			match segment_result {
				Ok(segment_len) => {
					if segment_len == 0 {
						break;
					}
					else if segment_len < SEGMENT_SIZE {
						let (data, _) = segment.split_at(segment_len);
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.unwrap();
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data).unwrap();
						break;
					}
					else {
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.unwrap();
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
						let encrypted_data = _encrypt_segment(&segment, nonce, key);
						write_callback(&encrypted_data).unwrap();
					}
				},
				Err(m) => panic!("Error reading input {:?}", m),
			}
		}
	}
	// With a max size
	else {
		let mut remaining_length = range_span.unwrap();
		while remaining_length > 0 {
			let segment_result = read_buffer.read(&mut segment);
			match segment_result {
				Ok(segment_len) => {
					// Stop
					if segment_len >= remaining_length {
						let (data, _) = segment.split_at(remaining_length);
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.unwrap();
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data).unwrap();
						break;
					}

					// Not a full segment
					if segment_len < SEGMENT_SIZE {
						let (data, _) = segment.split_at(segment_len);
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.unwrap();
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data).unwrap();
						break;
					}

					let nonce =
						chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12)).unwrap();
					let key = chacha20poly1305_ietf::Key::from_slice(&session_key).unwrap();
					let encrypted_data = _encrypt_segment(&segment, nonce, key);
					write_callback(&encrypted_data).unwrap();

					remaining_length -= segment_len;
				},
				Err(m) => panic!("Error reading input {:?}", m),
			}
		}
	}

	eprintln!("Encryption Successful");
}

fn _encrypt_segment(data: &[u8], nonce: Nonce, key: Key) -> Vec<u8> {
	chacha20poly1305_ietf::seal(data, None, &nonce, &key)
}

pub fn decrypt() {}
