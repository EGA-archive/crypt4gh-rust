use sodiumoxide::crypto::aead::chacha20poly1305_ietf::{self, Key, Nonce};
use std::{
	collections::HashSet,
	io::{self, Read},
};

mod header;

const SEGMENT_SIZE: usize = 65536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + CIPHER_DIFF;

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
	log::debug!("Start: {}, Span: {:?}", range_start, range_span);

	if recipient_keys.is_empty() {
		panic!("No Recipients' Public Key found")
	}

	log::info!("Encrypting the file");
	log::debug!("    Start Coordinate: {}", range_start);

	// Seek
	if range_start > 0 {
		log::info!("Forwarding to position: {}", range_start);
	}

	// TODO: read_buffer.seek(SeekFrom::Start(range_start as u64)).unwrap();
	read_buffer.read_exact(&mut vec![0u8; range_start]).unwrap();

	log::debug!("    Span: {:?}", range_span);

	let encryption_method = 0;
	let mut session_key = [0u8; 32];
	sodiumoxide::randombytes::randombytes_into(&mut session_key);

	log::info!("Creating Crypt4GH header");

	let header_content = header::make_packet_data_enc(encryption_method, &session_key);
	let header_packets = header::encrypt(header_content, recipient_keys);
	let header_bytes = header::serialize(header_packets);

	log::debug!("header length: {}", header_bytes.len());

	write_callback(&header_bytes).unwrap();

	log::info!("Streaming content");

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

	log::info!("Encryption Successful");
}

fn _encrypt_segment(data: &[u8], nonce: Nonce, key: Key) -> Vec<u8> {
	vec![nonce.0.to_vec(), chacha20poly1305_ietf::seal(data, None, &nonce, &key)].concat()
}

pub fn decrypt(
	keys: Vec<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> io::Result<()>,
	range_start: usize,
	range_span: Option<usize>,
	sender_pubkey: Option<Vec<u8>>,
) {
	match range_span {
		Some(span) => log::info!("Decrypting file | Range: [{}, {})", range_start, range_start + span + 1),
		None => log::info!("Decrypting file | Range: [{}, EOF)", range_start),
	}

	// Get header info
	let mut temp_buf = [0u8; 16]; // Size of the header
	read_buffer.read_exact(&mut temp_buf).unwrap();
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf);

	// Calculate header packets
	let encrypted_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0u8; 4];
			read_buffer.read_exact(&mut length_buffer).unwrap();
			let length = bincode::deserialize::<u32>(&length_buffer).unwrap() - 4;

			// Get data
			let mut encrypted_data = vec![0u8; length as usize];
			read_buffer.read_exact(&mut encrypted_data).unwrap();
			encrypted_data
		})
		.collect();

	let (session_keys, edit_list) = header::deconstruct_header_body(encrypted_packets, keys, sender_pubkey);

	match range_span {
		Some(span) => log::info!("Slicing from {} | Keeping {} bytes", range_start, span),
		None => log::info!("Slicing from {} | Keeping all bytes", range_start),
	}

	assert!(range_span.is_none() || range_span.unwrap() > 0);

	// Iterator to slice the output
	let write_func = |segment| {
		write_segment(range_start, range_span, write_callback, segment);
	};

	match edit_list {
		None => body_decrypt(read_buffer, session_keys, write_func, range_start),
		Some(edit_list_content) => body_decrypt_parts(read_buffer, session_keys, write_func, edit_list_content),
	}

	log::info!("Decryption Over");
}

fn body_decrypt_parts(
	_read_buffer: impl Read,
	_session_keys: Vec<Vec<u8>>,
	_output: impl Fn(Vec<u8>),
	_edit_list: Vec<u64>,
) {
	unimplemented!()
}

fn body_decrypt(mut read_buffer: impl Read, session_keys: Vec<Vec<u8>>, output: impl Fn(Vec<u8>), range_start: usize) {
	if range_start >= SEGMENT_SIZE {
		let start_segment = range_start / SEGMENT_SIZE;
		log::info!("Fast-forwarding {} segments", start_segment);
		let start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE;
		read_buffer.read_exact(&mut vec![0u8; start_ciphersegment]).unwrap();
	}

	loop {
		let mut chunk = Vec::with_capacity(CIPHER_SEGMENT_SIZE);
		let n = read_buffer
			.by_ref()
			.take(CIPHER_SEGMENT_SIZE as u64)
			.read_to_end(&mut chunk)
			.unwrap();

		if n == 0 {
			break;
		}

		let segment = decrypt_block(chunk, &session_keys);
		output(segment);

		if n < CIPHER_SEGMENT_SIZE {
			break;
		}
	}
}

fn decrypt_block(ciphersegment: Vec<u8>, session_keys: &Vec<Vec<u8>>) -> Vec<u8> {
	let (nonce_slice, data) = ciphersegment.split_at(12);
	let nonce = chacha20poly1305_ietf::Nonce::from_slice(nonce_slice).unwrap();

	session_keys
		.iter()
		.filter_map(|key| {
			let key = chacha20poly1305_ietf::Key::from_slice(key).unwrap();
			chacha20poly1305_ietf::open(data, None, &nonce, &key).ok()
		})
		.next()
		.expect("Could not decrypt that block (probably wrong keys were supplied)")
}

fn write_segment(_offset: usize, _limit: Option<usize>, write_callback: fn(&[u8]) -> io::Result<()>, data: Vec<u8>) {
	// TODO: This a minimal implementation

	write_callback(&data).unwrap();
}
