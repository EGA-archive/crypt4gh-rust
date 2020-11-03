use anyhow::{anyhow, bail, ensure, Result};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::{self, Key, Nonce};
use std::{
	collections::HashSet,
	io::{self, Read},
};

mod header;

const CHUNK_SIZE: usize = 4096;
const SEGMENT_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + CIPHER_DIFF;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Keys {
	pub method: u8,
	pub privkey: Vec<u8>,
	pub recipient_pubkey: Vec<u8>,
}

pub fn encrypt(
	recipient_keys: &HashSet<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> Result<()>,
	range_start: usize,
	range_span: Option<usize>,
) -> Result<()> {
	log::debug!("Start: {}, Span: {:?}", range_start, range_span);

	if recipient_keys.is_empty() {
		bail!("No Recipients' Public Key found")
	}

	log::info!("Encrypting the file");
	log::debug!("    Start Coordinate: {}", range_start);

	// Seek
	if range_start > 0 {
		log::info!("Forwarding to position: {}", range_start);
	}

	// TODO: read_buffer.seek(SeekFrom::Start(range_start as u64)).unwrap();
	// ALTERNATIVE?: io::copy(&mut read_buffer.by_ref().take(range_start as u64), &mut io::sink()).unwrap();
	read_buffer
		.read_exact(&mut vec![0u8; range_start])
		.map_err(|e| anyhow!("Unable to read {} bytes from input (ERROR = {:?})", range_start, e))?;

	log::debug!("    Span: {:?}", range_span);

	let encryption_method = 0;
	let mut session_key = [0u8; 32];
	sodiumoxide::randombytes::randombytes_into(&mut session_key);

	log::info!("Creating Crypt4GH header");

	let header_content = header::make_packet_data_enc(encryption_method, &session_key);
	let header_packets = header::encrypt(header_content, recipient_keys)?;
	let header_bytes = header::serialize(header_packets);

	log::debug!("header length: {}", header_bytes.len());

	write_callback(&header_bytes)?;

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
								.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key)
							.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data)?;
						break;
					}
					else {
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key)
							.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random session key"))?;
						let encrypted_data = _encrypt_segment(&segment, nonce, key);
						write_callback(&encrypted_data)?;
					}
				},
				Err(m) => bail!("Error reading input {:?}", m),
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
								.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key)
							.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random session key"))?;
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data)?;
						break;
					}

					// Not a full segment
					if segment_len < SEGMENT_SIZE {
						let (data, _) = segment.split_at(segment_len);
						let nonce =
							chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
								.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
						let key = chacha20poly1305_ietf::Key::from_slice(&session_key)
							.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random session key"))?;
						let encrypted_data = _encrypt_segment(data, nonce, key);
						write_callback(&encrypted_data)?;
						break;
					}

					let nonce = chacha20poly1305_ietf::Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
						.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random nonce"))?;
					let key = chacha20poly1305_ietf::Key::from_slice(&session_key)
						.ok_or_else(|| anyhow!("Excryption failed -> Unable to create random session key"))?;
					let encrypted_data = _encrypt_segment(&segment, nonce, key);
					write_callback(&encrypted_data)?;

					remaining_length -= segment_len;
				},
				Err(m) => bail!("Error reading input {:?}", m),
			}
		}
	}

	log::info!("Encryption Successful");
	Ok(())
}

fn _encrypt_segment(data: &[u8], nonce: Nonce, key: Key) -> Vec<u8> {
	vec![nonce.0.to_vec(), chacha20poly1305_ietf::seal(data, None, &nonce, &key)].concat()
}

pub fn decrypt(
	keys: Vec<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> Result<()>,
	range_start: usize,
	range_span: Option<usize>,
	sender_pubkey: Option<Vec<u8>>,
) -> Result<()> {
	match range_span {
		Some(span) => log::info!("Decrypting file | Range: [{}, {})", range_start, range_start + span + 1),
		None => log::info!("Decrypting file | Range: [{}, EOF)", range_start),
	}

	// Get header info
	let mut temp_buf = [0u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| anyhow!("Unable to read header info (ERROR = {:?})", e))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let encrypted_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| anyhow!("Unable to read header packet length (ERROR = {:?})", e))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|_| anyhow!("Unable to parse header packet length"))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| anyhow!("Unable to read header packet data (ERROR = {:?})", e))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>>>()?;

	let (session_keys, edit_list) = header::deconstruct_header_body(encrypted_packets, keys, sender_pubkey)?;

	match range_span {
		Some(span) => log::info!("Slicing from {} | Keeping {} bytes", range_start, span),
		None => log::info!("Slicing from {} | Keeping all bytes", range_start),
	}

	ensure!(
		range_span.is_none() || range_span.unwrap() > 0,
		"Invalid range span: {:?}",
		range_span
	);

	// Iterator to slice the output
	let write_func = |segment| write_segment(range_start, range_span, write_callback, segment);

	match edit_list {
		None => body_decrypt(read_buffer, session_keys, write_func, range_start)?,
		Some(edit_list_content) => body_decrypt_parts(read_buffer, session_keys, write_func, edit_list_content)?,
	}

	log::info!("Decryption Over");
	Ok(())
}

struct DecryptedBuffer<'a> {
	read_buffer: &'a mut dyn Read,
	session_keys: Vec<Vec<u8>>,
	buf: Vec<u8>,
	is_decrypted: bool,
	block: u64,
	output: &'a dyn Fn(Vec<u8>) -> Result<()>,
	index: usize,
}

impl<'a> DecryptedBuffer<'a> {
	fn new(
		read_buffer: &'a mut impl Read,
		session_keys: Vec<Vec<u8>>,
		output: &'a impl Fn(Vec<u8>) -> Result<()>,
	) -> Self {
		let mut decryptor = Self {
			read_buffer,
			session_keys,
			buf: Vec::with_capacity(CIPHER_SEGMENT_SIZE),
			is_decrypted: false,
			block: 0,
			output,
			index: 0,
		};

		decryptor.fetch();
		decryptor.decrypt();
		log::debug!("Index = {}", decryptor.index);
		log::debug!("");
		decryptor
	}

	fn fetch(&mut self) {
		log::debug!("Fetching block {}", self.block);
		self.block += 1;

		// Fetches a block
		self.buf.clear();
		self.read_buffer
			.take(CIPHER_SEGMENT_SIZE as u64)
			.read_to_end(&mut self.buf)
			.unwrap();

		self.is_decrypted = false;
		log::debug!("");
	}

	fn decrypt(&mut self) {
		// Decrypts its buffer
		if !self.is_decrypted {
			log::debug!("Decrypting block");
			self.buf = decrypt_block(&self.buf, &self.session_keys).unwrap();
			self.is_decrypted = true;
		}
		log::debug!("");
	}

	fn skip(&mut self, size: usize) -> Result<()> {
		assert!(size > 0, "You shouldn't skip 0 bytes");
		log::debug!("Skipping {} bytes | Buffer size: {}", size, self.buf.len());

		let mut remaining_size = size;

		// Skip fetches
		while remaining_size > 0 {
			log::debug!("Left to skip: {} | Buffer size: {}", remaining_size, self.buf.len());

			if remaining_size >= SEGMENT_SIZE {
				self.fetch();
				remaining_size -= SEGMENT_SIZE;
			}
			else {
				if (self.index + remaining_size) > SEGMENT_SIZE {
					self.fetch();
				}
				self.index = (self.index + remaining_size) % SEGMENT_SIZE;
				log::debug!("Index = {}", self.index);
				remaining_size -= remaining_size;
			}
		}

		log::debug!("Finished skipping");
		log::debug!("");

		// Apply
		self.decrypt();
		Ok(())
	}

	fn read(&mut self, size: usize) -> Result<usize> {
		assert!(size > 0, "You shouldn't read 0 bytes");
		log::debug!("Reading {} bytes | Buffer size: {}", size, self.buf.len());

		let mut remaining_size = size;

		while remaining_size > 0 {
			// Get read length
			log::debug!("Left to read: {} | Buffer size: {}", remaining_size, self.buf.len());
			let n_bytes = usize::min(SEGMENT_SIZE - self.index, remaining_size);

			// Process
			self.decrypt();
			(self.output)(self.buf[self.index..self.index + n_bytes].to_vec()).unwrap();

			// Advance
			self.index = (self.index + n_bytes) % self.buf.len();
			log::debug!("Index = {}", self.index);
			if self.index == 0 {
				self.fetch()
			}

			// Reduce
			remaining_size -= n_bytes;
		}

		log::debug!("Finished reading");
		log::debug!("");

		Ok(size)
	}
}

fn body_decrypt_parts(
	mut read_buffer: impl Read,
	session_keys: Vec<Vec<u8>>,
	output: impl Fn(Vec<u8>) -> Result<()>,
	edit_list: Vec<u64>,
) -> Result<()> {
	log::debug!("Edit List: {:?}", edit_list);

	ensure!(
		!edit_list.is_empty(),
		"You cannot call this function with an empty edit list"
	);

	let mut decrypted = DecryptedBuffer::new(&mut read_buffer, session_keys, &output);

	let mut skip = true;

	for edit_length in edit_list {
		match skip {
			true => {
				decrypted.skip(edit_length as usize)?;
			},
			false => {
				decrypted.read(edit_length as usize)?;
			},
		};
		skip = !skip;
	}

	if !skip {
		// If we finished with a skip, read until the end
		loop {
			let n = decrypted.read(SEGMENT_SIZE)?;
			if n == 0 {
				break;
			}
		}
	}

	Ok(())
}

fn body_decrypt(
	mut read_buffer: impl Read,
	session_keys: Vec<Vec<u8>>,
	output: impl Fn(Vec<u8>) -> Result<()>,
	range_start: usize,
) -> Result<()> {
	if range_start >= SEGMENT_SIZE {
		let start_segment = range_start / SEGMENT_SIZE;
		log::info!("Fast-forwarding {} segments", start_segment);
		let start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE;
		read_buffer
			.read_exact(&mut vec![0u8; start_ciphersegment])
			.map_err(|e| anyhow!("Unable to skip to the beginning of the decryption (ERROR = {:?})", e))?
	}

	loop {
		let mut chunk = Vec::with_capacity(CIPHER_SEGMENT_SIZE);
		let n = read_buffer
			.by_ref()
			.take(CIPHER_SEGMENT_SIZE as u64)
			.read_to_end(&mut chunk)
			.map_err(|e| anyhow!("Unable to read block (ERROR = {:?})", e))?;

		if n == 0 {
			break;
		}

		let segment = decrypt_block(&chunk, &session_keys)?;
		output(segment)?;

		if n < CIPHER_SEGMENT_SIZE {
			break;
		}
	}

	Ok(())
}

fn decrypt_block(ciphersegment: &Vec<u8>, session_keys: &Vec<Vec<u8>>) -> Result<Vec<u8>> {
	let (nonce_slice, data) = ciphersegment.split_at(12);
	let nonce = chacha20poly1305_ietf::Nonce::from_slice(nonce_slice)
		.ok_or_else(|| anyhow!("Block decryption failed -> Unable to wrap nonce"))?;

	session_keys
		.iter()
		.filter_map(|key| {
			let key = chacha20poly1305_ietf::Key::from_slice(key).unwrap();
			chacha20poly1305_ietf::open(data, None, &nonce, &key).ok()
		})
		.next()
		.ok_or_else(|| anyhow!("Could not decrypt that block"))
}

fn write_segment(
	_offset: usize,
	_limit: Option<usize>,
	write_callback: fn(&[u8]) -> Result<()>,
	data: Vec<u8>,
) -> Result<()> {
	// TODO: This a minimal implementation
	write_callback(&data)
}

pub fn reencrypt(
	keys: Vec<Keys>,
	recipient_keys: HashSet<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> Result<()>,
	trim: bool,
) -> Result<()> {
	// Get header info
	let mut temp_buf = [0u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| anyhow!("Unable to read header info (ERROR = {:?})", e))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let header_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| anyhow!("Unable to read header packet length (ERROR = {:?})", e))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|_| anyhow!("Unable to parse header packet length"))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| anyhow!("Unable to read header packet data (ERROR = {:?})", e))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>>>()?;

	let packets = header::reencrypt(header_packets, keys, recipient_keys, trim)?;
	write_callback(&header::serialize(packets))?;

	log::info!("Streaming the remainder of the file");

	loop {
		let mut buf = Vec::with_capacity(CHUNK_SIZE);
		let data = read_buffer.by_ref().take(CHUNK_SIZE as u64).read_to_end(&mut buf);

		match data {
			Ok(0) => break,
			Ok(n) => write_callback(&buf[0..n])?,
			Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
			Err(e) => bail!("Error reading the remainder of the file (ERROR = {:?})", e),
		}
	}

	log::info!("Reencryption successful");

	Ok(())
}

pub fn rearrange(
	keys: Vec<Keys>,
	mut read_buffer: impl Read,
	write_callback: fn(&[u8]) -> Result<()>,
	range_start: usize,
	range_span: Option<usize>,
) -> Result<()> {
	// Get header info
	let mut temp_buf = [0u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| anyhow!("Unable to read header info (ERROR = {:?})", e))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let header_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| anyhow!("Unable to read header packet length (ERROR = {:?})", e))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|_| anyhow!("Unable to parse header packet length"))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| anyhow!("Unable to read header packet data (ERROR = {:?})", e))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>>>()?;

	let (packets, mut segment_oracle) = header::rearrange(header_packets, keys, range_start, range_span, None)?;
	write_callback(&header::serialize(packets))?;

	log::info!("Streaming the remainder of the file");

	loop {
		let mut buf = Vec::with_capacity(SEGMENT_SIZE + CIPHER_DIFF);
		let data = read_buffer
			.by_ref()
			.take((SEGMENT_SIZE + CIPHER_DIFF) as u64)
			.read_to_end(&mut buf);

		let keep_segment = segment_oracle.next().unwrap();

		log::debug!("Keep segment: {:?}", keep_segment);

		match data {
			Ok(0) => break,
			Ok(n) => {
				if keep_segment {
					write_callback(&buf[0..n])?
				}
			},
			Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
			Err(e) => bail!("Error reading the remainder of the file (ERROR = {:?})", e),
		}
	}

	log::info!("Rearrangement successful");

	Ok(())
}
