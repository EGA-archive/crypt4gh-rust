//! Bob wants to send a message to Alice, containing sensitive data. Bob uses [`Crypt4GH`, the Global Alliance approved secure method for sharing human genetic data][ga4gh].
//! crypt4gh, a Python tool to encrypt, decrypt or re-encrypt files, according to the [GA4GH encryption file format](http://samtools.github.io/hts-specs/crypt4gh.pdf).
//! [![How `Crypt4GH` works](https://i.imgur.com/5czeods.png)][ga4gh]
//!
//! To learn more about the format visit the [`Crypt4GH` CLI & Format Documentation][format-docs]
//!
//! [format-docs]: https://ega-archive.github.io/crypt4gh-rust/
//! [ga4gh]: https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/

// TODO: Remove comment in the future
// #![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]
#![allow(
	clippy::missing_errors_doc,
	clippy::missing_panics_doc,
	clippy::module_name_repetitions,
	clippy::must_use_candidate,
	clippy::cast_possible_truncation,
	clippy::similar_names,
	clippy::implicit_hasher,
	clippy::redundant_else
)]

use rand::{SeedableRng, RngCore};
use rand_chacha;

use std::collections::HashSet;
use std::io::{self, Read, Write};

use header::DecryptedHeaderPackets;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ self, ChaCha20Poly1305, Key, KeyInit, Nonce };

use crate::error::Crypt4GHError;

/// Generate and parse a `Crypt4GH` header.
pub mod header;

/// Utility to read Crypt4GH-formatted keys.
pub mod keys;

/// `Crypt4GH` Errors.
pub mod error;

const CHUNK_SIZE: usize = 4096;

/// Size of the encrypted segments.
pub const SEGMENT_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + CIPHER_DIFF;

/// Write buffer wrapper.
/// * offset: Start writing on position = `offset`
/// * limit: Write a maximum of `limit` bytes at the time
/// * `write_buffer`: Write buffer
pub struct WriteInfo<'a, W: Write> {
	offset: usize,
	limit: Option<usize>,
	write_buffer: &'a mut W,
}

impl<'a, W: Write> WriteInfo<'a, W> {
	/// Creates a new `WriteInfo`
	pub fn new(offset: usize, limit: Option<usize>, write_buffer: &'a mut W) -> Self {
		Self {
			offset,
			limit,
			write_buffer,
		}
	}

	fn write_all(&mut self, data: &[u8]) -> Result<(), Crypt4GHError> {
		match &mut self.limit {
			Some(limit) => {
				if *limit >= data.len() {
					self.write_buffer.write_all(data)?;
					*limit -= data.len();
				}
				else {
					self.write_buffer.write_all(&data[..*limit])?;
					*limit = 0;
				}
			},
			None => self.write_buffer.write_all(&data[self.offset..])?,
		}
		Ok(())
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Key information.
pub struct Keys {
	/// Method used for the key encryption.
	/// > Only method 0 is supported.
	pub method: u8,
	/// Secret key of the encryptor / decryptor (your key).
	pub privkey: Vec<u8>,
	/// Public key of the recipient (the key you want to encrypt for).
	pub recipient_pubkey: Vec<u8>,
}

/// Reads from the `read_buffer` and writes the encrypted data to `write_buffer`.
///
/// Reads from the `read_buffer` and writes the encrypted data (for every `recipient_key`) to `write_buffer`.
/// If the range is specified, it will only encrypt the bytes from `range_start` to `range_start` + `range_span`.
/// In case that `range_span` is none, it will encrypt from `range_start` to the end of the input.
pub fn encrypt<R: Read, W: Write>(
	recipient_keys: &HashSet<Keys>,
	read_buffer: &mut R,
	write_buffer: &mut W,
	range_start: usize,
	range_span: Option<usize>,
) -> Result<(), Crypt4GHError> {
	if recipient_keys.is_empty() {
		return Err(Crypt4GHError::NoRecipients);
	}

	log::info!("Encrypting the file");
	log::debug!("    Start Coordinate: {}", range_start);

	// Seek
	if range_start > 0 {
		log::info!("Forwarding to position: {}", range_start);
	}

	read_buffer
		.by_ref()
		.take(range_start as u64)
		.read_to_end(&mut Vec::new())
		.map_err(|e| Crypt4GHError::NotEnoughInput(range_start, e.into()))?;

	log::debug!("    Span: {:?}", range_span);

	log::info!("Creating Crypt4GH header");

	let mut session_key = [0_u8; 32];
	let mut rnd = rand_chacha::ChaCha20Rng::from_entropy();
	
	// random bytes into session_key
	rnd.try_fill_bytes(&mut session_key).map_err(|_| Crypt4GHError::NoRandomNonce)?;
	
	let header_bytes = encrypt_header(recipient_keys, &Some(session_key))?;

	log::debug!("header length: {}", header_bytes.len());

	write_buffer.write_all(&header_bytes)?;

	log::info!("Streaming content");

	let mut segment = [0_u8; SEGMENT_SIZE];
	let seed = &rnd.get_seed();

	// The whole file
	match range_span {
		None | Some(0) => loop {
			let segment_len = read_buffer.read(&mut segment)?;
			if segment_len == 0 {
				break;
			}
			else if segment_len < SEGMENT_SIZE {
				let (data, _) = segment.split_at(segment_len);
				let nonce = Nonce::from_slice(seed);
					//.map_err(|_| Crypt4GHError::NoRandomNonce)?;
				let key = Key::from_slice(&session_key);
				//.ok_or(Crypt4GHError::NoKey)?;
				let encrypted_data = encrypt_segment(data, *nonce, &key)?;
				write_buffer.write_all(&encrypted_data)?;
				break;
			}
			else {
				let nonce = Nonce::from_slice(seed);
					//.ok_or(Crypt4GHError::NoRandomNonce)?;
				let key = Key::from_slice(&session_key);//.ok_or(Crypt4GHError::NoKey)?;
				let encrypted_data = encrypt_segment(&segment, *nonce, &key)?;
				write_buffer.write_all(&encrypted_data)?;
			}
		},
		Some(mut remaining_length) => {
			while remaining_length > 0 {
				let segment_len = read_buffer.read(&mut segment)?;

				// Stop
				if segment_len >= remaining_length {
					let (data, _) = segment.split_at(remaining_length);
					let nonce = Nonce::from_slice(seed);
						//.ok_or(Crypt4GHError::NoRandomNonce)?;
					let key = Key::from_slice(&session_key);
					//.ok_or(Crypt4GHError::NoKey)?;
					let encrypted_data = encrypt_segment(data, *nonce, &key)?;
					write_buffer.write_all(&encrypted_data)?;
					break;
				}

				// Not a full segment
				if segment_len < SEGMENT_SIZE {
					let (data, _) = segment.split_at(segment_len);
					let nonce = Nonce::from_slice(seed);
						//.ok_or(Crypt4GHError::NoRandomNonce)?;
					let key = Key::from_slice(&session_key);
					//.ok_or(Crypt4GHError::NoKey)?;
					let encrypted_data = encrypt_segment(data, *nonce, &key)?;
					write_buffer.write_all(&encrypted_data)?;
					break;
				}

				let nonce = Nonce::from_slice(seed);
					//.ok_or(Crypt4GHError::NoRandomNonce)?;
				let key = Key::from_slice(&session_key);
				//.ok_or(Crypt4GHError::NoKey)?;
				let encrypted_data = encrypt_segment(&segment, *nonce, &key)?;
				write_buffer.write_all(&encrypted_data)?;

				remaining_length -= segment_len;
			}
		},
	}

	log::info!("Encryption Successful");
	Ok(())
}

/// Builds a header with a random session key
///
/// Returns the encrypted header bytes
pub fn encrypt_header(
	recipient_keys: &HashSet<Keys>,
	session_key: &Option<[u8; 32]>,
) -> Result<Vec<u8>, Crypt4GHError> {
	let encryption_method = 0;
	
	let session_key_or_new = session_key.map_or_else(|| {
		let mut session_key = [0_u8; 32];
		let mut rnd = rand_chacha::ChaCha20Rng::from_entropy();

		rnd.try_fill_bytes(&mut session_key).map_err(|_| Crypt4GHError::NoRandomNonce)?; // TODO: Custom error for this

		Ok::<_, Crypt4GHError>(session_key)
	}, |value| { Ok(value)} )?;

	let header_content = header::make_packet_data_enc(encryption_method, &session_key_or_new);
	let header_packets = header::encrypt(&header_content, recipient_keys)?;
	let header_bytes = header::serialize(header_packets);
	Ok(header_bytes)
}

/// Encrypts a segment.
///
/// Returns [ nonce + `encrypted_data` ].
pub fn encrypt_segment(data: &[u8], nonce: Nonce, key: &Key) -> Result<Vec<u8>, Crypt4GHError> {
	let cipher = ChaCha20Poly1305::new(key);
	let _ciphertext = cipher.encrypt(&nonce, data);
	Ok(vec![nonce.to_vec(), ].concat())
}

/// Reads from the `read_buffer` and writes the decrypted data to `write_buffer`.
///
/// Reads from the `read_buffer` and writes the decrypted data to `write_buffer`.
/// If the range is specified, it will only encrypt the bytes from `range_start` to `range_start` + `range_span`.
/// In case that `range_span` is none, it will encrypt from `range_start` to the end of the input.
/// If `sender_pubkey` is specified the program will check that the `recipient_key` in the message
/// is the same as the `sender_pubkey`.
pub fn decrypt<R: Read, W: Write>(
	keys: &[Keys],
	read_buffer: &mut R,
	write_buffer: &mut W,
	range_start: usize,
	range_span: Option<usize>,
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<(), Crypt4GHError> {
	range_span.map_or_else(
		|| {
			log::info!("Decrypting file | Range: [{}, EOF)", range_start);
		},
		|span| {
			log::info!("Decrypting file | Range: [{}, {})", range_start, range_start + span + 1);
		},
	);

	// Get header info
	let mut temp_buf = [0_u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| Crypt4GHError::ReadHeaderError(e.into()))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let encrypted_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0_u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketLengthError(e.into()))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|e| Crypt4GHError::ParseHeaderPacketLengthError(e))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0_u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketDataError(e.into()))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>, Crypt4GHError>>()?;

	let DecryptedHeaderPackets {
		data_enc_packets: session_keys,
		edit_list_packet: edit_list,
	} = header::deconstruct_header_body(encrypted_packets, keys, sender_pubkey)?;

	range_span.map_or_else(
		|| {
			log::info!("Slicing from {} | Keeping all bytes", range_start);
		},
		|span| {
			log::info!("Slicing from {} | Keeping {} bytes", range_start, span);
		},
	);

	if range_span.is_some() && range_span.unwrap() == 0 {
		return Err(Crypt4GHError::InvalidRangeSpan(range_span));
	}

	let mut write_info = WriteInfo::new(range_start, range_span, write_buffer);

	// TODO: Might fail here on Some() due to read_buffer coming from io::stdin is not populated? See run_decrypt() in bin.rs or
	// the appropriate test
	match edit_list {
		None => body_decrypt(read_buffer, &session_keys, &mut write_info, range_start)?,
		Some(edit_list_content) => body_decrypt_parts(read_buffer, session_keys, write_info, edit_list_content)?,
	}

	log::info!("Decryption Over");
	Ok(())
}

struct DecryptedBuffer<'a, W: Write> {
	read_buffer: &'a mut dyn Read,
	session_keys: Vec<Vec<u8>>,
	buf: Vec<u8>,
	is_decrypted: bool,
	block: u64,
	output: WriteInfo<'a, W>,
	index: usize,
}

impl<'a, W: Write> DecryptedBuffer<'a, W> {
	fn new(read_buffer: &'a mut impl Read, session_keys: Vec<Vec<u8>>, output: WriteInfo<'a, W>) -> Result<Self, Crypt4GHError> {
		let mut decryptor = Self {
			read_buffer,
			session_keys,
			buf: Vec::with_capacity(CIPHER_SEGMENT_SIZE),
			is_decrypted: false,
			block: 0,
			output,
			index: 0,
		};

		//log::debug!("DecryptedBuffer::new() ... about to fetch()");
		decryptor.fetch()?;
		//log::debug!("DecryptedBuffer::new() ... about to decrypt()");
		decryptor.decrypt()?;
		//log::debug!("Index = {}", decryptor.index);
		Ok(decryptor)
	}

	fn fetch(&mut self) -> Result<(), Crypt4GHError>{
		self.block += 1; //TODO: Why? Spec says that all must be 0-indexed?

		self.buf.clear();//TODO: Needed????

		//log::debug!("fetch()'s fetching block idx: {}", self.block);

		// Fetches a block
		self.read_buffer
			.take(CIPHER_SEGMENT_SIZE as u64)
			.read_to_end(&mut self.buf)?;

		//log::debug!("fetch()'s fetched block: {:?}", &self.buf);

		self.is_decrypted = false;

		Ok(())
	}

	fn decrypt(&mut self) -> Result<(), Crypt4GHError> {
		// Decrypts its buffer
		if !self.is_decrypted {
			//log::debug!("Decrypting block: {:?}", &self.buf);
			self.buf = decrypt_block(&self.buf, &self.session_keys)?;
			self.is_decrypted = true;
		}
		Ok(())
	}

	fn skip(&mut self, size: usize) -> Result<(), Crypt4GHError> {
		if size <= 0 {
			//return Err(Crypt4GHError::NotEnoughInput(size, self.buf.len()));
			return Err(Crypt4GHError::SkipZeroBytes)
		}
		// assert!(size > 0, "You shouldn't skip 0 bytes");
		log::debug!("Skipping {} bytes | Buffer size: {}", size, self.buf.len());

		let mut remaining_size = size;

		// Skip fetches
		while remaining_size > 0 {
			log::debug!("Left to skip: {} | Buffer size: {}", remaining_size, self.buf.len());

			if remaining_size >= SEGMENT_SIZE {
				self.fetch()?;
				remaining_size -= SEGMENT_SIZE;

				log::debug!("skip()'s skipping a whole segment, remaining size: {}", remaining_size);
			}
			else {
				if (self.index + remaining_size) > SEGMENT_SIZE {
					self.fetch()?;
				}
				self.index = (self.index + remaining_size) % SEGMENT_SIZE;
				log::debug!("skip()'s Index for remaining_size of the segment = {}", self.index);
				remaining_size -= remaining_size;
			}
		}

		log::debug!("Finished skipping");

		// Apply
		self.decrypt()?;

		Ok(())
	}

	fn read(&mut self, size: usize) -> Result<usize, Crypt4GHError> {
		if size <= 0 {
			//return Err(Crypt4GHError::NotEnoughInput(size, self.buf.len()));
			return Err(Crypt4GHError::SkipZeroBytes)
		}

		// assert!(size > 0, "You shouldn't read 0 bytes");
		// log::debug!("Reading {} bytes | Buffer size: {}", size, self.buf.len());

		let mut remaining_size = size;

		while remaining_size > 0 {
			// Get read length
			log::debug!("Left to read: {} | Buffer size: {}", remaining_size, self.buf.len());
			let n_bytes = usize::min(SEGMENT_SIZE - self.index, remaining_size);

			// Process
			self.decrypt()?;
			self.output
				.write_all(&self.buf[self.index..self.index + n_bytes])?;

			// Advance
			self.index = (self.index + n_bytes) % self.buf.len();
			log::debug!("Index = {}", self.index);
			if self.index == 0 {
				self.fetch()?;
			}

			// Reduce
			remaining_size -= n_bytes;
		}

		log::debug!("Finished reading");
		log::debug!("");

		Ok(size)
	}
}

/// Decrypts the specified content read using the keys provided.
///
/// Reads the bytes of the buffer and decrypts it using the `session_keys`.
/// Writes the decrypted bytes using the write buffer provided. It skips
/// the first `range_start` bytes. It uses the `edit_list` packets.
pub fn body_decrypt_parts<W: Write>(
	mut read_buffer: impl Read,
	session_keys: Vec<Vec<u8>>,
	output: WriteInfo<W>,
	edit_list: Vec<u64>,
) -> Result<(), Crypt4GHError> {
	//log::debug!("body_decrypt_parts()'s Edit List: {:?}", edit_list);

	if edit_list.is_empty() {
		//log::debug!("body_decrypt_parts()'s Edit List is empty");
		return Err(Crypt4GHError::EmptyEditList);
	}

	//log::debug!("body_decrypt_parts()'s session_keys: {:#?}", session_keys);
	let mut decrypted = DecryptedBuffer::new(&mut read_buffer, session_keys, output)?;
	//log::debug!("body_decrypt_parts()'s decrypted content length: {:#?}", decrypted.buf.len());

	let mut skip = true;

	for edit_length in edit_list {
		if skip {
			if edit_length != 0 {
				log::debug!("body_decrypt_parts()'s edit_length from edit list: {}", edit_length);
				decrypted.skip(edit_length as usize)?;
			}
		}
		else {
			decrypted.read(edit_length as usize)?;
		}
		skip = !skip;
	}

	if !skip {
		// If we finished with a skip, read until the end
		loop {
			let n = decrypted.read(SEGMENT_SIZE)?;
			//log::debug!("body_decrypt_parts()'s reading until the end index: {}", n);
			if n == 0 {
				break;
			}
		}
	}

	Ok(())
}

/// Decrypts the content read using the keys provided.
///
/// Reads the bytes of the buffer and decrypts it using the `session_keys`.
/// Writes the decrypted bytes using the write buffer provided. It skips
/// the first `range_start` bytes.
pub fn body_decrypt<W: Write>(
	mut read_buffer: impl Read,
	session_keys: &[Vec<u8>],
	output: &mut WriteInfo<W>,
	range_start: usize,
) -> Result<(), Crypt4GHError> {
	if range_start >= SEGMENT_SIZE {
		let start_segment = range_start / SEGMENT_SIZE;
		log::info!("Fast-forwarding {} segments", start_segment);
		let start_ciphersegment = start_segment * CIPHER_SEGMENT_SIZE;
		read_buffer
			.read_exact(&mut vec![0_u8; start_ciphersegment])
			.map_err(|e| Crypt4GHError::BadStartRange(e.into()))?;
	}

	loop {
		let mut chunk = Vec::with_capacity(CIPHER_SEGMENT_SIZE);
		let n = read_buffer
			.by_ref()
			.take(CIPHER_SEGMENT_SIZE as u64)
			.read_to_end(&mut chunk)
			.map_err(|e| Crypt4GHError::ReadBlockError(e.into()))?;

		if n == 0 {
			break;
		}

		log::debug!("body_decrypt()'s fetched block: {:#?}", &chunk);
		let segment = decrypt_block(&chunk, session_keys)?;
		output
			.write_all(&segment)
			.map_err(|e| Crypt4GHError::UnableToWrite(e.into()))?;

		if n < CIPHER_SEGMENT_SIZE {
			break;
		}
	}

	Ok(())
}

/// Reads and returns the first successfully decrypted block, iterating through all the session keys against one ciphersegment.
fn decrypt_block(ciphersegment: &[u8], session_keys: &[Vec<u8>]) -> Result<Vec<u8>, Crypt4GHError> {
	//log::debug!("Decrypt_block()'s the cyphersegment is: {:#?}", ciphersegment);
	let (nonce_slice, data) = ciphersegment.split_at(12);
    let nonce_bytes: [u8; 12] = nonce_slice
        .try_into()
        .map_err(|_| Crypt4GHError::UnableToWrapNonce)?;

	session_keys.iter()
		.find_map(|key| {
			let key = Key::from_slice(&key);
			let key = chacha20poly1305::ChaCha20Poly1305::new(&key);
			let nonce = Nonce::from_slice(&nonce_bytes);

			let out = key.decrypt(&nonce, data);
			//log::debug!("decrypt_block()'s out: {:#?}", out);
			out.ok()
		})
		.ok_or(Crypt4GHError::UnableToDecryptBlock(ciphersegment.to_vec(), "error decrypting block".to_string()))
}

/// Reads from the `read_buffer` and writes the reencrypted data to `write_buffer`.
///
/// Reads from the `read_buffer` and writes the reencrypted data to `write_buffer`.
/// It will decrypt the message using the key in `keys` and then reencrypt it for the
/// recipient keys specified in `recipient_keys`. If `trim` is true, it will discard
/// the packages that cannot be decrypted.
pub fn reencrypt<R: Read, W: Write>(
	keys: &[Keys],
	recipient_keys: &HashSet<Keys>,
	read_buffer: &mut R,
	write_buffer: &mut W,
	trim: bool,
) -> Result<(), Crypt4GHError> {
	// Get header info
	let mut temp_buf = [0_u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| Crypt4GHError::ReadHeaderError(e.into()))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let header_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0_u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketLengthError(e.into()))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|e| Crypt4GHError::ParseHeaderPacketLengthError(e))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0_u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketDataError(e.into()))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>, Crypt4GHError>>()?;

	let packets = header::reencrypt(header_packets, keys, recipient_keys, trim)?;
	write_buffer.write_all(&header::serialize(packets))?;

	log::info!("Streaming the remainder of the file");

	loop {
		let mut buf = Vec::with_capacity(CHUNK_SIZE);
		let data = read_buffer.by_ref().take(CHUNK_SIZE as u64).read_to_end(&mut buf);

		match data {
			Ok(0) => break,
			Ok(n) => write_buffer.write_all(&buf[0..n])?,
			Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
			Err(e) => return Err(Crypt4GHError::ReadRemainderError(e.into())),
		}
	}

	log::info!("Reencryption successful");

	Ok(())
}

/// Reads from the `read_buffer` and writes the rearranged data to `write_buffer`.
///
/// Reads from the `read_buffer` and writes the rearranged data to `write_buffer`.
/// If the range is specified, it will only rearrange the bytes from `range_start` to `range_start` + `range_span`.
/// In case that `range_span` is none, it will rearrange from `range_start` to the end of the input.
pub fn rearrange<R: Read, W: Write>(
	keys: Vec<Keys>,
	read_buffer: &mut R,
	write_buffer: &mut W,
	range_start: usize,
	range_span: Option<usize>,
) -> Result<(), Crypt4GHError> {
	// Get header info
	let mut temp_buf = [0_u8; 16]; // Size of the header
	read_buffer
		.read_exact(&mut temp_buf)
		.map_err(|e| Crypt4GHError::ReadHeaderError(e.into()))?;
	let header_info: header::HeaderInfo = header::deconstruct_header_info(&temp_buf)?;

	// Calculate header packets
	let header_packets = (0..header_info.packets_count)
		.map(|_| {
			// Get length
			let mut length_buffer = [0_u8; 4];
			read_buffer
				.read_exact(&mut length_buffer)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketLengthError(e.into()))?;
			let length = bincode::deserialize::<u32>(&length_buffer)
				.map_err(|e| Crypt4GHError::ParseHeaderPacketLengthError(e))?;
			let length = length - 4;

			// Get data
			let mut encrypted_data = vec![0_u8; length as usize];
			read_buffer
				.read_exact(&mut encrypted_data)
				.map_err(|e| Crypt4GHError::ReadHeaderPacketDataError(e.into()))?;
			Ok(encrypted_data)
		})
		.collect::<Result<Vec<Vec<u8>>, Crypt4GHError>>()?;

	let (packets, mut segment_oracle) = header::rearrange(header_packets, keys, range_start, range_span, &None)?;
	write_buffer.write_all(&header::serialize(packets))?;

	log::info!("Streaming the remainder of the file");

	loop {
		let mut buf = Vec::with_capacity(SEGMENT_SIZE + CIPHER_DIFF);
		let data = read_buffer
			.by_ref()
			.take((SEGMENT_SIZE + CIPHER_DIFF) as u64)
			.read_to_end(&mut buf)?;

		let keep_segment = segment_oracle.next().unwrap();

		log::debug!("Keep segment: {:?}", keep_segment);

		match data {
			0 => break,
			n => {
				if keep_segment {
					write_buffer.write_all(&buf[0..n])?;
				}
			},
			// Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
			// Err(e) => return Err(Crypt4GHError::ReadRemainderError(e.into())),
		}
	}

	log::info!("Rearrangement successful");

	Ok(())
}
