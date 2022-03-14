use std::{path::{PathBuf}, error::Error};

use crypto::symmetriccipher::SymmetricCipherError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Crypt4GHError {
	// User errors
	#[error("No Recipients' Public Key found")]
	NoRecipients,
	#[error("Invalid range span: {0:?}")]
	InvalidRangeSpan(Option<usize>),
	#[error("The edit list is empty")]
	EmptyEditList,

	// Sodiumoxide errors
	#[error("Unable to create random nonce")]
	NoRandomNonce,
	#[error("Unable to extract nonce")]
	NoNonce,
	#[error("Unable to create session key")]
	NoKey,
	#[error("Unable to wrap key")]
	BadKey,
	#[error("Unable to decrypt key (ERROR = {0:?})")]
	DecryptKeyError(SymmetricCipherError),
	#[error("Invalid key format")]
	InvalidKeyFormat,
	#[error("Invalid SSH key format")]
	InvalidSSHKey,
	#[error("Unable to wrap nonce")]
	UnableToWrapNonce,
	#[error("Could not decrypt that block")]
	UnableToDecryptBlock,
	#[error("Unable to decode with base64 the key (ERROR = {0:?})")]
	BadBase64Error(Box<dyn Error>),
	#[error("Unable to decode kdfname")]
	BadKdfName(Box<dyn Error>),
	#[error("Unsupported KDF: {0}")]
	UnsupportedKdf(String),
	#[error("Invalid Crypt4GH Key format")]
	InvalidCrypt4GHKey,
	#[error("Bad ciphername ({0:?})")]
	BadCiphername(String),
	#[error("Conversion from ed25519 to curve25519 failed")]
	ConversionFailed,
	#[error("Unsupported Header Encryption Method: {0}")]
	BadHeaderEncryptionMethod(u32),
	#[error("Unable to encrypt packet: None of the keys were used")]
	UnableToEncryptPacket,
	#[error("Decryption failed -> Invalid data")]
	InvalidData,

	// Keys errors
	#[error("Unable to extract public server key")]
	BadServerPublicKey,
	#[error("Unable to extract private server key")]
	BadServerPrivateKey,
	#[error("Unable to extract public client key")]
	BadClientPublicKey,
	#[error("Unable to extract public client key")]
	BadClientPrivateKey,
	#[error("Unable to create shared key")]
	BadSharedKey,
	#[error("Invalid Peer's Public Key")]
	InvalidPeerPubPkey,

	// Reading errors
	#[error("Unable to read {0} bytes from input (ERROR = {1:?})")]
	NotEnoughInput(usize, Box<dyn Error>),
	#[error("Unable to read header info (ERROR = {0:?})")]
	ReadHeaderError(Box<dyn Error>),
	#[error("Unable to read header packet length (ERROR = {0:?})")]
	ReadHeaderPacketLengthError(Box<dyn Error>),
	#[error("Unable to read header packet data (ERROR = {0:?})")]
	ReadHeaderPacketDataError(Box<dyn Error>),
	#[error("Unable to skip to the beginning of the decryption (ERROR = {0:?})")]
	BadStartRange(Box<dyn Error>),
	#[error("Unable to read block (ERROR = {0:?})")]
	ReadBlockError(Box<dyn Error>),
	#[error("Error reading the remainder of the file (ERROR = {0:?})")]
	ReadRemainderError(Box<dyn Error>),
	#[error("Unable to read lines from {0:?} (ERROR = {1:?})")]
	ReadLinesError(PathBuf, Box<dyn Error>),
	#[error("Unable to deserialize rounds from private key")]
	ReadRoundsError,
	#[error("Unable to extract public key")]
	ReadPublicKeyError,
	#[error("Unable to deserialize N keys from private key")]
	ReadSSHKeys,
	#[error("Unable to deserialize check number 1 from private blob")]
	ReadCheckNumber1Error,
	#[error("Unable to deserialize check number 2 from private blob")]
	ReadCheckNumber2Error,
	#[error("Unable to read magic word from private key (ERROR = {0:?})")]
	ReadMagicWord(Box<dyn Error>),
	#[error("Empty public key at {0:?}")]
	EmptyPublicKey(PathBuf),
	#[error("Secret key not found: {0}")]
	ReadSecretKeyFileError(PathBuf),

	// Packets
	#[error("Unable to read packet encryption method")]
	ReadPacketEncryptionMethod,
	#[error("Invalid packet type")]
	InvalidPacketType,
	#[error("Invalid file: Too many edit list packets")]
	TooManyEditListPackets,
	#[error("Unsupported bulk encryption method: {0}")]
	UnsupportedEncryptionMethod(u32),
	#[error("No supported encryption method")]
	NoSupportedEncryptionMethod,

	// Header
	#[error("No header packet could be decrypted")]
	NoValidHeaderPacket,

	// Edit list
	#[error("Edit list packet did not contain the length of the list")]
	NoEditListLength,
	#[error("Invalid edit list")]
	InvalidEditList,
	#[error("Unable to parse content of the edit list packet")]
	ReadEditListError,

	// Other
	#[error("Passphrase required (ERROR = {0:?})")]
	NoPassphrase(Box<dyn Error>),
	#[error("Nothing to be done")]
	Done,

	// Write errors
	#[error("Unable to write to output (ERROR = {0:?})")]
	UnableToWrite(Box<dyn Error>),

	// Parse errors
	#[error("Unable to parse header packet length (ERROR = {0:?})")]
	ParseHeaderPacketLengthError(Box<dyn Error>),
	#[error("Unable to parse the start of the range")]
	ParseRangeError,

	// // Config errors
	// #[error("Unable to get environment variable '{0}' (ERROR = {1}) ")]
	// NoEnvVar(&'static str, String),
	// #[error("Wrong Port")]
	// WrongPort,
	// #[error("Bad config (ERROR = {0})")]
	// BadConfig(String),

	// // Binding errors
	// #[error("Unable to bind to the address (ERROR = {0})")]
	// BindingError(String),
	// #[error("Unable to parse address: {0} (ERROR = {1})")]
	// WrongAddress(String, String),

	// // Runtime errors
	// #[error("Internal Server Failed (ERROR = {0})")]
	// InternalServerError(String),
	// #[error("Page not found (ERROR = {0})")]
	// NotFound(String),
	// #[error("Database Failed (ERROR = {0})")]
	// DbError(String),
	// #[error("Cache Failed (ERROR = {0})")]
	// CacheError(String),
	// #[error("Invalid Headers")]
	// InvalidHeaders,

	// // Passport errors
	// #[error("Unable to construct passport (ERROR = {0})")]
	// BadPassport(String),

	// // Authentication errors
	// #[error("Unauthorized")]
	// Unauthorized,
	// #[error("Forbidden")]
	// Forbidden,

	// // AMQP
	// #[error("Connection url bad format")]
	// BadConfigConnectionUrl,
	// #[error("AMQP TlsConnector builder failed")]
	// TlsConnectorError,
	// #[error("AMQP Connection failed")]
	// ConnectionError(Option<amiquip::Error>),
	// #[error("AMQP Error")]
	// AMQPError(#[from] amiquip::Error),

	// IO
	#[error("IO failed")]
	IoError(#[from] std::io::Error),
}
