use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
	// User errors
	#[error("No Recipients' Public Key found")]
	NoRecipients,
	#[error("Invalid range span: {0:?}")]
	InvalidRangeSpan(Option<usize>),
	#[error("The edit list is empty")]
	EmptyEditList,

	// Sodiumoxide errors
	#[error("Unable to create random nonce")]
	NoNonce,
	#[error("Unable to create session key")]
	NoKey,
	#[error("Unable to wrap nonce")]
	BadNonce,
	#[error("Could not decrypt that block")]
	UnableToDecryptBlock,
	#[error("Unable to decode with base64 the key (ERROR = {0:?})")]
	BadBase64Error(Box<dyn std::error::Error>),

	// Reading errors
	#[error("Unable to read {0} bytes from input (ERROR = {1:?})")]
	NotEnoughInput(usize, Box<dyn std::error::Error>),
	#[error("Unable to read header info (ERROR = {0:?})")]
	ReadHeaderError(Box<dyn std::error::Error>),
	#[error("Unable to read header packet length (ERROR = {0:?})")]
	ReadHeaderPacketLengthError(Box<dyn std::error::Error>),
	#[error("Unable to read header packet data (ERROR = {0:?})")]
	ReadHeaderPacketDataError(Box<dyn std::error::Error>),
	#[error("Unable to skip to the beginning of the decryption (ERROR = {0:?})")]
	BadStartRange(Box<dyn std::error::Error>),
	#[error("Unable to read block (ERROR = {0:?})")]
	ReadBlockError(Box<dyn std::error::Error>),
	#[error("Error reading the remainder of the file (ERROR = {0:?})")]
	ReadRemainderError(Box<dyn std::error::Error>),
	#[error("Unable to read lines from {0:?} (ERROR = {1:?})")]
	ReadLinesError(Box<Path>, Box<dyn std::error::Error>),

	// Write errors
	#[error("Unable to write to output (ERROR = {0:?})")]
	UnableToWrite(Box<dyn std::error::Error>),

	// Parse errors
	#[error("Unable to parse header packet length (ERROR = {0:?})")]
	ParseHeaderPacketLengthError(Box<dyn std::error::Error>),

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
