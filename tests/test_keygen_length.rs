mod test_common;

use std::path::PathBuf;

pub use test_common::*;
use testresult::TestResult;

#[test]
fn test_keygen_length_encrypted() -> TestResult {
	// Init
	let init = Cleanup::new();

	let bob_pk_path = temp_file("bob.pub");
	let bob_sk_path = temp_file("bob.sec");
	let callback = Ok(BOB_PASSPHRASE.to_string());

	crypt4gh::keys::generate_keys(PathBuf::from(&bob_sk_path), PathBuf::from(&bob_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

	count_characters(&temp_file("bob.pub"), 36 + 45 + 34);
	count_characters(&temp_file("bob.sec"), 37 + 161 + 35);

	// Cleanup
	drop(init);

	Ok(())
}

#[test]
fn test_keygen_length_not_encrypted() -> TestResult {
	// Init
	let init = Cleanup::new();

	let alice_pk_path = temp_file("alice.pub");
	let alice_sk_path = temp_file("alice.sec");
	let callback = Ok("".to_string());

	crypt4gh::keys::generate_keys(PathBuf::from(&alice_sk_path), PathBuf::from(&alice_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

	count_characters(&temp_file("alice.pub"), 36 + 45 + 34);
	count_characters(&temp_file("alice.sec"), 37 + 73 + 35);

	// Cleanup
	drop(init);

	Ok(())
}
