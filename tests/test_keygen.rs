mod test_common;

use std::path::Path;

pub use test_common::*;

#[test]
fn test_keygen() {
	// Init
	let init = Cleanup::new();

	let bob_pk_path = temp_file("bob.pub");
	let bob_sk_path = temp_file("bob.sec");
	let callback = || return Ok(BOB_PASSPHRASE.to_string());

	crypt4gh::keys::generate_keys(Path::new(&bob_sk_path), Path::new(&bob_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

	let alice_pk_path = temp_file("alice.pub");
	let alice_sk_path = temp_file("alice.sec");
	let callback = || return Ok(ALICE_PASSPHRASE.to_string());

	crypt4gh::keys::generate_keys(Path::new(&alice_sk_path), Path::new(&alice_pk_path), callback, None)
		.expect("Unable to generate Alice's keys");

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(strip_prefix("bob.sec"))
		.arg("--recipient_pk")
		.arg(strip_prefix("alice.pub"))
		.pipe_in(TESTFILE_ABCD)
		.pipe_out(&temp_file("message.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(strip_prefix("alice.sec"))
		.pipe_in(&temp_file("message.c4gh"))
		.pipe_out(&temp_file("message.received"))
		.succeeds();

	// Compare
	equal(TESTFILE_ABCD, &temp_file("message.received"));

	// Cleanup
	drop(init);
}