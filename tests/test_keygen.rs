mod test_common;

use std::path::Path;

pub use test_common::*;

#[test]
fn test_keygen() {
	// Init
	let init = Cleanup::new();

	let bob_pk_path = add_prefix(BOB_PUBKEY);
	let bob_sk_path = add_prefix(BOB_SECKEY);
	let callback = || return Ok(BOB_PASSPHRASE.to_string());

	if Path::new(&bob_pk_path).exists() {
		remove_file(&bob_pk_path);
	}
	if Path::new(&bob_sk_path).exists() {
		remove_file(&bob_sk_path);
	}

	crypt4gh::keys::generate_keys(Path::new(&bob_sk_path), Path::new(&bob_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

	let alice_pk_path = add_prefix(ALICE_PUBKEY);
	let alice_sk_path = add_prefix(ALICE_SECKEY);
	let callback = || return Ok(ALICE_PASSPHRASE.to_string());

	if Path::new(&alice_pk_path).exists() {
		remove_file(&alice_pk_path);
	}
	if Path::new(&alice_sk_path).exists() {
		remove_file(&alice_sk_path);
	}

	crypt4gh::keys::generate_keys(Path::new(&alice_sk_path), Path::new(&alice_pk_path), callback, None)
		.expect("Unable to generate Alice's keys");

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(ALICE_PUBKEY)
		.pipe_in(TESTFILE_ABCD)
		.pipe_out(&temp_file("message.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.c4gh"))
		.pipe_out(&temp_file("message.received"))
		.succeeds();

	// Compare
	equal(TESTFILE_ABCD, &temp_file("message.received"));

	// Cleanup
	drop(init);
}
