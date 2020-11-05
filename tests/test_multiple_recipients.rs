mod test_common;

pub use test_common::*;

#[test]
fn send_to_bob_and_alice() {
	// Init
	let init = Cleanup::new();

	// Create random file
	new_random_file(&temp_file("random.10MB"), 10);

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(BOB_PUBKEY)
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("random.10MB"))
		.pipe_out(&temp_file("random.10MB.c4gh"))
		.succeeds();

	// Alice decrypts
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("random.10MB.c4gh"))
		.pipe_out(&temp_file("random.10MB.received"))
		.succeeds();

	// Bob decrypts
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.pipe_in(&temp_file("random.10MB.c4gh"))
		.pipe_out(&temp_file("random.10MB.received"))
		.succeeds();

	// Compare
	equal(&temp_file("random.10MB"), &temp_file("random.10MB.received"));

	// Cleanup
	drop(init);
}

#[test]
fn reencrypt_to_bob_and_alice() {
	// Init
	let init = Cleanup::new();

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(BOB_PUBKEY)
		.pipe_in(TESTFILE_ABCD)
		.pipe_out(&temp_file("message.bob.c4gh"))
		.succeeds();

	// Reencrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("reencrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(BOB_PUBKEY)
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("message.bob.c4gh"))
		.pipe_out(&temp_file("message.c4gh"))
		.succeeds();

	// Alice decrypts
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.c4gh"))
		.pipe_out(&temp_file("message.alice.received"))
		.succeeds();

	// Bob decrypts
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.pipe_in(&temp_file("message.c4gh"))
		.pipe_out(&temp_file("message.bob.received"))
		.succeeds();

	// Compare
	equal(TESTFILE_ABCD, &temp_file("message.alice.received"));
	equal(TESTFILE_ABCD, &temp_file("message.bob.received"));

	// Cleanup
	drop(init);
}
