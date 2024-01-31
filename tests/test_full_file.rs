mod test_common;

pub use test_common::*;
use testresult::TestResult;

#[test]
fn test_encrypt_decrypt_random() -> TestResult {
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
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("random.10MB"))
		.pipe_out(&temp_file("random.10MB.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("random.10MB.c4gh"))
		.pipe_out(&temp_file("random.10MB.received"))
		.succeeds();

	// Compare
	equal(&temp_file("random.10MB"), &temp_file("random.10MB.received"));

	// Cleanup
	drop(init);

	Ok(())
}

#[test]
fn test_encrypt_decrypt_testfile() -> TestResult {
	// Init
	let init = Cleanup::new();

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

	Ok(())
}

#[test]
fn test_encrypt_then_reencrypt() -> TestResult {
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

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("reencrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("message.bob.c4gh"))
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

	Ok(())
}

#[test]
fn test_encrypt_with_missing_key() -> TestResult {
	// Init
	let init = Cleanup::new();

	// Create random file
	new_random_file(&temp_file("random.10MB"), 10);

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--recipient_pk")
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("random.10MB"))
		.pipe_out(&temp_file("random.10MB.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("random.10MB.c4gh"))
		.pipe_out(&temp_file("random.10MB.received"))
		.succeeds();

	// Compare
	equal(&temp_file("random.10MB"), &temp_file("random.10MB.received"));

	// Cleanup
	drop(init);

	Ok(())
}
