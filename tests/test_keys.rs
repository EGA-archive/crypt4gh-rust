mod test_common;

pub use test_common::*;
use testresult::TestResult;

#[test]
fn encrypt_ssh_decrypt() -> TestResult {
	// Init
	let init = Cleanup::new();

	// Create random file
	new_random_file(&temp_file("random.10MB"), 10);

	remove_file(&temp_file(BOB_PUBKEY_SSH));
	remove_file(&temp_file(BOB_SECKEY_SSH));

	ssh_gen(&temp_file(BOB_SECKEY_SSH), BOB_PASSPHRASE);

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(&strip_prefix(BOB_SECKEY_SSH))
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
fn encrypt_decrypt_ssh() -> TestResult{
	// Init
	let init = Cleanup::new();

	// Create random file
	new_random_file(&temp_file("random.10MB"), 10);

	remove_file(&temp_file(ALICE_PUBKEY_SSH));
	remove_file(&temp_file(ALICE_SECKEY_SSH));

	ssh_gen(&temp_file(ALICE_SECKEY_SSH), ALICE_PASSPHRASE);

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(&strip_prefix(ALICE_PUBKEY_SSH))
		.pipe_in(&temp_file("random.10MB"))
		.pipe_out(&temp_file("random.10MB.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(&strip_prefix(ALICE_SECKEY_SSH))
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
fn encrypt_ssh_decrypt_ssh() -> TestResult {
	// Init
	let init = Cleanup::new();

	// Create random file
	new_random_file(&temp_file("random.10MB"), 10);

	remove_file(&temp_file(ALICE_PUBKEY_SSH));
	remove_file(&temp_file(ALICE_SECKEY_SSH));
	remove_file(&temp_file(BOB_PUBKEY_SSH));
	remove_file(&temp_file(BOB_SECKEY_SSH));

	ssh_gen(&temp_file(ALICE_SECKEY_SSH), ALICE_PASSPHRASE);
	ssh_gen(&temp_file(BOB_SECKEY_SSH), BOB_PASSPHRASE);

	// Encrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("encrypt")
		.arg("--sk")
		.arg(&strip_prefix(BOB_SECKEY_SSH))
		.arg("--recipient_pk")
		.arg(&strip_prefix(ALICE_PUBKEY_SSH))
		.pipe_in(&temp_file("random.10MB"))
		.pipe_out(&temp_file("random.10MB.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(&strip_prefix(ALICE_SECKEY_SSH))
		.pipe_in(&temp_file("random.10MB.c4gh"))
		.pipe_out(&temp_file("random.10MB.received"))
		.succeeds();

	// Compare
	equal(&temp_file("random.10MB"), &temp_file("random.10MB.received"));

	// Cleanup
	drop(init);

	Ok(())
}
