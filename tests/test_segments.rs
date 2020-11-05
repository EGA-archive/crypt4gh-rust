mod test_common;

pub use test_common::*;

#[test]
fn test_send_all_b() {
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
		.arg("--range")
		.arg("65536-131073")
		.pipe_in(TESTFILE_ABCD)
		.pipe_out(&temp_file("message.b.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.b.c4gh"))
		.pipe_out(&temp_file("message.b.received"))
		.succeeds();

	// Count
	count_characters(&temp_file("message.b.received"), 65536);

	// All Bs
	grep(&temp_file("message.b.received"), "b");

	// Cleanup
	drop(init);
}

#[test]
fn test_send_one_a_all_b_one_c() {
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
		.arg("--range")
		.arg("65535-131074")
		.pipe_in(TESTFILE_ABCD)
		.pipe_out(&temp_file("message.abbbc.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.abbbc.c4gh"))
		.pipe_out(&temp_file("message.abbbc.received"))
		.succeeds();

	// Compare
	equal(TESTFILE_ABBBC, &temp_file("message.abbbc.received"));

	// Cleanup
	drop(init);
}

#[test]
fn test_rearrange_one_a_all_b_one_c() {
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

	// Rearrange
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("rearrange")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--range")
		.arg("65535-131074")
		.pipe_in(&temp_file("message.bob.c4gh"))
		.pipe_out(&temp_file("message.bob.abbbc.c4gh"))
		.succeeds();

	// Reencrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", BOB_PASSPHRASE)
		.arg("reencrypt")
		.arg("--sk")
		.arg(BOB_SECKEY)
		.arg("--recipient_pk")
		.arg(ALICE_PUBKEY)
		.pipe_in(&temp_file("message.bob.abbbc.c4gh"))
		.pipe_out(&temp_file("message.abbbc.c4gh"))
		.succeeds();

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.abbbc.c4gh"))
		.pipe_out(&temp_file("message.abbbc.received"))
		.succeeds();

	// Compare
	equal(TESTFILE_ABBBC, &temp_file("message.abbbc.received"));

	// Cleanup
	drop(init);
}
