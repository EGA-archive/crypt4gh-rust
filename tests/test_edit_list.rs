mod edit_list_gen;
mod test_common;

use std::fs::File;

pub use test_common::*;
use testresult::TestResult;

const INPUT_EDIT_LIST: &str = "Let's have
 beers 
in the sauna!
 or 
Dinner 
at 7pm?
";

#[test]
fn test_send_message_buried() -> TestResult {
	// Init
	let init = Cleanup::new();

	// Create input file
	echo(
		"Let's have beers in the sauna! or Dinner at 7pm?",
		&temp_file("message.bob"),
	);

	// Bob encrypts a file for Alice, and tucks in an edit list. The skipped pieces are random data.
	let mut file = File::create(&temp_file("message.bob.c4gh"))?;
	edit_list_gen::generate(
		&add_prefix(BOB_SECKEY),
		&add_prefix(ALICE_PUBKEY),
		INPUT_EDIT_LIST,
		&mut file,
		BOB_PASSPHRASE,
	)?;

	// Decrypt
	CommandUnderTest::new()
		.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
		.arg("decrypt")
		.arg("--sk")
		.arg(ALICE_SECKEY)
		.pipe_in(&temp_file("message.bob.c4gh"))
		.pipe_out(&temp_file("message.alice"))
		.succeeds();

	// Compare
	equal(&temp_file("message.bob"), &temp_file("message.alice"));

	// Cleanup
	drop(init);

	// All went fine!
	Ok(())
}
