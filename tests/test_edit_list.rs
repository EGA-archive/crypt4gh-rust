mod edit_list_gen;
mod test_common;

use std::{fs::File, path::PathBuf};

pub use test_common::*;
use testresult::TestResult;
use crypt4gh::keys::get_private_key;
use crypt4gh::Keys;
use std::io::Read;


const INPUT_EDIT_LIST: &str = "Let's have
 beers 
in the sauna!
 or 
Dinner 
at 7pm?
";

#[test]
fn test_send_message_buried() -> TestResult {
	pretty_env_logger::init();

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

	let sender_pubkey = None;
	let (range_start, range_span) = (0, None);

	let seckey = get_private_key(PathBuf::from("tests/testfiles/alice.sec"), Ok(ALICE_PASSPHRASE.to_string()))?;

	let keys = vec![Keys {
		method: 0,
		privkey: seckey,
		recipient_pubkey: vec![],
	}];

	// log::debug!("run_decrypt()'s parameters: {:#?}, {}, {:#?}, {:#?}", &keys, range_start, range_span, &sender_pubkey );

	let mut file = File::open(PathBuf::from("tests/tempfiles/message.bob.c4gh"))?;
	
	let mut out = vec![];
	file.read_to_end(&mut out)?;
	println!("message: {:?}", out);

	let mut buf_in = std::io::BufReader::new(&out[..]);

	let mut buf = vec![];
	// Decrypt
	crypt4gh::decrypt(
		&keys,
		&mut buf_in,
		&mut buf,
		range_start,
		range_span,
		&sender_pubkey,
	)?;

	// CommandUnderTest::new()
	// 	.env("C4GH_PASSPHRASE", ALICE_PASSPHRASE)
	// 	.arg("decrypt")
	// 	.arg("--sk")
	// 	.arg(ALICE_SECKEY)
	// 	.pipe_in(&temp_file("message.bob.c4gh"))
	// 	.pipe_out(&temp_file("message.alice"))
	// 	.succeeds();

	// Compare
	equal(&temp_file("message.bob"), &temp_file("message.alice"));

	// Cleanup
	drop(init);

	// All went fine!
	Ok(())
}
