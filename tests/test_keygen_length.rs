mod test_common;

use std::path::Path;

pub use test_common::*;

#[test]
fn test_keygen_length_encrypted() {
	// Init
	let init = Cleanup::new();

	let bob_pk_path = temp_file("bob.pub");
	let bob_sk_path = temp_file("bob.sec");
	let callback = || return Ok(BOB_PASSPHRASE.to_string());

	crypt4gh::keys::generate_keys(Path::new(&bob_sk_path), Path::new(&bob_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

    count_characters(&temp_file("bob.pub"), 36 + 45 + 34);
    count_characters(&temp_file("bob.sec"), 37 + 161 + 35);

	// Cleanup
	drop(init);
}

#[test]
fn test_keygen_length_not_encrypted() {
    // Init
	let init = Cleanup::new();

	let alice_pk_path = temp_file("alice.pub");
	let alice_sk_path = temp_file("alice.sec");
	let callback = || return Ok("".to_string());

	crypt4gh::keys::generate_keys(Path::new(&alice_sk_path), Path::new(&alice_pk_path), callback, None)
		.expect("Unable to generate Bob's keys");

    count_characters(&temp_file("alice.pub"), 36 + 45 + 34);
    count_characters(&temp_file("alice.sec"), 37 + 73 + 35);

	// Cleanup
	drop(init);
}
