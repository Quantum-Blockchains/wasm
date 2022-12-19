// Copyright 2019-2022 @polkadot/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;
use sp_core::{dilithium2, Pair};
use sp_core::dilithium2::{Public, Signature};

/// Keypair helper function
fn new_from_seed(seed: &[u8]) -> dilithium2::Pair {
	match Pair::from_seed_slice(seed) {
		Ok(pair) => {
			pair
		},
		_ => panic!("Invalid seed provided.")
	}
}

/// Generate a key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the secret (2528 bytes)
/// followed by the public key (1312) bytes.
#[wasm_bindgen]
pub fn ext_dilithium_from_seed(seed: &[u8]) -> Vec<u8> {
	new_from_seed(seed)
		.to_raw_vec()
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * _: UIntArray with 1312 element (was pubkey, now ignored)
/// * seed: UIntArray with 32 element
/// * message: Arbitrary length UIntArray
///
/// * returned vector is the signature consisting of 2420 bytes.
#[wasm_bindgen]
pub fn ext_dilithium_sign(_: &[u8], seed: &[u8], message: &[u8]) -> Vec<u8> {
	// https://github.com/MystenLabs/ed25519-unsafe-libs
	// we never use the provided pubkey
	let signature = new_from_seed(seed).sign(message);
	signature.0.to_vec()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 2420 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 1312 element
#[wasm_bindgen]
pub fn ext_dilithium_verify(signature: &[u8], message: &[u8], pubkey: &[u8]) -> bool {
	let pk_vec = pubkey.to_vec();
	let mut pk_array: [u8; 1312] = [0; 1312];
	pk_array[0..1312].copy_from_slice(&pk_vec[..1312]);
	let pk = Public::from_raw(pk_array);
	match Signature::from_slice(signature) {
		Some(s) => dilithium2::Pair::verify(&s, message, &pk),
		_ => false
	}
}

#[cfg(test)]
pub mod tests {
	extern crate rand;

	use super::*;

	const KEYPAIR_LENGTH: usize = 3840;
	const SECRET_KEY_LENGTH: usize = 2528;
	const SIGNATURE_LENGTH: usize = 2420;

	fn generate_random_seed() -> Vec<u8> {
		(0..32).map(|_| rand::random::<u8>() ).collect()
	}

	#[test]
	fn can_new_keypair() {
		let seed = generate_random_seed();
		let keypair = ext_dilithium_from_seed(seed.as_slice());

		assert!(keypair.len() == KEYPAIR_LENGTH);
	}

	#[test]
	fn creates_pair_from_known() {
		let seed = b"12345678901234567890123456789012";
		let expected = b"1234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012";
		let keypair = ext_dilithium_from_seed(seed);
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}

	#[test]
	fn can_sign_message() {
		let seed = generate_random_seed();
		let keypair = ext_dilithium_from_seed(seed.as_slice());
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_dilithium_sign(public, &seed, message);

		assert!(signature.len() == SIGNATURE_LENGTH);
	}

	#[test]
	fn can_verify_message() {
		let seed = generate_random_seed();
		let keypair = ext_dilithium_from_seed(seed.as_slice());
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_dilithium_sign(public, &seed, message);
		let is_valid = ext_dilithium_verify(&signature[..], message, public);

		assert!(is_valid);
	}
}
