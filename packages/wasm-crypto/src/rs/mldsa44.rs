// Copyright 2019-2022 @polkadot/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;
use crystals_dilithium::ml_dsa_44;
/// Keypair helper function
fn new_from_seed(seed: &[u8]) -> ml_dsa_44::Keypair {
	ml_dsa_44::Keypair::generate(Some(seed)).expect("Invalid seed provided.")
}

/// Generate a key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the secret (2528 bytes)
/// followed by the public key (1312) bytes.
#[wasm_bindgen]
pub fn ext_mldsa_from_seed(seed: &[u8]) -> Vec<u8> {
	let pair = new_from_seed(seed);
    [seed, &pair.public.to_bytes()].concat()
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
pub fn ext_mldsa_sign(_: &[u8], seed: &[u8], message: &[u8]) -> Vec<u8> {
    let sk: ml_dsa_44::SecretKey = new_from_seed(seed).secret;
	let signature = sk.sign(message, None, crystals_dilithium::RandomMode::Deterministic);
	signature.unwrap().to_vec()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 2420 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 1312 element
#[wasm_bindgen]
pub fn ext_mldsa_verify(signature: &[u8], message: &[u8], pubkey: &[u8]) -> bool {
	if signature.len() != 2420 {
		return false;
	}
    match ml_dsa_44::PublicKey::from_bytes(pubkey) {
        Ok(pk) => pk.verify(message, signature, None),
        _ => false,
    }
}

#[cfg(test)]
pub mod tests {
	extern crate rand;

	use super::*;
	use crystals_dilithium::ml_dsa_44;

    const SEED_LENGTH: usize = 32;
    const PUBLIC_KEY_LENGTH: usize = 1312;
	const KEYPAIR_LENGTH: usize = SEED_LENGTH + PUBLIC_KEY_LENGTH;
	const SECRET_KEY_LENGTH: usize = 2528;
	const SIGNATURE_LENGTH: usize = 2420;

	fn generate_random_seed() -> Vec<u8> {
		(0..32).map(|_| rand::random::<u8>() ).collect()
	}

	#[test]
	fn can_new_keypair() {
		let seed = generate_random_seed();
		let keypair = ext_mldsa_from_seed(seed.as_slice());
		assert!(keypair.len() == KEYPAIR_LENGTH);
	}

	#[test]
	fn can_sign_message() {
		let seed = generate_random_seed();
		let keypair = ext_mldsa_from_seed(seed.as_slice());
		let public = &keypair[SEED_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_mldsa_sign(public, &seed, message);

		assert!(signature.len() == SIGNATURE_LENGTH);
	}

	#[test]
	fn can_verify_message() {
		let seed = generate_random_seed();
		let keypair = ext_mldsa_from_seed(seed.as_slice());
		let public = &keypair[SEED_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_mldsa_sign(public, &seed, message);
		let is_valid = ext_mldsa_verify(&signature[..], message, public);

		assert!(is_valid);
	}
}