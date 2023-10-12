// Copyright 2019-2022 @polkadot/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::prelude::*;
use crystals_dilithium::dilithium2;
/// Keypair helper function
fn new_from_seed(seed: &[u8]) -> dilithium2::Keypair {
	dilithium2::Keypair::generate(Some(seed))
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
		.to_bytes().to_vec()
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
	let signature = new_from_seed(seed).sign(message);
	signature.to_vec()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 2420 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 1312 element
#[wasm_bindgen]
pub fn ext_dilithium_verify(signature: &[u8], message: &[u8], pubkey: &[u8]) -> bool {
	let pk: dilithium2::PublicKey = dilithium2::PublicKey::from_bytes(pubkey);
	if signature.len() != 2420 {
		return false;
	}
	pk.verify(message, signature)
}

#[cfg(test)]
pub mod tests {
	extern crate rand;

	use super::*;
	use dilithium::dilithium2 as dil2;

	const KEYPAIR_LENGTH: usize = 3840;
	const PUBLIC_KEY_LENGTH: usize = 1312;
	const SECRET_KEY_LENGTH: usize = 2528;
	const SIGNATURE_LENGTH: usize = 2420;

	const TEST_PK: [u8; PUBLIC_KEY_LENGTH] = [
        0x1C, 0x0E, 0xE1, 0x11, 0x1B, 0x08, 0x00, 0x3F, 0x28, 0xE6, 0x5E, 0x8B, 0x3B, 0xDE,
        0xB0, 0x37, 0xCF, 0x8F, 0x22, 0x1D, 0xFC, 0xDA, 0xF5, 0x95, 0x0E, 0xDB, 0x38, 0xD5,
        0x06, 0xD8, 0x5B, 0xEF, 0x61, 0x77, 0xE3, 0xDE, 0x0D, 0x4F, 0x1E, 0xF5, 0x84, 0x77,
        0x35, 0x94, 0x7B, 0x56, 0xD0, 0x8E, 0x84, 0x1D, 0xB2, 0x44, 0x4F, 0xA2, 0xB7, 0x29,
        0xAD, 0xEB, 0x14, 0x17, 0xCA, 0x7A, 0xDF, 0x42, 0xA1, 0x49, 0x0C, 0x5A, 0x09, 0x7F,
        0x00, 0x27, 0x60, 0xC1, 0xFC, 0x41, 0x9B, 0xE8, 0x32, 0x5A, 0xAD, 0x01, 0x97, 0xC5,
        0x2C, 0xED, 0x80, 0xD3, 0xDF, 0x18, 0xE7, 0x77, 0x42, 0x65, 0xB2, 0x89, 0x91, 0x2C,
        0xEC, 0xA1, 0xBE, 0x3A, 0x90, 0xD8, 0xA4, 0xFD, 0xE6, 0x5C, 0x84, 0xC6, 0x10, 0x86,
        0x4E, 0x47, 0xDE, 0xEC, 0xAE, 0x3E, 0xEA, 0x44, 0x30, 0xB9, 0x90, 0x95, 0x59, 0x40,
        0x8D, 0x11, 0xA6, 0xAB, 0xDB, 0x7D, 0xB9, 0x33, 0x6D, 0xF7, 0xF9, 0x6E, 0xAB, 0x48,
        0x64, 0xA6, 0x57, 0x97, 0x91, 0x26, 0x5F, 0xA5, 0x6C, 0x34, 0x8C, 0xB7, 0xD2, 0xDD,
        0xC9, 0x0E, 0x13, 0x3A, 0x95, 0xC3, 0xF6, 0xB1, 0x36, 0x01, 0x42, 0x9F, 0x54, 0x08,
        0xBD, 0x99, 0x9A, 0xA4, 0x79, 0xC1, 0x01, 0x81, 0x59, 0x55, 0x0E, 0xC5, 0x5A, 0x11,
        0x3C, 0x49, 0x3B, 0xE6, 0x48, 0xF4, 0xE0, 0x36, 0xDD, 0x4F, 0x8C, 0x80, 0x9E, 0x03,
        0x6B, 0x4F, 0xBB, 0x91, 0x8C, 0x2C, 0x48, 0x4A, 0xD8, 0xE1, 0x74, 0x7A, 0xE0, 0x55,
        0x85, 0xAB, 0x43, 0x3F, 0xDF, 0x46, 0x1A, 0xF0, 0x3C, 0x25, 0xA7, 0x73, 0x70, 0x07,
        0x21, 0xAA, 0x05, 0xF7, 0x37, 0x9F, 0xE7, 0xF5, 0xED, 0x96, 0x17, 0x5D, 0x40, 0x21,
        0x07, 0x6E, 0x7F, 0x52, 0xB6, 0x03, 0x08, 0xEF, 0xF5, 0xD4, 0x2B, 0xA6, 0xE0, 0x93,
        0xB3, 0xD0, 0x81, 0x5E, 0xB3, 0x49, 0x66, 0x46, 0xE4, 0x92, 0x30, 0xA9, 0xB3, 0x5C,
        0x8D, 0x41, 0x90, 0x0C, 0x2B, 0xB8, 0xD3, 0xB4, 0x46, 0xA2, 0x31, 0x27, 0xF7, 0xE0,
        0x96, 0xD8, 0x5A, 0x1C, 0x79, 0x4A, 0xD4, 0xC8, 0x92, 0x77, 0x90, 0x4F, 0xC6, 0xBF,
        0xEC, 0x57, 0xB1, 0xCD, 0xD8, 0x0D, 0xF9, 0x95, 0x50, 0x30, 0xFD, 0xCA, 0x74, 0x1A,
        0xFB, 0xDA, 0xC8, 0x27, 0xB1, 0x3C, 0xCD, 0x54, 0x03, 0x58, 0x8A, 0xF4, 0x64, 0x40,
        0x03, 0xC2, 0x26, 0x5D, 0xFA, 0x4D, 0x41, 0x9D, 0xBC, 0xCD, 0x20, 0x64, 0x89, 0x23,
        0x86, 0x51, 0x8B, 0xE9, 0xD5, 0x1C, 0x16, 0x49, 0x82, 0x75, 0xEB, 0xEC, 0xF5, 0xCD,
        0xC7, 0xA8, 0x20, 0xF2, 0xC2, 0x93, 0x14, 0xAC, 0x4A, 0x6F, 0x08, 0xB2, 0x25, 0x2A,
        0xD3, 0xCF, 0xB1, 0x99, 0xAA, 0x42, 0xFE, 0x0B, 0x4F, 0xB5, 0x71, 0x97, 0x5C, 0x10,
        0x20, 0xD9, 0x49, 0xE1, 0x94, 0xEE, 0x1E, 0xAD, 0x93, 0x7B, 0xFB, 0x55, 0x0B, 0xB3,
        0xBA, 0x8E, 0x35, 0x7A, 0x02, 0x9C, 0x29, 0xF0, 0x77, 0x55, 0x46, 0x02, 0xE1, 0xCA,
        0x2F, 0x22, 0x89, 0xCB, 0x91, 0x69, 0x94, 0x1C, 0x3A, 0xAF, 0xDB, 0x8E, 0x58, 0xC7,
        0xF2, 0xAC, 0x77, 0x29, 0x1F, 0xB4, 0x14, 0x7C, 0x65, 0xF6, 0xB0, 0x31, 0xD3, 0xEB,
        0xA4, 0x2F, 0x2A, 0xCF, 0xD9, 0x44, 0x8A, 0x5B, 0xC2, 0x2B, 0x47, 0x6E, 0x07, 0xCC,
        0xCE, 0xDA, 0x23, 0x06, 0xC5, 0x54, 0xEC, 0x9B, 0x7A, 0xB6, 0x55, 0xF1, 0xD7, 0x31,
        0x8C, 0x2B, 0x7E, 0x67, 0xD5, 0xF6, 0x9B, 0xED, 0xF5, 0x60, 0x00, 0xFD, 0xA9, 0x89,
        0x86, 0xB5, 0xAB, 0x1B, 0x3A, 0x22, 0xD8, 0xDF, 0xD6, 0x68, 0x16, 0x97, 0xB2, 0x3A,
        0x55, 0xC9, 0x6E, 0x87, 0x10, 0xF3, 0xF9, 0x8C, 0x04, 0x4F, 0xB1, 0x5F, 0x60, 0x63,
        0x13, 0xEE, 0x56, 0xC0, 0xF1, 0xF5, 0xCA, 0x0F, 0x51, 0x2E, 0x08, 0x48, 0x4F, 0xCB,
        0x35, 0x8E, 0x6E, 0x52, 0x8F, 0xFA, 0x89, 0xF8, 0xA8, 0x66, 0xCC, 0xFF, 0x3C, 0x0C,
        0x58, 0x13, 0x14, 0x7E, 0xC5, 0x9A, 0xF0, 0x47, 0x0C, 0x4A, 0xAD, 0x01, 0x41, 0xD3,
        0x4F, 0x10, 0x1D, 0xA2, 0xE5, 0xE1, 0xBD, 0x52, 0xD0, 0xD4, 0xC9, 0xB1, 0x3B, 0x3E,
        0x3D, 0x87, 0xD1, 0x58, 0x61, 0x05, 0x79, 0x67, 0x54, 0xE7, 0x97, 0x8C, 0xA1, 0xC6,
        0x8A, 0x7D, 0x85, 0xDF, 0x11, 0x2B, 0x7A, 0xB9, 0x21, 0xB3, 0x59, 0xA9, 0xF0, 0x3C,
        0xBD, 0x27, 0xA7, 0xEA, 0xC8, 0x7A, 0x9A, 0x80, 0xB0, 0xB2, 0x6B, 0x4C, 0x96, 0x57,
        0xED, 0x85, 0xAD, 0x7F, 0xA2, 0x61, 0x6A, 0xB3, 0x45, 0xEB, 0x82, 0x26, 0xF6, 0x9F,
        0xC0, 0xF4, 0x81, 0x83, 0xFF, 0x57, 0x4B, 0xCD, 0x76, 0x7B, 0x56, 0x76, 0x41, 0x3A,
        0xDB, 0x12, 0xEA, 0x21, 0x50, 0xA0, 0xE9, 0x76, 0x83, 0xEE, 0x54, 0x24, 0x3C, 0x25,
        0xB7, 0xEA, 0x8A, 0x71, 0x86, 0x06, 0xF8, 0x69, 0x93, 0xD8, 0xD0, 0xDA, 0xCE, 0x83,
        0x4E, 0xD3, 0x41, 0xEE, 0xB7, 0x24, 0xFE, 0x3D, 0x5F, 0xF0, 0xBC, 0x8B, 0x8A, 0x7B,
        0x81, 0x04, 0xBA, 0x26, 0x9D, 0x34, 0x13, 0x3A, 0x4C, 0xF8, 0x30, 0x0A, 0x2D, 0x68,
        0x84, 0x96, 0xB5, 0x9B, 0x6F, 0xCB, 0xC6, 0x1A, 0xE9, 0x60, 0x62, 0xEA, 0x1D, 0x8E,
        0x5B, 0x41, 0x0C, 0x56, 0x71, 0xF4, 0x24, 0x41, 0x7E, 0xD6, 0x93, 0x32, 0x9C, 0xD9,
        0x83, 0x00, 0x1F, 0xFC, 0xD1, 0x00, 0x23, 0xD5, 0x98, 0x85, 0x9F, 0xB7, 0xAD, 0x5F,
        0xD2, 0x63, 0x54, 0x71, 0x17, 0x10, 0x06, 0x90, 0xC6, 0xCE, 0x74, 0x38, 0x95, 0x6E,
        0x6C, 0xC5, 0x7F, 0x1B, 0x5D, 0xE5, 0x3B, 0xB0, 0xDC, 0x72, 0xCE, 0x9B, 0x6D, 0xEA,
        0xA8, 0x57, 0x89, 0x59, 0x9A, 0x70, 0xF0, 0x05, 0x1F, 0x1A, 0x0E, 0x25, 0xE8, 0x6D,
        0x88, 0x8B, 0x00, 0xDF, 0x36, 0xBD, 0xBC, 0x93, 0xEF, 0x72, 0x17, 0xC4, 0x5A, 0xCE,
        0x11, 0xC0, 0x79, 0x0D, 0x70, 0xE9, 0x95, 0x3E, 0x5B, 0x41, 0x7B, 0xA2, 0xFD, 0x9A,
        0x4C, 0xAF, 0x82, 0xF1, 0xFC, 0xE6, 0xF4, 0x5F, 0x53, 0xE2, 0x15, 0xB8, 0x35, 0x5E,
        0xF6, 0x1D, 0x89, 0x1D, 0xF1, 0xC7, 0x94, 0x23, 0x1C, 0x16, 0x2D, 0xD2, 0x41, 0x64,
        0xB5, 0x34, 0xA9, 0xD4, 0x84, 0x67, 0xCD, 0xC3, 0x23, 0x62, 0x4C, 0x2F, 0x95, 0xD4,
        0x40, 0x2F, 0xF9, 0xD6, 0x6A, 0xB1, 0x19, 0x1A, 0x81, 0x24, 0x14, 0x4A, 0xFA, 0x35,
        0xD4, 0xE3, 0x1D, 0xC8, 0x6C, 0xAA, 0x79, 0x7C, 0x31, 0xF6, 0x8B, 0x85, 0x85, 0x4C,
        0xD9, 0x59, 0xC4, 0xFA, 0xC5, 0xEC, 0x53, 0xB3, 0xB5, 0x6D, 0x37, 0x4B, 0x88, 0x8A,
        0x9E, 0x97, 0x9A, 0x65, 0x76, 0xB6, 0x34, 0x5E, 0xC8, 0x52, 0x2C, 0x96, 0x06, 0x99,
        0x02, 0x81, 0xBF, 0x3E, 0xF7, 0xC5, 0x94, 0x5D, 0x10, 0xFD, 0x21, 0xA2, 0xA1, 0xD2,
        0xE5, 0x40, 0x4C, 0x5C, 0xF2, 0x12, 0x20, 0x64, 0x13, 0x91, 0xB9, 0x8B, 0xCF, 0x82,
        0x53, 0x98, 0x30, 0x5B, 0x56, 0xE5, 0x8B, 0x61, 0x1F, 0xE5, 0x25, 0x32, 0x03, 0xE3,
        0xDF, 0x0D, 0x22, 0x46, 0x6A, 0x73, 0xB3, 0xF0, 0xFB, 0xE4, 0x3B, 0x9A, 0x62, 0x92,
        0x80, 0x91, 0x89, 0x8B, 0x8A, 0x0E, 0x5B, 0x26, 0x9D, 0xB5, 0x86, 0xB0, 0xE4, 0xDD,
        0xEF, 0x50, 0xD6, 0x82, 0xA1, 0x2D, 0x2C, 0x1B, 0xE8, 0x24, 0x14, 0x9A, 0xA2, 0x54,
        0xC6, 0x38, 0x1B, 0xB4, 0x12, 0xD7, 0x7C, 0x3F, 0x9A, 0xA9, 0x02, 0xB6, 0x88, 0xC8,
        0x17, 0x15, 0xA5, 0x9C, 0x83, 0x95, 0x58, 0x55, 0x6D, 0x35, 0xED, 0x4F, 0xC8, 0x3B,
        0x4A, 0xB1, 0x81, 0x81, 0xF4, 0x0F, 0x73, 0xDC, 0xD7, 0x68, 0x60, 0xD8, 0xD8, 0xBF,
        0x94, 0x52, 0x02, 0x37, 0xC2, 0xAC, 0x0E, 0x46, 0x3B, 0xA0, 0x9E, 0x3C, 0x97, 0x82,
        0x38, 0x0D, 0xC0, 0x7F, 0xE4, 0xFC, 0xBA, 0x34, 0x0C, 0xC2, 0x00, 0x34, 0x39, 0xFD,
        0x23, 0x14, 0x61, 0x06, 0x38, 0x07, 0x0D, 0x6C, 0x9E, 0xEA, 0x0A, 0x70, 0xBA, 0xE8,
        0x3B, 0x5D, 0x5D, 0x3C, 0x5D, 0x3F, 0xDE, 0x26, 0xDD, 0x01, 0x60, 0x6C, 0x8C, 0x52,
        0x01, 0x58, 0xE7, 0xE5, 0x10, 0x40, 0x20, 0xF2, 0x48, 0xCE, 0xAA, 0x66, 0x64, 0x57,
        0xC1, 0x0A, 0xEB, 0xF0, 0x68, 0xF8, 0xA3, 0xBD, 0x5C, 0xE7, 0xB5, 0x2C, 0x6A, 0xF0,
        0xAB, 0xD5, 0x94, 0x4A, 0xF1, 0xAD, 0x47, 0x52, 0xC9, 0x11, 0x39, 0x76, 0x08, 0x3C,
        0x03, 0xB6, 0xC3, 0x4E, 0x1D, 0x47, 0xED, 0x69, 0x64, 0x4C, 0xAD, 0x78, 0x2C, 0x2F,
        0x7D, 0x05, 0xF8, 0xA1, 0x48, 0x96, 0x1D, 0x96, 0x5F, 0xA2, 0xE1, 0x72, 0x3A, 0x8D,
        0xDE, 0xBC, 0x22, 0xA9, 0x0C, 0xD7, 0x83, 0xDD, 0x1F, 0x4D, 0xB3, 0x8F, 0xB9, 0xAE,
        0x5A, 0x67, 0x14, 0xB3, 0xD9, 0x46, 0x78, 0x16, 0x43, 0xD3, 0x17, 0xB7, 0xDD, 0x79,
        0x38, 0x1C, 0xF7, 0x89, 0xA9, 0x58, 0x8B, 0xB3, 0xE1, 0x93, 0xB9, 0x2A, 0x0B, 0x60,
        0xD6, 0xB0, 0x7D, 0x04, 0x7F, 0x69, 0x84, 0xB0, 0x60, 0x9E, 0xC5, 0x75, 0x43, 0xC3,
        0x94, 0xCA, 0x8D, 0x5E, 0x5B, 0xCC, 0x2A, 0x73, 0x1A, 0x79, 0x61, 0x8B, 0xD1, 0xE2,
        0xE0, 0xDA, 0x87, 0x04, 0xAF, 0x98, 0xF2, 0x0F, 0x5F, 0x8F, 0x54, 0x52, 0xDD, 0xF6,
        0x46, 0xB9, 0x5B, 0x34, 0x1D, 0xD7, 0xF0, 0xD2, 0xCC, 0x1F, 0xA1, 0x5B, 0xD9, 0x89,
        0x5C, 0xD5, 0xB6, 0x5A, 0xA1, 0xCB, 0x94, 0xB5, 0xE2, 0xE7, 0x88, 0xFD, 0xA9, 0x82,
        0x5B, 0x65, 0x66, 0x39, 0x19, 0x3D, 0x98, 0x32, 0x81, 0x54, 0xA4, 0xF2, 0xC3, 0x54,
        0x95, 0xA3, 0x8B, 0x6E, 0xA0, 0xD2, 0xFF, 0xAA, 0xA3, 0x5D, 0xF9, 0x2C, 0x20, 0x3C,
        0x7F, 0x31, 0xCB, 0xBC, 0xA7, 0xBD, 0x03, 0xC3, 0xC2, 0x30, 0x21, 0x90, 0xCE, 0xCD,
        0x16, 0x1F, 0xD4, 0x92, 0x37, 0xE4, 0xF8, 0x39, 0xE3, 0xF3,
    ];
    const TEST_SK: [u8; SECRET_KEY_LENGTH] = [
        0x1C, 0x0E, 0xE1, 0x11, 0x1B, 0x08, 0x00, 0x3F, 0x28, 0xE6, 0x5E, 0x8B, 0x3B, 0xDE,
        0xB0, 0x37, 0xCF, 0x8F, 0x22, 0x1D, 0xFC, 0xDA, 0xF5, 0x95, 0x0E, 0xDB, 0x38, 0xD5,
        0x06, 0xD8, 0x5B, 0xEF, 0x39, 0x4D, 0x16, 0x95, 0x05, 0x9D, 0xFF, 0x40, 0xAE, 0x25,
        0x6C, 0x5D, 0x5E, 0xDA, 0xBF, 0xB6, 0x9F, 0x5F, 0x40, 0xF3, 0x7A, 0x58, 0x8F, 0x50,
        0x53, 0x2C, 0xA4, 0x08, 0xA8, 0x16, 0x8A, 0xB1, 0x87, 0xD0, 0xAD, 0x11, 0x52, 0x21,
        0x10, 0x93, 0x14, 0x94, 0xBF, 0x2C, 0xAE, 0xAE, 0x36, 0x97, 0x97, 0x11, 0xBC, 0x58,
        0x5B, 0x32, 0xF0, 0x8C, 0x78, 0x49, 0x6F, 0x37, 0x9D, 0x60, 0x4D, 0x53, 0xC0, 0xA6,
        0x71, 0x1A, 0x96, 0x6C, 0x11, 0x31, 0x2A, 0xD9, 0xA8, 0x21, 0xD8, 0x08, 0x65, 0x42,
        0xA6, 0x00, 0xA4, 0xB4, 0x2C, 0x19, 0x40, 0x72, 0x02, 0x42, 0x62, 0x81, 0x06, 0x21,
        0x0A, 0x43, 0x85, 0x23, 0x31, 0x70, 0x93, 0x08, 0x10, 0x8B, 0x18, 0x8C, 0x02, 0x24,
        0x92, 0xC1, 0xB2, 0x84, 0x12, 0xC4, 0x21, 0x8B, 0x04, 0x21, 0x81, 0xC8, 0x61, 0x02,
        0x48, 0x05, 0x9C, 0x92, 0x01, 0xC0, 0x34, 0x88, 0x19, 0x32, 0x6C, 0x58, 0x20, 0x46,
        0x89, 0x18, 0x68, 0xA2, 0xC2, 0x8D, 0x82, 0x34, 0x6A, 0x1C, 0x09, 0x42, 0x00, 0xA2,
        0x8C, 0xE3, 0xA6, 0x49, 0x1C, 0x11, 0x2C, 0xC2, 0x48, 0x12, 0xE0, 0x90, 0x21, 0x91,
        0x98, 0x50, 0x62, 0xC0, 0x84, 0x62, 0x24, 0x51, 0xCA, 0x06, 0x2C, 0x64, 0x24, 0x0E,
        0x1B, 0xB3, 0x31, 0x24, 0x96, 0x85, 0x4B, 0x46, 0x06, 0xDB, 0x26, 0x68, 0xC3, 0x82,
        0x68, 0x44, 0x10, 0x46, 0xC9, 0xB6, 0x21, 0x14, 0x04, 0x81, 0x14, 0x45, 0x50, 0x24,
        0x42, 0x08, 0x44, 0x22, 0x71, 0x0B, 0x92, 0x45, 0x9A, 0xA0, 0x81, 0x1A, 0x91, 0x70,
        0x9C, 0x24, 0x10, 0x03, 0x95, 0x70, 0x04, 0xC5, 0x04, 0xC8, 0x26, 0x92, 0xD2, 0x92,
        0x00, 0xC0, 0xB2, 0x60, 0xC0, 0xA2, 0x68, 0x09, 0x19, 0x0A, 0xA2, 0x30, 0x0E, 0x18,
        0x89, 0x69, 0xE0, 0x00, 0x8D, 0xD8, 0x48, 0x62, 0xDA, 0x14, 0x71, 0x20, 0x18, 0x05,
        0x19, 0x07, 0x44, 0x04, 0x12, 0x40, 0x9B, 0x12, 0x40, 0x11, 0x80, 0x10, 0xD1, 0x42,
        0x81, 0x99, 0x28, 0x50, 0x8B, 0x10, 0x91, 0x02, 0x24, 0x64, 0xA0, 0x20, 0x6D, 0x12,
        0x46, 0x21, 0x1C, 0x83, 0x8C, 0x1B, 0x47, 0x69, 0x01, 0x06, 0x90, 0xCC, 0x06, 0x24,
        0x81, 0x84, 0x69, 0x20, 0x98, 0x2C, 0x24, 0x12, 0x05, 0x21, 0xB1, 0x50, 0x41, 0x36,
        0x02, 0x98, 0x44, 0x6E, 0xD1, 0xA6, 0x31, 0x11, 0x05, 0x6A, 0xD3, 0xA8, 0x40, 0xCA,
        0xA8, 0x4C, 0x62, 0xB0, 0x00, 0x03, 0x13, 0x4A, 0x53, 0x34, 0x46, 0x14, 0x19, 0x40,
        0x04, 0xC5, 0x4C, 0xE3, 0x06, 0x69, 0x5A, 0xB0, 0x89, 0x61, 0x16, 0x8E, 0xCB, 0x10,
        0x80, 0x8B, 0x16, 0x8E, 0xD9, 0x90, 0x64, 0x0B, 0x94, 0x60, 0x24, 0x83, 0x85, 0x1A,
        0xB3, 0x04, 0x54, 0x26, 0x22, 0x51, 0xB8, 0x25, 0x1C, 0x42, 0x4A, 0x0B, 0x81, 0x48,
        0x42, 0xC4, 0x44, 0x5A, 0x10, 0x20, 0x23, 0x80, 0x84, 0x09, 0xB7, 0x25, 0x4C, 0xC6,
        0x48, 0x14, 0x85, 0x4D, 0x19, 0x38, 0x0E, 0x60, 0x16, 0x51, 0xD8, 0x32, 0x6A, 0x0A,
        0x91, 0x89, 0x08, 0xC1, 0x70, 0xE0, 0x96, 0x4D, 0x18, 0x46, 0x8C, 0x01, 0x32, 0x8D,
        0x91, 0xC4, 0x05, 0x4A, 0x00, 0x61, 0x23, 0x08, 0x68, 0xA2, 0x10, 0x42, 0x10, 0xA8,
        0x61, 0x13, 0x06, 0x21, 0x8A, 0x24, 0x8E, 0x62, 0x06, 0x89, 0xC9, 0xB2, 0x45, 0x08,
        0x27, 0x84, 0x51, 0x20, 0x0D, 0x98, 0x04, 0x66, 0xDC, 0x42, 0x05, 0x44, 0x24, 0x85,
        0x24, 0x26, 0x28, 0x22, 0x21, 0x61, 0x20, 0x16, 0x09, 0x0B, 0xA6, 0x2C, 0x0A, 0x11,
        0x44, 0xE0, 0x92, 0x81, 0x58, 0x48, 0x0D, 0x42, 0x22, 0x10, 0xA0, 0x06, 0x09, 0x8B,
        0x24, 0x6E, 0x81, 0x28, 0x8C, 0xC0, 0x24, 0x80, 0x90, 0x30, 0x8D, 0x84, 0x36, 0x40,
        0x4C, 0xA6, 0x84, 0x50, 0x04, 0x24, 0x94, 0xB6, 0x8D, 0xA2, 0x92, 0x6D, 0x18, 0xB3,
        0x44, 0xA0, 0x00, 0x85, 0xE3, 0xB8, 0x05, 0x14, 0x05, 0x04, 0xA4, 0xC2, 0x90, 0x84,
        0x22, 0x81, 0xC3, 0x26, 0x2D, 0x0B, 0x20, 0x66, 0xCC, 0x90, 0x31, 0x98, 0x38, 0x28,
        0x10, 0x16, 0x6C, 0xC1, 0x34, 0x45, 0xC0, 0x10, 0x22, 0x24, 0xC6, 0x88, 0x03, 0x46,
        0x32, 0xD8, 0x40, 0x90, 0x1C, 0x20, 0x68, 0x04, 0x15, 0x28, 0x9A, 0x18, 0x81, 0x44,
        0x98, 0x8D, 0x9C, 0x20, 0x6E, 0x9C, 0x30, 0x2C, 0xC1, 0xB8, 0x20, 0x61, 0x42, 0x21,
        0x08, 0x03, 0x10, 0xA0, 0xC2, 0x8C, 0x58, 0x12, 0x85, 0x53, 0x20, 0x4C, 0x03, 0x30,
        0x81, 0x4C, 0xA4, 0x8D, 0x44, 0xC0, 0x8D, 0x51, 0x40, 0x4C, 0x1C, 0xA7, 0x2C, 0x44,
        0x08, 0x65, 0xA0, 0x38, 0x40, 0xDA, 0x20, 0x80, 0x81, 0x06, 0x85, 0x8C, 0x26, 0x0D,
        0xE2, 0xA8, 0x8C, 0x9C, 0x44, 0x11, 0x59, 0x42, 0x28, 0xC4, 0x26, 0x04, 0x44, 0x14,
        0x26, 0xA1, 0x42, 0x64, 0x08, 0xC0, 0x85, 0x11, 0x01, 0x86, 0x9B, 0x48, 0x31, 0x99,
        0xB2, 0x0C, 0x80, 0x46, 0x44, 0x59, 0xA8, 0x8C, 0x00, 0x42, 0x08, 0x98, 0x82, 0x90,
        0x0A, 0xB5, 0x45, 0x62, 0x24, 0x48, 0x12, 0x96, 0x05, 0x44, 0x12, 0x46, 0x00, 0xC8,
        0x88, 0x13, 0xA0, 0x61, 0xE1, 0x28, 0x4D, 0x0A, 0xB9, 0x91, 0x4B, 0x96, 0x20, 0x99,
        0xB8, 0x44, 0x00, 0x31, 0x4E, 0x98, 0x12, 0x85, 0x00, 0xB6, 0x01, 0x83, 0xA0, 0x0D,
        0x14, 0x15, 0x0E, 0x18, 0x81, 0x10, 0x19, 0x01, 0x22, 0x4A, 0x06, 0x68, 0x1A, 0x49,
        0x8D, 0xE1, 0xA2, 0x84, 0x11, 0xC6, 0x31, 0x21, 0x26, 0x25, 0x91, 0xA0, 0x6D, 0x03,
        0x05, 0x24, 0xA1, 0xB6, 0x08, 0x94, 0x44, 0x72, 0x43, 0x34, 0x12, 0x5B, 0xB4, 0x20,
        0x41, 0xB6, 0x50, 0xD0, 0x88, 0x8D, 0x0B, 0x07, 0x4D, 0x1C, 0x94, 0x64, 0x4C, 0x20,
        0x8E, 0x8B, 0x88, 0x08, 0xE0, 0x30, 0x09, 0x44, 0x20, 0x05, 0x49, 0x86, 0x4D, 0x03,
        0x13, 0x4E, 0x19, 0xC9, 0x84, 0x09, 0x37, 0x61, 0x1A, 0x43, 0x68, 0x4A, 0x80, 0x90,
        0x02, 0x04, 0x31, 0x1C, 0x17, 0x42, 0x18, 0x40, 0x80, 0xC8, 0x30, 0x8E, 0xE1, 0xA2,
        0x41, 0xC3, 0x34, 0x04, 0xA3, 0x28, 0x22, 0x51, 0x24, 0x71, 0x88, 0xD6, 0xFE, 0xF4,
        0x67, 0x12, 0xCA, 0x18, 0x28, 0x72, 0xAB, 0x29, 0x19, 0x67, 0x8A, 0xFF, 0x9D, 0x94,
        0xE7, 0x43, 0xE0, 0x63, 0xA3, 0x9E, 0x0C, 0x35, 0xCA, 0xF7, 0x2A, 0x7F, 0x2E, 0xDA,
        0x28, 0xE6, 0x58, 0x58, 0x52, 0x0D, 0x5D, 0x84, 0x67, 0xDE, 0x74, 0x7C, 0xF3, 0x40,
        0x65, 0x3B, 0x52, 0xC2, 0x68, 0xF5, 0x54, 0x13, 0xF5, 0xAD, 0xDC, 0x7D, 0x49, 0x01,
        0x1E, 0xC3, 0x3E, 0xDD, 0x53, 0x74, 0x23, 0xA8, 0x42, 0x88, 0x86, 0x93, 0x37, 0xAE,
        0xA0, 0x78, 0x1A, 0x12, 0x42, 0x69, 0x07, 0x14, 0x51, 0x72, 0x2D, 0xB3, 0xBB, 0x8F,
        0x2C, 0xE5, 0xB1, 0x55, 0x2F, 0x83, 0xD2, 0xAF, 0x07, 0xF2, 0x56, 0x13, 0x91, 0x8A,
        0x9F, 0x4E, 0x6F, 0x12, 0x57, 0x60, 0x38, 0x88, 0xE5, 0x89, 0x30, 0x8C, 0xA5, 0xF9,
        0x5F, 0x07, 0x14, 0x3D, 0x23, 0xBA, 0xAE, 0x17, 0x52, 0x0B, 0x36, 0xB6, 0xE0, 0xE9,
        0x4F, 0xAF, 0x68, 0x45, 0xEB, 0x21, 0x31, 0xAE, 0xC3, 0x83, 0xE6, 0x3B, 0xC8, 0x64,
        0x4E, 0xE5, 0xF1, 0xAC, 0xCB, 0xA8, 0x2F, 0x92, 0x11, 0xE5, 0x7A, 0xFC, 0xBF, 0x50,
        0x9C, 0x11, 0x31, 0xA3, 0x74, 0x66, 0xBC, 0x91, 0xB3, 0x57, 0xDC, 0xBB, 0xBC, 0x14,
        0xCC, 0xC3, 0x19, 0xC4, 0xCC, 0x6A, 0xC7, 0x5F, 0xCD, 0xC8, 0x2C, 0x65, 0x96, 0xD0,
        0x77, 0x70, 0xC8, 0x27, 0x7A, 0xD3, 0x70, 0xB1, 0x92, 0xA0, 0xB4, 0xE0, 0x5F, 0x81,
        0x2E, 0x0E, 0x26, 0x5D, 0x29, 0x12, 0xAA, 0x29, 0xF0, 0x3F, 0xC9, 0xF7, 0x2D, 0xFA,
        0x69, 0xC9, 0xB1, 0x29, 0x1A, 0x3F, 0xC5, 0x83, 0x64, 0x2B, 0x23, 0x5F, 0x69, 0x91,
        0xA9, 0x54, 0x78, 0x83, 0x47, 0xF6, 0x0A, 0x03, 0x28, 0xC4, 0x8E, 0xCE, 0xE5, 0x1B,
        0xA0, 0x2D, 0xFF, 0x32, 0x3A, 0xBD, 0x91, 0x16, 0x67, 0xCB, 0x14, 0x54, 0x9B, 0x61,
        0x8F, 0x1C, 0x5D, 0x25, 0x0C, 0xAC, 0x9E, 0x35, 0xE0, 0x71, 0x60, 0x19, 0x92, 0xFB,
        0xEC, 0x0B, 0xAE, 0x6F, 0x74, 0x21, 0x30, 0x81, 0x40, 0x47, 0x44, 0xD1, 0x2F, 0x2A,
        0x0E, 0x04, 0xBD, 0xB2, 0x65, 0xE0, 0x92, 0x4C, 0xAD, 0xA4, 0x0D, 0x1F, 0xA1, 0xF3,
        0x8A, 0xCA, 0x46, 0x06, 0xBF, 0xD4, 0x57, 0x57, 0x12, 0xB8, 0x26, 0x0A, 0x45, 0x6F,
        0xDD, 0xEE, 0xEF, 0xE7, 0xCA, 0x25, 0x9B, 0xCD, 0xA9, 0x7B, 0x9B, 0x93, 0x9A, 0x5F,
        0xD2, 0x88, 0x9C, 0x9B, 0x49, 0xFB, 0x7D, 0x4E, 0x35, 0x53, 0xDE, 0xA6, 0x1B, 0x33,
        0x39, 0xBD, 0x0E, 0x6B, 0x16, 0xBF, 0x3B, 0xB2, 0x27, 0x10, 0x3B, 0xF9, 0x20, 0x2E,
        0x72, 0xDC, 0x50, 0x2E, 0x28, 0xF7, 0xCE, 0x15, 0x59, 0xA4, 0x63, 0x1F, 0x37, 0x25,
        0x20, 0x32, 0x4E, 0x4E, 0xBA, 0x07, 0x54, 0x5F, 0x78, 0xBF, 0x4D, 0x94, 0xB0, 0xE5,
        0xB8, 0xBF, 0x51, 0xB8, 0xF1, 0x76, 0x53, 0x3D, 0x5C, 0xFE, 0xA5, 0x23, 0x2F, 0x28,
        0x3A, 0x47, 0x60, 0x5F, 0xA6, 0x5D, 0xDB, 0x17, 0xC8, 0x91, 0xC2, 0x51, 0x01, 0x1C,
        0x4E, 0x98, 0xEE, 0xB6, 0xEB, 0x00, 0xCB, 0x65, 0xBA, 0x31, 0xC8, 0xF0, 0x25, 0xC8,
        0x7A, 0x9F, 0xE0, 0x2D, 0xBC, 0x10, 0xC5, 0xD8, 0x3A, 0x06, 0x5E, 0xBA, 0x5D, 0x7B,
        0x2A, 0x19, 0xD5, 0xA1, 0xCB, 0x2C, 0x16, 0x0A, 0xE1, 0x66, 0xE8, 0x67, 0xF2, 0xAF,
        0x8C, 0x7D, 0x49, 0xD6, 0x3F, 0xB8, 0x3A, 0x61, 0x49, 0x57, 0xFC, 0x0A, 0x3B, 0x5A,
        0x5C, 0x74, 0x99, 0x0E, 0x9A, 0x2B, 0x02, 0x12, 0x0C, 0x7E, 0x6D, 0xE3, 0x7E, 0x15,
        0x5F, 0xB4, 0x72, 0xF5, 0x0F, 0x0A, 0x45, 0xE4, 0x7C, 0xF5, 0xF9, 0xD7, 0xA4, 0xC8,
        0x29, 0x82, 0xC9, 0xDC, 0x86, 0xAE, 0x87, 0x7C, 0x3F, 0xD1, 0x88, 0x59, 0x43, 0xE4,
        0x39, 0xFB, 0x00, 0x3C, 0x7A, 0x9A, 0x42, 0xF7, 0x1B, 0x4F, 0xF6, 0xF0, 0xA2, 0x8B,
        0x14, 0x0C, 0xBD, 0xBA, 0x6E, 0x71, 0xB1, 0x3A, 0xC3, 0x1B, 0x23, 0xDE, 0x9E, 0xAB,
        0x78, 0x37, 0xE1, 0x5A, 0x69, 0xF8, 0x33, 0xEB, 0x7B, 0x56, 0xA7, 0x1D, 0x8B, 0xC2,
        0xCA, 0xF1, 0xF2, 0xA3, 0x1C, 0x34, 0x5B, 0xD5, 0xF4, 0x6E, 0xE0, 0x13, 0xA7, 0xC6,
        0x89, 0x37, 0x23, 0x37, 0x19, 0x1D, 0xAA, 0x80, 0x0C, 0x0A, 0xC6, 0xC4, 0x6C, 0x9F,
        0xF6, 0x88, 0xB1, 0xA0, 0x13, 0x47, 0xF2, 0x57, 0xC4, 0x74, 0xAA, 0x3D, 0x97, 0xC1,
        0xD6, 0x3A, 0x8C, 0x00, 0xE0, 0xA3, 0x7B, 0x68, 0x16, 0x73, 0xF5, 0x7C, 0x1C, 0x9C,
        0x8F, 0xCC, 0xD4, 0x6F, 0x17, 0x4C, 0x74, 0xA2, 0x9D, 0x84, 0xCE, 0xB7, 0x1F, 0x7E,
        0x6B, 0x2F, 0x8C, 0xD2, 0xB0, 0x89, 0xED, 0x43, 0xF7, 0xC9, 0x6D, 0xAE, 0x81, 0xA2,
        0x23, 0x41, 0x8C, 0x20, 0xB1, 0x6F, 0x1D, 0xF3, 0xD1, 0xA9, 0x78, 0xAE, 0x28, 0xF6,
        0xDF, 0x35, 0xEC, 0x55, 0x9D, 0x04, 0xD2, 0x0E, 0xC7, 0x4B, 0x22, 0x4A, 0xEA, 0x31,
        0xA2, 0x89, 0xB0, 0x15, 0xB0, 0x69, 0xE9, 0xCB, 0xBB, 0xF7, 0xCF, 0x6D, 0xE9, 0x4C,
        0xFB, 0x2A, 0x96, 0xE4, 0xAE, 0x34, 0x62, 0xC9, 0x60, 0x03, 0xCD, 0xDA, 0x87, 0xDB,
        0x56, 0x1A, 0xF2, 0xCE, 0x3C, 0x0B, 0xA1, 0xD9, 0x04, 0x13, 0xFD, 0xCE, 0x3C, 0xCF,
        0x43, 0x90, 0xC0, 0x2C, 0x1C, 0xB9, 0xF6, 0x54, 0xF4, 0x82, 0x0E, 0xC3, 0x30, 0x15,
        0x45, 0x7D, 0x4A, 0x62, 0x9F, 0xBF, 0x39, 0x41, 0x9C, 0xAB, 0x76, 0x42, 0xD6, 0x88,
        0x5E, 0x10, 0x3F, 0xCE, 0x0D, 0x42, 0x06, 0xCC, 0xE7, 0xC1, 0x2C, 0x6F, 0xC4, 0x4F,
        0xA3, 0x3A, 0xD0, 0x86, 0x4C, 0x33, 0x71, 0xA7, 0xCB, 0xE8, 0x20, 0xE3, 0xB3, 0x71,
        0xB6, 0x56, 0xA3, 0x8F, 0x2E, 0x7F, 0xF1, 0x8F, 0xE4, 0xA5, 0x0C, 0x8A, 0xB3, 0xF8,
        0x5D, 0x78, 0x3F, 0xB5, 0x78, 0x35, 0xCE, 0xD8, 0x49, 0x0B, 0x84, 0xEE, 0x0D, 0x99,
        0xAF, 0x0D, 0x64, 0xC4, 0x83, 0xCE, 0xB6, 0x36, 0x6F, 0xF5, 0x4F, 0x8A, 0xC8, 0xA4,
        0x0D, 0xB1, 0xAF, 0xA5, 0x73, 0xA4, 0xFB, 0x32, 0x6C, 0x74, 0xF0, 0x23, 0x6E, 0xCE,
        0xF3, 0xDA, 0x71, 0x20, 0x66, 0x5C, 0xCE, 0x05, 0xDD, 0x65, 0x4B, 0x50, 0x71, 0x72,
        0x3A, 0x83, 0x48, 0xE7, 0xCD, 0x77, 0x93, 0x51, 0x38, 0x19, 0xB6, 0x1C, 0xB6, 0x4E,
        0x13, 0x28, 0xE8, 0xB2, 0x2E, 0x76, 0x64, 0xBD, 0x6B, 0x41, 0xB5, 0x71, 0x0D, 0x19,
        0xEA, 0x88, 0x09, 0xD4, 0x45, 0x08, 0x50, 0xE9, 0x07, 0xDF, 0xC4, 0xD0, 0xB7, 0x5F,
        0x58, 0x8C, 0xEC, 0xE9, 0x62, 0xE9, 0xE0, 0x93, 0x7C, 0xE1, 0x40, 0x24, 0x46, 0xA4,
        0xD2, 0x89, 0x1A, 0x46, 0xE6, 0x61, 0x7F, 0xB2, 0x9D, 0x4F, 0xCD, 0x71, 0x26, 0x06,
        0xF7, 0x81, 0x9E, 0xCA, 0x60, 0xF7, 0xE0, 0xD5, 0xB1, 0x9E, 0x7F, 0xFB, 0x57, 0xC7,
        0x3C, 0x16, 0xFF, 0xEE, 0xB9, 0x00, 0x38, 0x41, 0x0C, 0xB9, 0xFC, 0xBB, 0x5E, 0x9D,
        0x51, 0xEB, 0x3E, 0xB6, 0x29, 0x7E, 0x9F, 0xF6, 0xAB, 0x70, 0x88, 0xFE, 0x2D, 0x9B,
        0x23, 0x7B, 0xC2, 0x4C, 0xF7, 0xF8, 0x29, 0x01, 0x18, 0xA5, 0xE0, 0xE0, 0x0A, 0x0B,
        0x90, 0x3F, 0xB6, 0x37, 0x5C, 0x84, 0x81, 0x76, 0xCD, 0x0A, 0x8C, 0x88, 0x75, 0xCC,
        0x59, 0x19, 0x9C, 0xDA, 0x11, 0xA8, 0x7A, 0x78, 0xF6, 0x5C, 0xC4, 0x04, 0x33, 0x0B,
        0x08, 0x75, 0x71, 0xFD, 0x06, 0x33, 0xE2, 0x71, 0x29, 0xFD, 0xAB, 0x5A, 0x8A, 0x1F,
        0x79, 0x3E, 0x52, 0x41, 0x2B, 0x00, 0x83, 0xFD, 0x5C, 0x74, 0xDB, 0x3C, 0xF6, 0x0C,
        0x25, 0x43, 0xCE, 0x7C, 0x91, 0xB2, 0x80, 0x0E, 0x40, 0x20, 0x3F, 0x8D, 0x99, 0xFE,
        0x5F, 0xDE, 0x5B, 0x10, 0x8E, 0x7E, 0xDC, 0x80, 0xEB, 0xB9, 0xBB, 0x34, 0x98, 0x6E,
        0xC5, 0xC5, 0xA8, 0xF5, 0x80, 0xE7, 0x57, 0x52, 0x90, 0x7F, 0xF0, 0xF2, 0x94, 0xC8,
        0x66, 0xC2, 0xCF, 0x1F, 0x36, 0x2E, 0x84, 0x0B, 0x68, 0x81, 0xBD, 0x43, 0x21, 0x92,
        0x01, 0x78, 0x1C, 0x63, 0xB0, 0x03, 0x9A, 0x95, 0xBC, 0xFB, 0x4A, 0x0F, 0xEC, 0xE5,
        0x69, 0xDF, 0x00, 0x52, 0x3C, 0xE9, 0xC0, 0x84, 0xB0, 0x22, 0xB3, 0xB0, 0x22, 0x24,
        0x2E, 0x28, 0x41, 0x97, 0x96, 0xAC, 0xF0, 0xA0, 0xC9, 0x95, 0xF9, 0x48, 0xDB, 0xFF,
        0xFD, 0x30, 0xD7, 0x7E, 0xD1, 0x05, 0xA3, 0xC9, 0x94, 0x3C, 0x40, 0x6B, 0x30, 0x5B,
        0xC8, 0x1A, 0x6A, 0x24, 0x8A, 0x29, 0x15, 0x48, 0xF2, 0xA6, 0x7F, 0x43, 0x8D, 0x96,
        0x6A, 0x57, 0xD5, 0x3F, 0x4B, 0x7B, 0xE1, 0x53, 0x54, 0xE5, 0x81, 0xBE, 0x16, 0xF7,
        0xAD, 0x64, 0xD1, 0x64, 0xE8, 0x57, 0x87, 0xDF, 0x58, 0x49, 0xC8, 0x10, 0xAF, 0xC2,
        0x8D, 0x06, 0x48, 0x2F, 0x44, 0x1B, 0x5F, 0xDE, 0x3D, 0xB2, 0xED, 0x36, 0xDD, 0x25,
        0xAA, 0x66, 0x64, 0xD4, 0xD4, 0x3F, 0xFA, 0x32, 0xED, 0xA2, 0x56, 0x89, 0xC9, 0xF4,
        0xA5, 0xD5, 0x14, 0xFC, 0x66, 0x23, 0x1C, 0x54, 0x01, 0x52, 0x09, 0x22, 0x52, 0x44,
        0x38, 0xEF, 0x1D, 0xC7, 0x8D, 0x69, 0x3C, 0x97, 0x18, 0xDE, 0xBB, 0xD2, 0x43, 0x31,
        0x26, 0x74, 0xC8, 0x99, 0xF1, 0x89, 0x10, 0xE3, 0x89, 0xC8, 0xEB, 0xE5, 0x05, 0x82,
        0x4B, 0xCC, 0x42, 0xCD, 0x4A, 0x9A, 0xCE, 0x19, 0x37, 0x68, 0x22, 0x02, 0x19, 0x01,
        0x1F, 0x3B, 0x1F, 0x33, 0x54, 0x27, 0xBF, 0xF9, 0xE8, 0xBD, 0xED, 0x5C, 0x08, 0x71,
        0x1A, 0x09, 0xC2, 0xB7, 0x1C, 0xB9, 0x64, 0xC5, 0x6A, 0x83, 0x93, 0xBF, 0xD2, 0xB5,
        0x6E, 0x9B, 0x6B, 0x2F, 0x51, 0x3E, 0x68, 0x25, 0x87, 0xDC, 0x1B, 0x8E, 0xD1, 0x96,
        0x06, 0x63, 0x26, 0x87, 0x10, 0x25, 0x62, 0x80, 0x36, 0x70, 0x00, 0x63, 0x17, 0x6D,
        0x34, 0x5D, 0xE3, 0x84, 0xE1, 0x82, 0xD6, 0xC4, 0x17, 0xA3, 0x2A, 0xB1, 0x10, 0x95,
        0xEF, 0x59, 0xBB, 0x4D, 0x17, 0x1B, 0x9C, 0xF8, 0x1D, 0x17, 0xAC, 0x42, 0x66, 0x4D,
        0xED, 0x93, 0x3C, 0xCB, 0x72, 0x2C, 0x69, 0x85, 0x7F, 0xFC, 0x53, 0xC8, 0xE7, 0xF2,
        0x47, 0x4B, 0x0C, 0xB2, 0xDF, 0xF2, 0xDD, 0xC8, 0xA5, 0xC6, 0x01, 0xC8, 0x4A, 0x70,
        0x19, 0x81, 0x19, 0x9B, 0xCC, 0xF7, 0x41, 0x12, 0xA6, 0xEC, 0x06, 0x2C, 0x4F, 0xEB,
        0x60, 0x1A, 0x02, 0x8A, 0xF0, 0x10, 0x32, 0xAD, 0xB6, 0xBD, 0x15, 0xD4, 0xC2, 0xB9,
        0x55, 0x0A, 0xA8, 0x50, 0xAD, 0x62, 0xCC, 0xC3, 0xA3, 0x66, 0x5D, 0x52, 0x12, 0xB1,
        0x2E, 0x0F, 0xD5, 0xC5, 0x32, 0x6A, 0x1E, 0x5E, 0xB1, 0xF1, 0x0D, 0x55, 0x7D, 0x94,
        0x60, 0x5E, 0x8E, 0x3F, 0x35, 0x6E, 0x08, 0xFF, 0x7F, 0xD8, 0x84, 0xED, 0x3C, 0x42,
        0x05, 0x46, 0x35, 0x94, 0xC9, 0xAF, 0x2F, 0x39, 0xE4, 0xB1, 0x27, 0x46, 0x95, 0x23,
        0x4B, 0x54, 0xEE, 0xCE, 0xD9, 0x3F, 0x46, 0x0E, 0xDF, 0x1A, 0x13, 0xC2, 0xCB, 0x4B,
        0x17, 0xD3, 0x22, 0xF6, 0xF7, 0x9F, 0xE1, 0x6F, 0x03, 0x57, 0xC1, 0xC4, 0x73, 0x98,
        0x63, 0xE7, 0x96, 0x79, 0x1F, 0x86, 0x47, 0xFA, 0xBF, 0x73, 0x0A, 0xB0, 0x0E, 0x0D,
        0xA5, 0x09, 0x70, 0x6D, 0x94, 0x57, 0x17, 0x40, 0xF6, 0x1F, 0x7B, 0xAF, 0x36, 0x6D,
        0x27, 0x74, 0xC9, 0xB5, 0xB8, 0xC6, 0x1D, 0xD6, 0xBE, 0x98, 0x19, 0xA6, 0x02, 0x8B,
        0x26, 0x4B, 0xB2, 0xE4, 0xAE, 0xA5, 0x4B, 0x56, 0xD4, 0xEC, 0xAB, 0x5B, 0x52, 0x8C,
        0xE0, 0xC0, 0xC0, 0xCC, 0xDB, 0x73, 0x02, 0x33, 0x52, 0xCB, 0x00, 0x44, 0x5B, 0xAB,
        0x6F, 0x74, 0x67, 0xB4, 0x64, 0x4D, 0x43, 0x61, 0xC4, 0x64, 0xFA, 0xC6, 0xB5, 0xB1,
        0x37, 0xD3, 0x23, 0x91, 0x02, 0x1B, 0x47, 0x5F, 0xCB, 0x5F, 0x31, 0x77, 0x4F, 0xD8,
        0xEC, 0xAB, 0xDF, 0x65, 0x47, 0x5F, 0x25, 0x57, 0x4C, 0x65, 0x55, 0x9C, 0xB3, 0x31,
        0xF4, 0x1C, 0x0F, 0x49, 0x8B, 0x74, 0xDD, 0x94, 0x1C, 0x34, 0x4C, 0x50, 0xD8, 0xE6,
        0x4F, 0x95, 0x78, 0x71, 0x4A, 0x32, 0x56, 0x1F, 0xAA, 0xCE, 0xAF, 0x78, 0x14, 0x8E,
        0x6D, 0xA4, 0xB5, 0x66, 0x82, 0x69, 0x25, 0x71, 0x4B, 0x17, 0x10, 0x8A, 0xFD, 0xD5,
        0x46, 0x38, 0x5A, 0x3C, 0xD4, 0x54, 0xD5, 0xCA, 0xA1, 0x69, 0x60, 0x91, 0x62, 0x82,
        0xA4, 0x7C, 0x43, 0x15, 0xCE, 0x23, 0x6B, 0xD9, 0xE3, 0x25, 0x5C, 0x60, 0x4E, 0xBD,
        0xC3, 0x97, 0x72, 0xDB, 0x5C, 0xE0, 0xB2, 0x36,
    ];

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
		let seed: [u8; 32] = [
            0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B,
            0x1A, 0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99,
            0x36, 0x73, 0x7F, 0x2D,
        ];

		let test = dil2::Keypair::generate(Some(&seed));
		let keypair = ext_dilithium_from_seed(&seed);
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, TEST_PK);
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