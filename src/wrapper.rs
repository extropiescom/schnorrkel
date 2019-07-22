// -*- mode: rust; -*-
//
// This file is part of schnorrkel for embedded C program.
// Copyright (c) 2019 Chester Lee @extropies.com
//
// Authors:
// - Chester Lee <chester@extropies.com>

use alloc::boxed::Box;
use core::panic::PanicInfo;
use core::slice;

use super::*;
//use keys::*; // {MiniSecretKey,SecretKey,PublicKey,Keypair}; + *_LENGTH
//use context::{signing_context}; // SigningContext,SigningTranscript
//use sign::{Signature,SIGNATURE_LENGTH};
//use errors::{SignatureError,SignatureResult};

/// Must have for no std on embedded
///
/// ```
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
	loop {}
}

/// Must have for no std on embedded
///
/// ```
#[alloc_error_handler]
fn foo(_: core::alloc::Layout) -> ! {
	loop {}
}

const PUB_KEY_LEN: usize = 32;
const PRI_KEY_LEN: usize = 64;
const SIGN_LEN: usize = 64;
const BUFFER_LEN: usize = 96;

const STATUS_OK: u32 = 0;
const STATUS_NOK: u32 = 1;
const ERR_KEYPAIR: u32 = 2;
const ERR_PRIKEY: u32 = 3;
const ERR_SIGBYTE: u32 = 4;


 
#[repr(C)]
pub struct sr_data {
	status: u32,
	len: usize,
	data: [u8; 96],
}

#[inline]
pub fn heap_start() -> *mut u32 {
    extern "C" {
        static mut __sheap: u32;
    }

    unsafe { &mut __sheap }
}
 
/// Alloc memory for sr lib
///
/// ```
#[no_mangle]
pub unsafe extern "C" fn sr_init() {
	let start: usize = heap_start() as usize;
	let size: usize = 1024; // in bytes
	ALLOCATOR.init(start, size);
}

/// Free memory used, keypair ptr and signature ptr should be free
///
/// # Inputs
///
/// * `b` ptr return by Box.
/// ```
#[no_mangle]
pub unsafe extern "C" fn sr_free(b: *mut u8) {
	let u = Box::from_raw(b);
	drop(u);
}

/// Sign message by keypairs
///
/// # Inputs
///
/// * `messages` plain text message.
/// * `keypair` is derived from seed
/// * 'random' is give by C code
///
/// # Returns
///
/// * A `*u8` ptr tp sr_data struct` value data is the signature len = 64
///
/// ```
#[no_mangle]
pub unsafe extern "C" fn sr_sign(
	message: *const u8,
	len: usize,
	random: *const u8,
	keypair: *const u8,
) -> *mut u8 {
	let context = signing_context(b"good");
	let mut sr_data = sr_data {
		status: STATUS_NOK,
		len: 0,
		data: [0u8;BUFFER_LEN],
	};
	let keypair =
		match Keypair::from_bytes(slice::from_raw_parts(keypair, PUB_KEY_LEN + PRI_KEY_LEN)) {
			Ok(pair) => pair,
			Err(_) => {
				sr_data.status = ERR_KEYPAIR;
				return Box::into_raw(Box::new(sr_data)) as *mut u8;
			}
		};

	let message_bytes: &[u8] = slice::from_raw_parts(message, len);
	let trng_bytes: &[u8] = slice::from_raw_parts(random, PUB_KEY_LEN);

	let signature: Signature = keypair.sign_trng(context.bytes(message_bytes),&trng_bytes);
	let signature_bytes = signature.to_bytes();

	let mut i = 0;
	while i < SIGN_LEN {
		sr_data.data[i] = signature_bytes[i];
		i = i + 1;
	}

	sr_data.status = STATUS_OK;
	sr_data.len = SIGN_LEN;

	Box::into_raw(Box::new(sr_data)) as *mut u8
}
/// get public key from private key
///
/// # Inputs
///
/// * `secret` bytes of private key
///
/// # Returns
///
/// * A `*u8` ptr tp sr_data struct` value data is the public key len = 32
///
/// ```
#[no_mangle]
pub unsafe extern "C" fn sr_getpub(private_key: *const u8) -> *mut u8 {
	let private_bytes: &[u8] = slice::from_raw_parts(private_key, PRI_KEY_LEN);
	let mut sr_data = sr_data {
		status: STATUS_NOK,
		len: 0,
		data: [0u8;BUFFER_LEN],
	};
	let secret = match SecretKey::from_bytes(&private_bytes[..PRI_KEY_LEN]) {
		Ok(key) => key,
		Err(_) => {
			sr_data.status = ERR_PRIKEY;
			return Box::into_raw(Box::new(sr_data)) as *mut u8;
		}
	};

	let public_from_secret: PublicKey = secret.to_public();
	let public_bytes:[u8;PUB_KEY_LEN] = public_from_secret.to_bytes();
	let mut i = 0;
	while i < PUB_KEY_LEN {
		sr_data.data[i] = public_bytes[i];
		i = i + 1;
	}
	sr_data.status = STATUS_OK;
	sr_data.len = PUB_KEY_LEN;

	Box::into_raw(Box::new(sr_data)) as *mut u8
}

/// Verify signature
///
/// # Inputs
///
/// * `signature` bytes with last one greater the 0x7f.
/// * `keypair` is derived from seed
///
/// # Returns
///
/// * 0 ok; 1 nok
///
/// ```
#[no_mangle]
pub unsafe extern "C" fn sr_verify(
	signature: *const u8,
	message: *const u8,
	len: usize,
	keypair: *const u8,
) -> u32 {
	let context = signing_context(b"good");
	let message_bytes: &[u8] = slice::from_raw_parts(message, len);
	let keypair =
		match Keypair::from_bytes(slice::from_raw_parts(keypair, PUB_KEY_LEN + PRI_KEY_LEN)) {
			Ok(pair) => pair,
			Err(_) => {
				return { ERR_KEYPAIR };
			}
		};

	let signature = match Signature::from_bytes(slice::from_raw_parts(signature, SIGN_LEN)) {
		Ok(signature) => signature,
		Err(_) => {
			return { ERR_SIGBYTE };
		}
	};

	if keypair
		.verify(context.bytes(message_bytes), &signature)
		.is_ok()
	{
		STATUS_OK
	} else {
		STATUS_NOK
	}
}


#[no_mangle]
pub unsafe extern "C" fn sr_keypair_from_seed(
	seed: *const u8
) -> *mut u8 {

	let mut sr_data = sr_data {
		status: STATUS_NOK,
		len: 0,
		data: [0u8;BUFFER_LEN],
	};
	let seed_bytes: &[u8] = slice::from_raw_parts(seed, 64);

	let keypair = MiniSecretKey::from_bytes(seed_bytes).unwrap();
	let keypair_bytes = keypair.to_bytes();

	let mut i = 0;
	while i < KEYPAIR_LENGTH {
		sr_data.data[i] = keypair_bytes[i];
		i = i + 1;
	}
	sr_data.status = STATUS_OK;
	sr_data.len = PUB_KEY_LEN;

	Box::into_raw(Box::new(sr_data)) as *mut u8
}