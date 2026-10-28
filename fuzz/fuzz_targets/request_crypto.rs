#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| xshield_fuzz::request_crypto(data));
