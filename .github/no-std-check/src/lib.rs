//! Builds `ark-vrf` with `secret-split` on targets without `std`. The
//! application selects the `getrandom` backend: `rdrand` on
//! `x86_64-unknown-none`, `js` on `wasm32-unknown-unknown`.
#![no_std]

use ark_vrf::suites::bandersnatch::*;

pub fn public_key(seed: [u8; 32]) -> Public {
    Secret::from_seed(seed).public()
}
