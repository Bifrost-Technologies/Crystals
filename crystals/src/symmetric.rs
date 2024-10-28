use crate::fips202::*;
use crate::params::{CRHBYTES, SEEDBYTES};

pub type Stream128State = KeccakState;
pub type Stream256State = KeccakState;

pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;
pub const STREAM256_BLOCKBYTES: usize = SHAKE256_RATE;

pub fn _crh(out: &mut [u8], input: &[u8], inbytes: usize) {
  shake256(out, CRHBYTES, input, inbytes)
}

pub fn stream128_init(state: &mut Stream128State, seed: &[u8], nonce: u16) {
  dilithium_shake128_stream_init(state, seed, nonce);

}

pub fn stream128_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream128State,
) {
  shake128_squeezeblocks(out, outblocks as usize, state);
}

pub fn dilithium_shake128_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
) {
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, &t, 2);
  shake128_finalize(state);
}


pub fn stream256_init(state: &mut Stream256State, seed: &[u8], nonce: u16) {
  dilithium_shake256_stream_init(state, seed, nonce);
}

pub fn stream256_squeezeblocks(
  out: &mut [u8],
  outblocks: u64,
  state: &mut Stream256State,
) {
  shake256_squeezeblocks(out, outblocks as usize, state);
}

pub fn dilithium_shake256_stream_init(
  state: &mut KeccakState,
  seed: &[u8],
  nonce: u16,
) {
  let t = [nonce as u8, (nonce >> 8) as u8];
  state.init();
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, &t, 2);
  shake256_finalize(state);
}