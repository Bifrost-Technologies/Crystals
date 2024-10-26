use crate::fips202::*;
use crate::params::{CRHBYTES, SEEDBYTES};

pub type Stream128State = KeccakState;

pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;

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