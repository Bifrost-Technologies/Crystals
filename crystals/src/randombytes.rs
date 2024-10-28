#[cfg(feature = "offchain")]
use rand::prelude::*;

#[cfg(feature = "offchain")]
pub fn randombytes(x: &mut [u8], len: usize) {
  thread_rng().fill_bytes(&mut x[..len])
}