use crate::{
  fips202::*, ntt::*, params::*, reduce::*, rounding::*, symmetric::*,
};
#[derive(Copy, Clone)]
pub struct Poly {
  pub coeffs: [i32; N],
}

impl Default for Poly {
  fn default() -> Self {
    Poly { coeffs: [0i32; N] }
  }
}

/// Inplace reduction of all coefficients of polynomial to
/// representative in [0,2*Q].
pub fn poly_reduce(a: &mut Poly) {
  for i in 0..N {
    a.coeffs[i] = reduce32(a.coeffs[i]);
  }
}

/// For all coefficients of in/out polynomial add Q if
/// coefficient is negative.
pub fn poly_caddq(a: &mut Poly) {
  for i in 0..N {
    a.coeffs[i] = caddq(a.coeffs[i]);
  }
}

/// Add polynomials. No modular reduction is performed.
pub fn poly_add(c: &mut Poly, b: &Poly) {
  for i in 0..N {
    c.coeffs[i] = c.coeffs[i] + b.coeffs[i];
  }
}

/// Subtract polynomials. Assumes coefficients of second input
/// polynomial to be less than 2*Q. No modular reduction is
/// performed.
pub fn poly_sub(c: &mut Poly, b: &Poly) {
  for i in 0..N {
    c.coeffs[i] = c.coeffs[i] - b.coeffs[i];
  }
}

/// Multiply polynomial by 2^D without modular reduction. Assumes
/// input coefficients to be less than 2^{32-D}.
pub fn poly_shiftl(a: &mut Poly) {
  for i in 0..N {
    a.coeffs[i] <<= D;
  }
}

/// Inplace forward NTT. Output coefficients can be up to
/// 16*Q larger than input coefficients.
pub fn poly_ntt(a: &mut Poly) {
  ntt(&mut a.coeffs);
}

/// Inplace inverse NTT and multiplication by 2^{32}.
/// Input coefficients need to be less than 2*Q.
/// Output coefficients are less than 2*Q.
pub fn poly_invntt_tomont(a: &mut Poly) {
  invntt_tomont(&mut a.coeffs);
}

/// Pointwise multiplication of polynomials in NTT domain
/// representation and multiplication of resulting polynomial
/// by 2^{-32}. Output coefficients are less than 2*Q if input
/// coefficient are less than 22*Q.
pub fn poly_pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
  for i in 0..N {
    c.coeffs[i] = montgomery_reduce((a.coeffs[i] as i64) * b.coeffs[i] as i64);
  }
}


/// Use hint polynomial to correct the high bits of a polynomial.
///
/// Arguments:   - poly *b: pointer to output polynomial with corrected high bits
/// - const poly *a: pointer to input polynomial
/// - const poly *h: pointer to input hint polynomial
pub fn poly_use_hint(b: &mut Poly, h: &Poly) {
  for i in 0..N {
    b.coeffs[i] = use_hint(b.coeffs[i], h.coeffs[i] as u8);
  }
}

/// Check infinity norm of polynomial against given bound.
/// Assumes input coefficients to be standard representatives.
/// Returns 0 if norm is strictly smaller than B and 1 otherwise.
pub fn poly_chknorm(a: &Poly, b: i32) -> u8 {
  // It is ok to leak which coefficient violates the bound since
  // the probability for each coefficient is independent of secret
  // data but we must not leak the sign of the centralized representative.
  let mut t;

  if b > (Q_I32 - 1) / 8 {
    return 1;
  }
  for i in 0..N {
    // Absolute value of centralized representative
    t = a.coeffs[i] >> 31;
    t = a.coeffs[i] - (t & 2 * a.coeffs[i]);

    if t >= b {
      return 1;
    }
  }
  return 0;
}

/// Sample uniformly random coefficients in [0, Q-1] by
/// performing rejection sampling on array of random bytes.
/// Returns number of sampled coefficients. Can be smaller than len if not enough
/// random bytes were given.
pub fn rej_uniform(a: &mut [i32], len: u32, buf: &[u8], buflen: usize) -> u32 {
  let (mut ctr, mut pos) = (0usize, 0usize);
  let mut t;
  while ctr < len as usize && pos + 3 <= buflen {
    t = buf[pos] as u32;
    pos += 1;
    t |= (buf[pos] as u32) << 8;
    pos += 1;
    t |= (buf[pos] as u32) << 16;
    pos += 1;
    t &= 0x7FFFFF;

    if t < Q as u32 {
      a[ctr] = t as i32;
      ctr += 1;
    }
  }
  ctr as u32
}

const POLY_UNIFORM_NBLOCKS: usize =
  (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;

/// Sample polynomial with uniformly random coefficients
/// in [0, Q-1] by performing rejection sampling using the
/// output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
pub fn poly_uniform(a: &mut Poly, seed: &[u8], nonce: u16) {
  let mut buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
  let mut buf = [0u8; POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2];
  let mut state = Stream128State::default();

  stream128_init(&mut state, seed, nonce);
  stream128_squeezeblocks(&mut buf, POLY_UNIFORM_NBLOCKS as u64, &mut state);

  let mut ctr = rej_uniform(&mut a.coeffs, N_U32, &mut buf, buflen);
  let mut off;
  while ctr < N_U32 {
    off = buflen % 3;
    for i in 0..off {
      buf[i] = buf[buflen - off + i];
    }
    buflen = STREAM128_BLOCKBYTES + off;
    stream128_squeezeblocks(&mut buf[off..], 1, &mut state);
    ctr += rej_uniform(
      &mut a.coeffs[(ctr as usize)..],
      N_U32 - ctr,
      &mut buf,
      buflen,
    );
  }
}

/// Implementation of H. Samples polynomial with TAU nonzero
/// coefficients in {-1,1} using the output stream of
/// SHAKE256(seed).
pub fn poly_challenge(c: &mut Poly, seed: &[u8]) {
  let mut _signs = 0u64;
  let mut buf = [0u8; SHAKE256_RATE];
  let mut state = KeccakState::default(); //shake256_init

  shake256_absorb(&mut state, seed, SEEDBYTES);
  shake256_finalize(&mut state);
  shake256_squeezeblocks(&mut buf, 1, &mut state);

  for i in 0..8 {
    _signs |= (buf[i] as u64) << 8 * i;
  }
  let mut pos: usize = 8;
  // let mut b = buf[pos];
  let mut b;
  c.coeffs.fill(0);
  for i in N - TAU..N {
    loop {
      if pos >= SHAKE256_RATE {
        shake256_squeezeblocks(&mut buf, 1, &mut state);
        pos = 0;
      }
      b = buf[pos] as usize;
      pos += 1;
      if b <= i {
        break;
      }
    }
    c.coeffs[i] = c.coeffs[b as usize];
    c.coeffs[b as usize] = 1i32 - 2 * (_signs & 1) as i32;
    _signs >>= 1;
  }
}

/// Unpack polynomial t1 with 9-bit coefficients.
/// Output coefficients are standard representatives.
pub fn polyt1_unpack(r: &mut Poly, a: &[u8]) {
  for i in 0..N / 4 {
    r.coeffs[4 * i + 0] = (((a[5 * i + 0] >> 0) as u32
      | (a[5 * i + 1] as u32) << 8)
      & 0x3FF) as i32;
    r.coeffs[4 * i + 1] = (((a[5 * i + 1] >> 2) as u32
      | (a[5 * i + 2] as u32) << 6)
      & 0x3FF) as i32;
    r.coeffs[4 * i + 2] = (((a[5 * i + 2] >> 4) as u32
      | (a[5 * i + 3] as u32) << 4)
      & 0x3FF) as i32;
    r.coeffs[4 * i + 3] = (((a[5 * i + 3] >> 6) as u32
      | (a[5 * i + 4] as u32) << 2)
      & 0x3FF) as i32;
  }
}

/// Unpack polynomial z with coefficients
/// in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Output coefficients are standard representatives.
pub fn polyz_unpack(r: &mut Poly, a: &[u8]) {
  if GAMMA1 == (1 << 17) {
    for i in 0..N / 4 {
      r.coeffs[4 * i + 0] = a[9 * i + 0] as i32;
      r.coeffs[4 * i + 0] |= (a[9 * i + 1] as i32) << 8;
      r.coeffs[4 * i + 0] |= (a[9 * i + 2] as i32) << 16;
      r.coeffs[4 * i + 0] &= 0x3FFFF;

      r.coeffs[4 * i + 1] = (a[9 * i + 2] as i32) >> 2;
      r.coeffs[4 * i + 1] |= (a[9 * i + 3] as i32) << 6;
      r.coeffs[4 * i + 1] |= (a[9 * i + 4] as i32) << 14;
      r.coeffs[4 * i + 1] &= 0x3FFFF;

      r.coeffs[4 * i + 2] = (a[9 * i + 4] as i32) >> 4;
      r.coeffs[4 * i + 2] |= (a[9 * i + 5] as i32) << 4;
      r.coeffs[4 * i + 2] |= (a[9 * i + 6] as i32) << 12;
      r.coeffs[4 * i + 2] &= 0x3FFFF;

      r.coeffs[4 * i + 3] = (a[9 * i + 6] as i32) >> 6;
      r.coeffs[4 * i + 3] |= (a[9 * i + 7] as i32) << 2;
      r.coeffs[4 * i + 3] |= (a[9 * i + 8] as i32) << 10;
      r.coeffs[4 * i + 3] &= 0x3FFFF; // TODO: Unnecessary mask?

      r.coeffs[4 * i + 0] = GAMMA1_I32 - r.coeffs[4 * i + 0];
      r.coeffs[4 * i + 1] = GAMMA1_I32 - r.coeffs[4 * i + 1];
      r.coeffs[4 * i + 2] = GAMMA1_I32 - r.coeffs[4 * i + 2];
      r.coeffs[4 * i + 3] = GAMMA1_I32 - r.coeffs[4 * i + 3];
    }
  } else if GAMMA1 == 1 << 19 {
    for i in 0..N / 2 {
      r.coeffs[2 * i + 0] = a[5 * i + 0] as i32;
      r.coeffs[2 * i + 0] |= (a[5 * i + 1] as i32) << 8;
      r.coeffs[2 * i + 0] |= (a[5 * i + 2] as i32) << 16;
      r.coeffs[2 * i + 0] &= 0xFFFFF;

      r.coeffs[2 * i + 1] = (a[5 * i + 2] as i32) >> 4;
      r.coeffs[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
      r.coeffs[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;
      r.coeffs[2 * i + 0] &= 0xFFFFF; // TODO: Unnecessary mask?

      r.coeffs[2 * i + 0] = GAMMA1_I32 - r.coeffs[2 * i + 0];
      r.coeffs[2 * i + 1] = GAMMA1_I32 - r.coeffs[2 * i + 1];
    }
  }
}

/// Bit-pack polynomial w1 with coefficients in [0, 15].
/// Input coefficients are assumed to be standard representatives.
pub fn polyw1_pack(r: &mut [u8], a: &Poly) {
  if GAMMA2 == (Q - 1) / 88 {
    for i in 0..N / 4 {
      r[3 * i + 0] = a.coeffs[4 * i + 0] as u8;
      r[3 * i + 0] |= (a.coeffs[4 * i + 1] << 6) as u8;
      r[3 * i + 1] = (a.coeffs[4 * i + 1] >> 2) as u8;
      r[3 * i + 1] |= (a.coeffs[4 * i + 2] << 4) as u8;
      r[3 * i + 2] = (a.coeffs[4 * i + 2] >> 4) as u8;
      r[3 * i + 2] |= (a.coeffs[4 * i + 3] << 2) as u8;
    }
  } else {
    for i in 0..N / 2 {
      r[i] = (a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4)) as u8;
    }
  }
}
