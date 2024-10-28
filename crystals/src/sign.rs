use crate::{
  fips202::*, packing::*, params::*, poly::*, polyvec::*,
  SignError
};

#[cfg(feature = "offchain")]
 use randombytes::*;

#[cfg(feature = "offchain")]

pub fn crypto_sign_keypair(
  pk: &mut [u8],
  sk: &mut [u8],
  seed: Option<&[u8]>,
) -> u8
{
  let mut init_seed = [0u8; SEEDBYTES];
  match seed {
    Some(x) => init_seed.copy_from_slice(x),
    None => randombytes(&mut init_seed, SEEDBYTES),
  };
  let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
  let mut tr = [0u8; SEEDBYTES];
  let (mut rho, mut rhoprime, mut key) =
    ([0u8; SEEDBYTES], [0u8; CRHBYTES], [0u8; SEEDBYTES]);
  let mut mat = [
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
  ];
  let mut s1 = Polyvecl::default();
  let (mut s2, mut t1, mut t0) = (
    Polyveck::default(),
    Polyveck::default(),
    Polyveck::default(),
  );

  // Get randomness for rho, rhoprime and key
  shake256(
    &mut seedbuf,
    2 * SEEDBYTES + CRHBYTES,
    &init_seed,
    SEEDBYTES,
  );
  rho.copy_from_slice(&seedbuf[..SEEDBYTES]);
  rhoprime.copy_from_slice(&seedbuf[SEEDBYTES..SEEDBYTES + CRHBYTES]);
  key.copy_from_slice(&seedbuf[SEEDBYTES + CRHBYTES..]);

  // Expand matrix
  polyvec_matrix_expand(&mut mat, &rho);
  // Sample short vectors s1 and s2
  polyvecl_uniform_eta(&mut s1, &rhoprime, 0);
  polyveck_uniform_eta(&mut s2, &rhoprime, L_U16);

  // Matrix-vector multiplication
  let mut s1hat = s1.clone();
  polyvecl_ntt(&mut s1hat);

  polyvec_matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
  polyveck_reduce(&mut t1);
  polyveck_invntt_tomont(&mut t1);

  // Add error vector s2
  polyveck_add(&mut t1, &s2);
  // Extract t1 and write public key
  polyveck_caddq(&mut t1);
  polyveck_power2round(&mut t1, &mut t0);
  pack_pk(pk, &rho, &t1);

  // Compute H(rho, t1) and write secret key
  shake256(&mut tr, SEEDBYTES, pk, PUBLICKEYBYTES);
  pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);

  return 0;
}

pub fn crypto_sign_signature(sig: &mut [u8], m: &[u8], sk: &[u8])
{
  // `key` and `mu` are concatenated
  let mut keymu = [0u8; SEEDBYTES + CRHBYTES];

  let mut nonce = 0u16;
  let mut mat = [
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
  ];
  let (mut s1, mut y) = (Polyvecl::default(), Polyvecl::default());
  let (mut s2, mut t0) = (Polyveck::default(), Polyveck::default());
  let (mut w1, mut w0) = (Polyveck::default(), Polyveck::default());
  let mut h = Polyveck::default();
  let mut cp = Poly::default();
  let mut state = KeccakState::default(); //shake256_init()
  let mut rho = [0u8; SEEDBYTES];
  let mut tr = [0u8; SEEDBYTES];
  let mut rhoprime = [0u8; CRHBYTES];

  unpack_sk(
    &mut rho,
    &mut tr,
    &mut keymu[..SEEDBYTES],
    &mut t0,
    &mut s1,
    &mut s2,
    &sk,
  );

  // Compute CRH(tr, msg)
  shake256_absorb(&mut state, &tr, SEEDBYTES);
  shake256_absorb(&mut state, m, m.len());
  shake256_finalize(&mut state);
  shake256_squeeze(&mut keymu[SEEDBYTES..], CRHBYTES, &mut state);

  shake256(&mut rhoprime, CRHBYTES, &keymu, SEEDBYTES + CRHBYTES);
  
  // Expand matrix and transform vectors
  polyvec_matrix_expand(&mut mat, &rho);
  polyvecl_ntt(&mut s1);
  polyveck_ntt(&mut s2);
  polyveck_ntt(&mut t0);

  loop {
    // Sample intermediate vector y
    polyvecl_uniform_gamma1(&mut y, &rhoprime, nonce);
    nonce += 1;

    // Matrix-vector multiplication
    let mut z = y.clone();
    polyvecl_ntt(&mut z);
    polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
    polyveck_reduce(&mut w1);
    polyveck_invntt_tomont(&mut w1);

    // Decompose w and call the random oracle
    polyveck_caddq(&mut w1);
    polyveck_decompose(&mut w1, &mut w0);
    polyveck_pack_w1(sig, &w1);

    state.init();
    shake256_absorb(&mut state, &keymu[SEEDBYTES..], CRHBYTES);
    shake256_absorb(&mut state, &sig, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&mut state);
    shake256_squeeze(sig, SEEDBYTES, &mut state);
    poly_challenge(&mut cp, sig);
    poly_ntt(&mut cp);

    // Compute z, reject if it reveals secret
    polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
    polyvecl_invntt_tomont(&mut z);
    polyvecl_add(&mut z, &y);
    polyvecl_reduce(&mut z);
    if polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) > 0 {
      continue;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery(&mut h, &cp, &s2);
    polyveck_invntt_tomont(&mut h);
    polyveck_sub(&mut w0, &h);
    polyveck_reduce(&mut w0);
    if polyveck_chknorm(&w0, (GAMMA2 - BETA) as i32) > 0 {
      continue;
    }

    // Compute hints for w1
    polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
    polyveck_invntt_tomont(&mut h);
    polyveck_reduce(&mut h);
    if polyveck_chknorm(&h, GAMMA2_I32) > 0 {
      continue;
    }

    polyveck_add(&mut w0, &h);
    let n = polyveck_make_hint(&mut h, &w0, &w1);
    if n > OMEGA as i32 {
      continue;
    }

    // Write signature
    pack_sig(sig, None, &z, &h);
    return;
  }
}

pub fn crypto_sign_verify_stage1(
  sig: &[u8],
  pk: &[u8],
) -> Result<(Box<[u8; SEEDBYTES]>, Box<Polyveck>), SignError>
{
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  let mut rho = Box::new([0u8; SEEDBYTES]);
  let mut t1 = Box::new(Polyveck::default());

  unpack_pk(&mut *rho, &mut *t1, pk);

  Ok((rho, t1))
}

pub fn crypto_sign_verify_stage2(
  sig: &[u8],
) -> Result<(Box<[u8; SEEDBYTES]>, Box<Polyvecl>, Box<Polyveck>), SignError>
{
  let mut c = Box::new([0u8; SEEDBYTES]);
  let mut z = Box::new(Polyvecl::default());
  let mut h = Box::new(Polyveck::default());

  if let Err(e) = unpack_sig(&mut *c, &mut *z, &mut *h, sig) {
    return Err(e);
  }
  if polyvecl_chknorm(&z, (GAMMA1 - BETA) as i32) > 0 {
    return Err(SignError::Input);
  }

  Ok((c, z, h))
}

pub fn crypto_sign_verify_stage3(pk: &[u8], m: &[u8]) -> Box<[u8; CRHBYTES]>
{
  let mut mu = Box::new([0u8; CRHBYTES]);
  let mut state = Box::new(KeccakState::default());

  shake256(&mut *mu, SEEDBYTES, pk, PUBLICKEYBYTES);
  shake256_absorb(&mut *state, &*mu, SEEDBYTES);
  shake256_absorb(&mut *state, m, m.len());
  shake256_finalize(&mut *state);
  shake256_squeeze(&mut *mu, CRHBYTES, &mut *state);

  mu
}

pub fn crypto_sign_verify_stage4(c: &mut [u8; SEEDBYTES]) -> Box<Poly>
{
  let mut cp = Box::new(Poly::default());
  poly_challenge(&mut *cp, c);
  cp
}

pub fn crypto_sign_verify_stage5(
  rho: &mut [u8; SEEDBYTES],
) -> Box<[Polyvecl; 6]>
{
  let mut mat: Box<[Polyvecl; 6]> = Box::new([
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
    Polyvecl::default(),
  ]);
  polyvec_matrix_expand(&mut *mat, rho);
  mat
}

pub fn crypto_sign_verify_stage6(
  mut cp: Box<Poly>,
  mut mat: Box<[Polyvecl; 6]>,
  mut z: Box<Polyvecl>,
  mut t1: Box<Polyveck>,
) -> Result<Box<Polyveck>, SignError>
{
  let mut w1 = Box::new(Polyveck::default());
  polyvecl_ntt(&mut *z);
  polyvec_matrix_pointwise_montgomery(&mut *w1, &mut *mat, &*z);
  poly_ntt(&mut *cp);
  polyveck_shiftl(&mut *t1);
  polyveck_ntt(&mut *t1);
  let t1_2 = Box::new((*t1).clone()); // Allocate t1_2 on the heap
  polyveck_pointwise_poly_montgomery(&mut *t1, &*cp, &*t1_2);
  Ok(w1)
}

pub fn crypto_sign_verify_stage7(
  mut w1: Box<Polyveck>,
  t1: Polyveck,
) -> Result<Box<Polyveck>, SignError>
{
  polyveck_sub(&mut *w1, &t1);
  polyveck_reduce(&mut *w1);
  polyveck_invntt_tomont(&mut *w1);

  Ok(w1)
}

pub fn crypto_sign_verify_stage8(
  mut buf: Box<[u8; K * POLYW1_PACKEDBYTES]>,
  mut w1: Box<Polyveck>,
  h: &Polyveck,
  mu: Box<[u8; CRHBYTES]>,
  c: &Box<[u8; SEEDBYTES]>,
  c2: &mut [u8; SEEDBYTES],
) -> Result<(), SignError>
{
  polyveck_caddq(&mut *w1);
  polyveck_use_hint(&mut *w1, h);
  polyveck_pack_w1(&mut *buf, &*w1);

  let mut state = Box::new(KeccakState::default());
  state.init();
  shake256_absorb(&mut *state, &*mu, CRHBYTES);
  shake256_absorb(&mut *state, &*buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&mut *state);
  shake256_squeeze(c2, SEEDBYTES, &mut *state);

  if &**c != c2 {
    Err(SignError::Verify)
  } else {
    Ok(())
  }
}

fn solvematrix(
  mut rho: Box<[u8; 32]>,
  c: &mut Box<[u8; 32]>,
  z: Box<Polyvecl>,
  t1: &Box<Polyveck>, // Box for heap allocation
) -> Result<Box<Polyveck>, SignError>
{
  let cp = crypto_sign_verify_stage4(&mut **c); // Correct dereferencing
  let mat = crypto_sign_verify_stage5(&mut *rho); // Correct dereferencing
  let w1_part1 = crypto_sign_verify_stage6(cp, mat, z, t1.clone())?; // Correct dereferencing for `t1`
  Ok(w1_part1)
}

pub fn finalverify(
  w1_part1: Box<Polyveck>,
  t1: Box<Polyveck>,
  h: Box<Polyveck>,
  mu: Box<[u8; 64]>,
  c: Box<[u8; 32]>,
) -> Result<(), SignError>
{
  let w1 = crypto_sign_verify_stage7(w1_part1, *t1)?; // Correct dereferencing for `t1`

  let buf = Box::new([0u8; K * POLYW1_PACKEDBYTES]);
  let mut c2 = Box::new([0u8; SEEDBYTES]);
  crypto_sign_verify_stage8(buf, w1, &h, mu, &c, &mut *c2)?;
  Ok(())
}

pub fn crypto_sign_verify(
  sig: &[u8],
  m: &[u8],
  pk: &[u8],
) -> Result<(), SignError>
{
  // Stage A: Initial Setup and Key Unpacking
  let (rho, t1) = crypto_sign_verify_stage1(sig, pk)?;

  // Stage B: Signature Unpacking and Initial Checks
  let (mut c, z, h) = crypto_sign_verify_stage2(sig)?;

  // Stage C: Compute CRH
  let mu = crypto_sign_verify_stage3(pk, m);

  // Stage D: Matrix Operations
  let w1_part1 = solvematrix(rho, &mut c, z, &t1)?;

  // Stage E: Final Verification
  finalverify(w1_part1, t1, h, mu, c)
}

pub fn crypto_sign_open(msg: &[u8], mlen: &mut usize, sig: &[u8], pk: &[u8]) -> Result<(), SignError> {
    let siglen = sig.len();
    let mut msg_copy = msg.to_vec();  // Create a copy of `msg`
    
    if siglen < SIGNBYTES {
        return goto_badsig(&mut msg_copy, mlen);
    }

    *mlen = siglen - SIGNBYTES;

    if crypto_sign_verify(&sig[..SIGNBYTES], &sig[SIGNBYTES..], pk).is_err() {
        return goto_badsig(&mut msg_copy, mlen);
    } else {
        // All good, copy msg, return 0
        msg_copy[..*mlen].copy_from_slice(&sig[SIGNBYTES..SIGNBYTES + *mlen]);
        return Ok(());
    }
}

fn goto_badsig(msg_copy: &mut [u8], mlen: &mut usize) -> Result<(), SignError> {
    *mlen = 0;
    msg_copy.fill(0);
    Err(SignError::Verify)
}
