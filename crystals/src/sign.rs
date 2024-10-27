use crate::{
  fips202::*, packing::*, params::*, poly::*, polyvec::*, SignError,
};

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

pub fn crypto_sign_verify_stage4(
    c: &mut [u8; SEEDBYTES]
) -> Box<Poly> {
    let mut cp = Box::new(Poly::default());
    poly_challenge(&mut *cp, c);
    cp
}

pub fn crypto_sign_verify_stage5(rho: &mut [u8; SEEDBYTES]) -> Box<[Polyvecl; 4]> {
  let mut mat: Box<[Polyvecl; 4]> = Box::new([Polyvecl::default(), Polyvecl::default(), Polyvecl::default(), Polyvecl::default()]);
  polyvec_matrix_expand(&mut *mat, rho);
  mat
}



pub fn crypto_sign_verify_stage6(
    mut cp: Box<Poly>,
    mut mat: Box<[Polyvecl; 4]>,
    mut z: Box<Polyvecl>,
    mut t1: Box<Polyveck>
) -> Result<Box<Polyveck>, SignError> {
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

pub fn crypto_sign_verify(
    sig: &[u8],
    m: &[u8],
    pk: &[u8],
) -> Result<(), SignError> {
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

fn solvematrix(
    mut rho: Box<[u8; 32]>,
    c: &mut Box<[u8; 32]>,
    z: Box<Polyvecl>,
     t1: &Box<Polyveck> // Box for heap allocation
) -> Result<Box<Polyveck>, SignError> {
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
    c: Box<[u8; 32]>
) -> Result<(), SignError> {
    
    let w1 = crypto_sign_verify_stage7(w1_part1, *t1)?; // Correct dereferencing for `t1`

    let buf = Box::new([0u8; K * POLYW1_PACKEDBYTES]);
    let mut c2 = Box::new([0u8; SEEDBYTES]);
    crypto_sign_verify_stage8(buf, w1, &h, mu, &c, &mut *c2)?;
    Ok(())
}
