use crate::params::*;
use crate::poly::*;

#[derive(Copy, Clone)]
pub struct Polyveck {
  pub vec: [Poly; K],
}

impl Default for Polyveck {
  fn default() -> Self {
    Polyveck {
      vec: [Poly::default(); K],
    }
  }
}

#[derive(Copy, Clone)]
pub struct Polyvecl {
  pub vec: [Poly; L],
}

impl Default for Polyvecl {
  fn default() -> Self {
    Polyvecl {
      vec: [Poly::default(); L],
    }
  }
}

/// Implementation of ExpandA. Generates matrix A with uniformly
/// random coefficients a_{i,j} by performing rejection
/// sampling on the output stream of SHAKE128(rho|j|i)
/// or AES256CTR(rho,j|i).
pub fn polyvec_matrix_expand(mat: &mut [Polyvecl], rho: &[u8]) {
  for i in 0..K {
    for j in 0..L {
      poly_uniform(&mut mat[i].vec[j], rho, ((i << 8) + j) as u16);
    }
  }
}

pub fn polyvec_matrix_pointwise_montgomery(
  t: &mut Polyveck,
  mat: &[Polyvecl],
  v: &Polyvecl,
) {
  for i in 0..K {
    polyvecl_pointwise_acc_montgomery(&mut t.vec[i], &mat[i], v);
  }
}

/// Forward NTT of all polynomials in vector of length L. Output
/// coefficients can be up to 16*Q larger than input coefficients.*
pub fn polyvecl_ntt(v: &mut Polyvecl) {
  for i in 0..L {
    poly_ntt(&mut v.vec[i]);
  }
}

/// Pointwise multiply vectors of polynomials of length L, multiply
/// resulting vector by 2^{-32} and add (accumulate) polynomials
/// in it. Input/output vectors are in NTT domain representation.
/// Input coefficients are assumed to be less than 22*Q. Output
/// coeffcient are less than 2*L*Q.
pub fn polyvecl_pointwise_acc_montgomery(
  w: &mut Poly,
  u: &Polyvecl,
  v: &Polyvecl,
) {
  let mut t = Poly::default();
  poly_pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
  for i in 1..L {
    poly_pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
    poly_add(w, &t);
  }
}

/// Check infinity norm of polynomials in vector of length L.
/// Assumes input coefficients to be standard representatives.
/// Returns 0 if norm of all polynomials is strictly smaller than B and 1
/// otherwise.
pub fn polyvecl_chknorm(v: &Polyvecl, bound: i32) -> u8 {
  for i in 0..L {
    if poly_chknorm(&v.vec[i], bound) > 0 {
      return 1;
    }
  }
  return 0;
}

//*********** Vectors of polynomials of length K ****************************


/// Reduce coefficients of polynomials in vector of length K
/// to representatives in [0,2*Q].
pub fn polyveck_reduce(v: &mut Polyveck) {
  for i in 0..K {
    poly_reduce(&mut v.vec[i]);
  }
}

/// For all coefficients of polynomials in vector of length K
/// add Q if coefficient is negative.
pub fn polyveck_caddq(v: &mut Polyveck) {
  for i in 0..K {
    poly_caddq(&mut v.vec[i]);
  }
}

/// Subtract vectors of polynomials of length K.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn polyveck_sub(w: &mut Polyveck, v: &Polyveck) {
  for i in 0..K {
    poly_sub(&mut w.vec[i], &v.vec[i]);
  }
}

/// Multiply vector of polynomials of Length K by 2^D without modular
/// reduction. Assumes input coefficients to be less than 2^{32-D}.
pub fn polyveck_shiftl(v: &mut Polyveck) {
  for i in 0..K {
    poly_shiftl(&mut v.vec[i]);
  }
}

/// Forward NTT of all polynomials in vector of length K. Output
/// coefficients can be up to 16*Q larger than input coefficients.
pub fn polyveck_ntt(v: &mut Polyveck) {
  for i in 0..K {
    poly_ntt(&mut v.vec[i]);
  }
}

/// Inverse NTT and multiplication by 2^{32} of polynomials
/// in vector of length K. Input coefficients need to be less
/// than 2*Q.
pub fn polyveck_invntt_tomont(v: &mut Polyveck) {
  for i in 0..K {
    poly_invntt_tomont(&mut v.vec[i]);
  }
}

pub fn polyveck_pointwise_poly_montgomery(
  r: &mut Polyveck,
  a: &Poly,
  v: &Polyveck,
) {
  for i in 0..K {
    poly_pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
  }
}



/// Use hint vector to correct the high bits of input vector.
pub fn polyveck_use_hint(w: &mut Polyveck, h: &Polyveck) {
  for i in 0..K {
    poly_use_hint(&mut w.vec[i], &h.vec[i]);
  }
}

pub fn polyveck_pack_w1(r: &mut [u8], w1: &Polyveck) {
  for i in 0..K {
    polyw1_pack(&mut r[i * POLYW1_PACKEDBYTES..], &w1.vec[i]);
  }
}
