use crate::{params::*, poly::*, polyvec::*, SignError};

/// Unpack public key pk = (rho, t1).
pub fn unpack_pk(rho: &mut [u8], t1: &mut Polyveck, pk: &[u8]) {
  rho[..SEEDBYTES].copy_from_slice(&pk[..SEEDBYTES]);
  for i in 0..K {
    polyt1_unpack(&mut t1.vec[i], &pk[SEEDBYTES + i * POLYT1_PACKEDBYTES..])
  }
}

/// Unpack signature sig = (z, h, c).
pub fn unpack_sig(
  c: &mut [u8],
  z: &mut Polyvecl,
  h: &mut Polyveck,
  sig: &[u8],
) -> Result<(), SignError> {
  let mut idx = 0usize;

  c[..SEEDBYTES].copy_from_slice(&sig[..SEEDBYTES]);
  idx += SEEDBYTES;

  for i in 0..L {
    polyz_unpack(&mut z.vec[i], &sig[idx + i * POLYZ_PACKEDBYTES..]);
  }
  idx += L * POLYZ_PACKEDBYTES;

  // Decode h
  let mut k = 0usize;
  for i in 0..K {
    if sig[idx + OMEGA + i] < k as u8 || sig[idx + OMEGA + i] > OMEGA_U8 {
      return Err(SignError::Input);
    }
    for j in k..sig[idx + OMEGA + i] as usize {
      // Coefficients are ordered for strong unforgeability
      if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
        return Err(SignError::Input);
      }
      h.vec[i].coeffs[sig[idx + j] as usize] = 1;
    }
    k = sig[idx + OMEGA + i] as usize;
  }

  // Extra indices are zero for strong unforgeability
  for j in k..OMEGA {
    if sig[idx + j as usize] > 0 {
      return Err(SignError::Input);
    }
  }

  Ok(())
}
