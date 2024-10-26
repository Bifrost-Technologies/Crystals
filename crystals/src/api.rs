use crate::params::SIGNBYTES;
use crate::sign::*;

pub enum SignError {
  Input,
  Verify,
}

/// Verify signature using keypair
///
/// Example:
/// ```
/// # use pqc_dilithium::*;
/// # let keys = Keypair::generate();
/// # let msg = [0u8; 32];
/// # let sig = keys.sign(&msg);
/// let sig_verify = verify(&sig, &msg, &keys.public);
/// assert!(sig_verify.is_ok());
pub fn verify(sig: &[u8], msg: &[u8], public_key: &[u8]) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
      return Err(SignError::Input);
  }

  // Wrapping inputs in Box for heap allocation
  let sig_box = Box::new(sig.to_vec());
  let msg_box = Box::new(msg.to_vec());
  let pk_box = Box::new(public_key.to_vec());

  crypto_sign_verify(&sig_box, &msg_box, &pk_box)
}

