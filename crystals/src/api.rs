use crate::params::{PUBLICKEYBYTES, SIGNBYTES};
use crate::sign::*;

#[cfg(feature = "offchain")]
use SECRETKEYBYTES;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Keypair
{
  public: Box<[u8]>,
  secret: Box<[u8]>,
}

/// Secret key elided
impl std::fmt::Debug for Keypair
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError
{
  Input,
  Verify,
}

pub enum KeypairError
{
  InvalidPublicKey,
  InvalidSecretKey,
}

impl Keypair
{
  /// Explicitly expose secret key
  pub fn expose_secret(&self) -> &[u8]
  {
    &self.secret
  }

  /// Generates a keypair for signing and verification
  #[cfg(feature = "offchain")]
  pub fn generate() -> Keypair
  {
    let mut public = vec![0u8; PUBLICKEYBYTES].into_boxed_slice();
    let mut secret = vec![0u8; SECRETKEYBYTES].into_boxed_slice();
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  /// Restore a keypair
 #[cfg(feature = "offchain")]
  pub fn restore(
    pub_bytes: Vec<u8>,
    sec_bytes: Vec<u8>,
  ) -> Result<Self, KeypairError>
  {
    let public = match pub_bytes.into_boxed_slice().try_into() {
      Ok(bytes) => bytes,
      Err(_) => return Err(KeypairError::InvalidPublicKey),
    };
    let secret = match sec_bytes.into_boxed_slice().try_into() {
      Ok(bytes) => bytes,
      Err(_) => return Err(KeypairError::InvalidSecretKey),
    };
    Ok(Self { public, secret })
  }

  /// Generates a signature for the given message using a keypair
  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES]
  {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret);
    sig
  }
}

/// Verify signature using keypair
pub fn verify(
  sig: &[u8; SIGNBYTES],
  msg: &[u8],
  public_key: &[u8; PUBLICKEYBYTES],
) -> Result<(), SignError>
{
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }

  // Wrapping inputs in Box for heap allocation
  let sig_box = Box::new(sig.to_vec());
  let msg_box = Box::new(msg.to_vec());
  let pk_box = Box::new(public_key.to_vec());

  crypto_sign_verify(&sig_box, &msg_box, &pk_box)
}

/// Open message
pub fn open(
  sig: &[u8; SIGNBYTES],
  msg: &[u8],
  public_key: &[u8; PUBLICKEYBYTES],
) -> Result<(), SignError>
{
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }

  // Wrapping inputs in Box for heap allocation
  let sig_box = Box::new(sig.to_vec());
  let msg_box = Box::new(msg.to_vec());
  let pk_box = Box::new(public_key.to_vec());

  crypto_sign_open(&msg_box, &mut msg_box.len(), &sig_box, &pk_box)
}
