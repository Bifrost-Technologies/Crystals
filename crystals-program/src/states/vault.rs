use anchor_lang::prelude::*;
use crystals::PUBLICKEYBYTES;
use crate::errors::VaultError;

#[account]
pub struct Vault {
    owner_pubkey: Pubkey,
    is_initialized: bool,
    crystal_pubkey: Box<[u8; PUBLICKEYBYTES]>
}

impl Vault {

    // Set to maximum account size to leave expansion room, find what it is
    pub const MAXIMUM_SIZE: usize = 8000;

    pub fn init(&mut self, _owner_pubkey: Pubkey, _crystal_pubkey:  Box<[u8; PUBLICKEYBYTES]>) -> Result<()> {
        require_eq!(self.is_initialized, false, VaultError::AlreadyInitialized);

        self.owner_pubkey = _owner_pubkey;
        self.crystal_pubkey = _crystal_pubkey;
        self.is_initialized = true;

        Ok(())
    }
}