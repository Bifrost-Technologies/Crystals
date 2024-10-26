use anchor_lang::prelude::*;
use crate::errors::PlayerError;

#[account]
pub struct Vault {
    owner_pubkey: Pubkey,
    is_initialized: bool,
}

impl Vault {

    // Set to maximum account size to leave expansion room, find what it is
    pub const MAXIMUM_SIZE: usize = 5000;

    pub fn init(&mut self, owner_pubkey: Pubkey) -> Result<()> {
        require_eq!(self.is_initialized, false, PlayerError::AlreadyInitialized);

        self.owner_pubkey = owner_pubkey;

        self.is_initialized = true;

        Ok(())
    }
}