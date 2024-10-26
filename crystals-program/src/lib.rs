use anchor_lang::prelude::*;
use instructions::*;

pub mod errors;
pub mod instructions;
pub mod states;

declare_id!("11111111111111111111111111111111");

#[cfg(target_os = "solana")]
#[global_allocator]
static ALLOC: smalloc::Smalloc<
    { anchor_lang::solana_program::entrypoint::HEAP_START_ADDRESS as usize },
    { anchor_lang::solana_program::entrypoint::HEAP_LENGTH as usize },
    16,
    1024,
> = smalloc::Smalloc::new();


#[program]
pub mod crystals {
    use super::*;

    pub fn init_vault_accounts(
        ctx: Context<InitVaultAccounts>, args: VerifyArgs
    ) -> Result<()> {
        instructions::init_vault_accounts(ctx, args)
    }
    
}

