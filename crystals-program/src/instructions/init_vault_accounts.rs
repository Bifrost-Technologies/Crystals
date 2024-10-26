use crate::states::vault::*;
use anchor_lang::prelude::*;
use crystals::*;
extern crate crystals;

pub fn init_vault_accounts(_ctx: Context<InitVaultAccounts>, args: VerifyArgs) -> Result<()> {
    let sig_verify = verify(&args.sig, &args.msg, &args.public_key);
    assert!(sig_verify.is_ok());
    Ok(())
}

#[derive(Accounts)]
pub struct InitVaultAccounts<'info> {
    
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer=owner,
        seeds=["vault".as_bytes(), owner.key().as_ref()],
        bump,
        space=1000,
    )]
    pub vault_account: Account<'info, Vault>,
   
    pub system_program: Program<'info, System>,
}

#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct VerifyArgs {
    pub sig: [u8; SIGNBYTES],
    pub msg: [u8; 32],
    pub public_key: [u8; PUBLICKEYBYTES],
}