// High risk Solana program
// Expected: CRITICAL findings — missing signer, arbitrary CPI, integer overflow

use anchor_lang::prelude::*;
use solana_program::program::invoke;

declare_id!("VulnVaultHigh111111111111111111111111111111");

#[program]
pub mod vuln_vault_high {
    use super::*;

    // VULNERABILITY: Missing signer check — authority is AccountInfo not Signer
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        // VULNERABILITY: integer overflow — raw addition
        vault.balance = vault.balance + amount;
        Ok(())
    }

    // VULNERABILITY: Arbitrary CPI — token_program not validated
    pub fn execute_transfer(ctx: Context<ExecuteTransfer>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // VULNERABILITY: integer overflow — raw subtraction
        vault.balance = vault.balance - amount;

        invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.source.to_account_info(),
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.authority.to_account_info(),
            ],
        )?;

        Ok(())
    }

    // VULNERABILITY: Insecure randomness
    pub fn select_winner(ctx: Context<SelectWinner>, total: u64) -> Result<()> {
        let clock = Clock::get()?;
        let winner = clock.unix_timestamp as u64 % total;
        msg!("Winner: {}", winner);
        Ok(())
    }
}

// VULNERABILITY: unsafe block
unsafe fn dangerous_op(ptr: *mut u64, val: u64) {
    *ptr = val;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,  // Should be Signer<'info>
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteTransfer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub source: AccountInfo<'info>,
    pub destination: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,  // Should be Program<'info, Token>
}

#[derive(Accounts)]
pub struct SelectWinner<'info> {
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
