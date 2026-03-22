// Medium risk Solana program
// Expected: MEDIUM findings — missing rent exemption, unvalidated data, PDA issues

use anchor_lang::prelude::*;

declare_id!("VulnVaultMed1111111111111111111111111111111");

#[program]
pub mod vuln_vault_medium {
    use super::*;

    pub fn create_escrow(ctx: Context<CreateEscrow>, amount: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.maker = ctx.accounts.maker.key();
        escrow.taker = ctx.accounts.taker.key();
        escrow.amount = amount;

        // VULNERABILITY: Uses block timestamp for time-locked logic
        // sequencer can manipulate this on L2 equivalents
        let clock = Clock::get()?;
        escrow.expiry = clock.unix_timestamp + 86400;

        Ok(())
    }

    pub fn claim_escrow(ctx: Context<ClaimEscrow>) -> Result<()> {
        let escrow = &ctx.accounts.escrow;
        let clock = Clock::get()?;

        // VULNERABILITY: timestamp dependence for critical logic
        require!(
            clock.unix_timestamp >= escrow.expiry,
            EscrowError::NotExpired
        );

        // VULNERABILITY: No verification that taker matches escrow.taker
        // Anyone can claim after expiry
        msg!("Escrow claimed by {}", ctx.accounts.claimer.key());
        Ok(())
    }

    // VULNERABILITY: Close account without zeroing data
    pub fn close_escrow(ctx: Context<CloseEscrow>) -> Result<()> {
        // Just transfers lamports but doesn't zero the data
        // Account can be re-initialized with stale data
        msg!("Closing escrow");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateEscrow<'info> {
    #[account(init, payer = maker, space = 8 + 32 + 32 + 8 + 8)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub maker: Signer<'info>,
    pub taker: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimEscrow<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    pub claimer: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseEscrow<'info> {
    #[account(mut, close = maker)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub maker: Signer<'info>,
}

#[account]
pub struct Escrow {
    pub maker: Pubkey,
    pub taker: Pubkey,
    pub amount: u64,
    pub expiry: i64,
}

#[error_code]
pub enum EscrowError {
    #[msg("Escrow has not expired yet")]
    NotExpired,
}
