// Anchor staking program with mixed vulnerabilities
// Expected: CRITICAL + HIGH findings, is_anchor = true

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};
use solana_program::program::invoke;

declare_id!("StakingVulnProgram1111111111111111111111111");

#[program]
pub mod staking_program {
    use super::*;

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        // VULNERABILITY: Integer overflow
        pool.total_staked = pool.total_staked + amount;

        // VULNERABILITY: CPI before state update — reentrancy risk
        invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.user_token.key,
                ctx.accounts.pool_token.key,
                ctx.accounts.user.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.user_token.to_account_info(),
                ctx.accounts.pool_token.to_account_info(),
                ctx.accounts.user.to_account_info(),
            ],
        )?;

        Ok(())
    }

    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        // VULNERABILITY: Integer underflow
        pool.total_staked = pool.total_staked - amount;

        Ok(())
    }

    // VULNERABILITY: Insecure reward calculation using slot
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let clock = Clock::get()?;
        let reward = clock.slot as u64 * 100;
        msg!("Reward: {}", reward);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub user: AccountInfo<'info>,           // Missing Signer check
    pub token_program: AccountInfo<'info>,  // Should be Program<Token>
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub pool: Account<'info, StakingPool>,
    pub user: Signer<'info>,
}

#[account]
pub struct StakingPool {
    pub authority: Pubkey,
    pub total_staked: u64,
    pub reward_rate: u64,
}
