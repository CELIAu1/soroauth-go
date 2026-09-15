//! A modular custom account that authenticates purely through CAP-71 delegated
//! signers.
//!
//! This is TEST FIXTURE CODE. It exists so that soroauth's delegated-signer
//! support can be proven against a real host on testnet, and for nothing else.
//! It is deliberately not a product: there are no policies, no admin functions,
//! no upgradability, and no way to change the signer set after construction.
//! Do not deploy it to mainnet or treat it as a smart-account starting point.
//!
//! The account carries no signature of its own. Its `__check_auth` reads the
//! delegates the client attached to the authorization entry, refuses any it
//! does not recognise, and otherwise forwards the authorization to each of
//! them. That is the CAP-71-01 delegation flow soroauth builds entries for.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Vec,
};

/// How long to keep the instance alive, in ledgers. Roughly 30 days at 5
/// seconds per ledger, which comfortably outlives a test run.
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccountError {
    /// A delegate was attached that this account has not registered.
    UnknownDelegate = 1,
    /// No delegates were attached at all.
    NoDelegates = 2,
}

#[contracttype]
pub enum DataKey {
    Signers,
}

#[contract]
pub struct ModularAccount;

#[contractimpl]
impl ModularAccount {
    /// Registers the addresses allowed to authenticate for this account.
    ///
    /// The set is fixed at construction. This is a test fixture, so there is
    /// deliberately no way to change it afterwards.
    pub fn __constructor(env: Env, signers: Vec<Address>) {
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Returns the registered signers, so a test can confirm what was stored.
    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env))
    }
}

#[contractimpl]
impl CustomAccountInterface for ModularAccount {
    /// The account verifies no signature of its own, so there is nothing to
    /// check. Authentication comes entirely from its delegates.
    type Signature = ();
    type Error = AccountError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        // The delegates the client attached to this entry. The host does not
        // sanitise these; checking that they belong to the account is this
        // contract's job.
        let delegates = env.custom_account().get_delegated_signers();

        // Fail closed. With no delegates there is nothing authenticating this
        // account, and returning Ok here would authorize the invocation on the
        // strength of nobody at all.
        if delegates.is_empty() {
            return Err(AccountError::NoDelegates);
        }

        let registered = Self::signers(env.clone());

        // Every delegate is validated before any authorization is forwarded,
        // so an unrecognised delegate is reported as UnknownDelegate rather
        // than after a partial delegation has already happened.
        for delegate in delegates.iter() {
            if !registered.contains(&delegate) {
                return Err(AccountError::UnknownDelegate);
            }
        }

        for delegate in delegates.iter() {
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
