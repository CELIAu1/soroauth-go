//! Unit tests for the modular account fixture.
//!
//! These cover the three things §5.10 asks for: that the constructor stores its
//! signer set, that an entry with no delegates is refused, and that an
//! unregistered delegate is refused.
//!
//! The delegates used here are themselves contract accounts that approve
//! anything. That keeps the tests free of real signatures — a C-address
//! delegate authenticates through its own `__check_auth`, which lets these
//! tests exercise the delegation path without reimplementing ed25519 signing in
//! the test env. Scenario D in e2e_test.go covers G-account delegates with real
//! signatures against the live host.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::Address as _,
    vec, Address, Env, Vec,
};

use crate::{AccountError, ModularAccount, ModularAccountArgs, ModularAccountClient};

/// A delegate that approves everything, so the tests can drive delegation
/// without producing real signatures.
#[contract]
pub struct AlwaysApproves;

#[contractimpl]
impl CustomAccountInterface for AlwaysApproves {
    type Signature = ();
    type Error = AccountError;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        Ok(())
    }
}

/// A contract whose operation requires the account's authorization, so the
/// delegation path is reached the way it is on-chain.
#[contract]
pub struct Protected;

#[contractimpl]
impl Protected {
    pub fn protected(_env: Env, account: Address) {
        account.require_auth();
    }
}

fn register_account(env: &Env, signers: Vec<Address>) -> Address {
    env.register(ModularAccount, ModularAccountArgs::__constructor(&signers))
}

#[test]
fn constructor_stores_the_signer_set() {
    let env = Env::default();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    let account = register_account(&env, vec![&env, first.clone(), second.clone()]);
    let client = ModularAccountClient::new(&env, &account);

    let stored = client.signers();
    assert_eq!(stored.len(), 2);
    assert!(stored.contains(&first));
    assert!(stored.contains(&second));
}

#[test]
fn check_auth_refuses_when_no_delegates_are_attached() {
    let env = Env::default();

    let registered = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, registered]);
    let protected = env.register(Protected, ());

    // A well-formed delegates entry that names nobody. Nothing authenticates
    // the account, so authorizing would be authorizing on the strength of no
    // one at all.
    let entry = delegates_entry(&env, &account, &protected, &[]);
    env.set_auths(&[entry]);

    let client = ProtectedClient::new(&env, &protected);
    let result = client.try_protected(&account);
    assert_auth_refused(result, "an entry with no delegates");
}

#[test]
fn check_auth_refuses_an_unregistered_delegate() {
    let env = Env::default();

    let registered = env.register(AlwaysApproves, ());
    let stranger = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, registered.clone()]);
    let protected = env.register(Protected, ());

    // An entry whose delegate is not in the account's signer set.
    let entry = delegates_entry(&env, &account, &protected, &[stranger.clone()]);
    env.set_auths(&[entry]);

    let client = ProtectedClient::new(&env, &protected);
    let result = client.try_protected(&account);
    assert_auth_refused(result, "an unregistered delegate");
}

#[test]
fn check_auth_accepts_a_registered_delegate() {
    let env = Env::default();

    let registered = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, registered.clone()]);
    let protected = env.register(Protected, ());

    let entry = delegates_entry(&env, &account, &protected, &[registered.clone()]);
    env.set_auths(&[entry]);

    let client = ProtectedClient::new(&env, &protected);
    client.protected(&account);
}

/// Asserts the host refused the invocation because __check_auth rejected it.
///
/// A failing __check_auth surfaces to the caller as (Context, InvalidAction);
/// the account's own error code is not visible from here, so these tests assert
/// the exact outer error rather than merely "something went wrong". Which of
/// AccountError's two codes was returned is proven against the live host by
/// scenario E in e2e_test.go, which reports the raw error.
///
/// The positive test above is the control: it uses the same entry builder and
/// succeeds, so a refusal here cannot be blamed on a malformed entry.
fn assert_auth_refused<T: core::fmt::Debug>(
    result: Result<T, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
    what: &str,
) {
    match result {
        Err(Ok(error)) => {
            let expected = soroban_sdk::Error::from_type_and_code(
                soroban_sdk::xdr::ScErrorType::Context,
                soroban_sdk::xdr::ScErrorCode::InvalidAction,
            );
            assert_eq!(error, expected, "{} failed with an unexpected error", what);
        }
        other => panic!("{} was not refused as expected: {:?}", what, other),
    }
}

/// Builds a delegates-arm authorization entry for `account` covering a call to
/// `protected.protected(account)`, naming zero or more delegates.
fn delegates_entry(
    env: &Env,
    account: &Address,
    protected: &Address,
    delegates: &[Address],
) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
    use soroban_sdk::xdr::{
        InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
        SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
        SorobanDelegateSignature, StringM, VecM, WriteXdr,
    };

    let account_sc: ScAddress = account.try_into().unwrap();
    let protected_sc: ScAddress = protected.try_into().unwrap();
    let account_arg: ScVal = account.try_into().unwrap();

    let mut nodes = std::vec::Vec::new();
    for delegate in delegates {
        let delegate_sc: ScAddress = delegate.try_into().unwrap();
        nodes.push(SorobanDelegateSignature {
            address: delegate_sc,
            signature: ScVal::Void,
            nested_delegates: VecM::default(),
        });
    }
    // CAP-71-01 requires each delegates array to be in ascending address
    // order; sorting by the XDR encoding is what soroauth does too.
    nodes.sort_by_key(|node| node.address.to_xdr(soroban_sdk::xdr::Limits::none()).unwrap());

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account_sc,
                    nonce: 1,
                    signature_expiration_ledger: env.ledger().sequence() + 1000,
                    // The account authenticates purely through its delegates,
                    // which CAP-71-01 permits.
                    signature: ScVal::Void,
                },
                delegates: VecM::try_from(nodes).unwrap(),
            },
        ),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: protected_sc,
                function_name: ScSymbol(StringM::try_from("protected").unwrap()),
                args: VecM::try_from(std::vec![account_arg]).unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    }
}
