use cvlr::{cvlr_assert, cvlr_assume, cvlr_satisfy, nondet, rule};
use tempo_revm::{
    certora::{
        Address, EmptyDB, KeyAuthorization, KeyAuthorizationTokenLimit, MockKeychainSignature,
        MockPrimitiveSignature, SignatureType, SignedKeyAuthorization, TempoBatchCallEnv,
        TempoContext, TempoEvm, TempoPrecompileError, TempoSignature, TempoTxEnv,
        Vec as CertoraVec, U256,
    },
    handler::TempoEvmHandler,
};

fn nondet_address() -> Address {
    Address::new(nondet())
}

fn nondet_balance() -> U256 {
    let balance: u64 = nondet(); // fix later
    U256::from(balance)
}

fn nondet_expiry() -> Option<u64> {
    if nondet::<bool>() {
        Some(nondet())
    } else {
        None
    }
}

fn nondet_limits() -> Option<CertoraVec<KeyAuthorizationTokenLimit>> {
    if !nondet::<bool>() {
        return None;
    }

    let mut limits = CertoraVec::default();
    if nondet::<bool>() {
        limits.push(KeyAuthorizationTokenLimit {
            token: nondet_address(),
            limit: nondet_balance(),
        });
    }
    Some(limits)
}

fn nondet_signature_type() -> SignatureType {
    match nondet::<u8>() {
        0 => SignatureType::Secp256k1,
        1 => SignatureType::P256,
        _ => SignatureType::WebAuthn,
    }
}

fn prepare_evm_and_handler(
    root_account: Address,
    fee_token: Address,
    fee_payer: Address,
    expected_chain_id: u64,
    mock_balance: U256,
    aa_env: TempoBatchCallEnv,
) -> (TempoEvm<EmptyDB, ()>, TempoEvmHandler<EmptyDB, ()>) {
    let tx = TempoTxEnv {
        caller: root_account,
        fee_token: Some(fee_token),
        fee_payer: Some(Some(fee_payer)),
        tempo_tx_env: Some(aa_env),
        ..Default::default()
    };

    let ctx = TempoContext::<EmptyDB> {
        tx,
        ..Default::default()
    };
    let mut evm = TempoEvm::new(ctx, ());
    evm.inner.ctx.cfg.chain_id = expected_chain_id;
    evm.inner
        .ctx
        .journaled_state
        .set_token_balance(fee_token, fee_payer, mock_balance);
    let mut handler = TempoEvmHandler::<EmptyDB, ()>::new();

    handler.load_fee_fields(&mut evm).unwrap();
    (evm, handler)
}

#[rule]
pub fn sunbeam_key_auth_not_signed_by_root() {
    let root_account = nondet_address();
    let auth_signer = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();

    cvlr_assume!(auth_signer != root_account);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(auth_signer),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_key_auth_not_signed_by_root_sanity() {
    let root_account = nondet_address();
    let auth_signer = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();

    cvlr_assume!(auth_signer != root_account);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(auth_signer),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[rule]
pub fn sunbeam_key_auth_signature_recovery_fails() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Err(()), // by construction, we make this Err
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_key_auth_signature_recovery_fails_sanity() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Err(()),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[rule]
pub fn sunbeam_key_auth_chain_id_mismatch() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let wrong_chain_id: u64 = nondet();

    // Pre-T1C, chain_id == 0 is a wildcard and should be handled by a separate rule.
    cvlr_assume!(wrong_chain_id != 0);
    cvlr_assume!(wrong_chain_id != expected_chain_id);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: wrong_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_key_auth_chain_id_mismatch_sanity() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let wrong_chain_id: u64 = nondet();

    // Pre-T1C, chain_id == 0 is a wildcard and should be handled by a separate rule.
    cvlr_assume!(wrong_chain_id != 0);
    cvlr_assume!(wrong_chain_id != expected_chain_id);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: wrong_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[rule]
pub fn sunbeam_access_key_cannot_authorize_other_keys() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let access_key_addr = nondet_address();
    let authorized_key_id = nondet_address();

    cvlr_assume!(access_key_addr != authorized_key_id);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: authorized_key_id,
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Keychain(MockKeychainSignature {
            user_address: root_account,
            access_key_addr: Ok(access_key_addr),
            signature: MockPrimitiveSignature { signature_type },
        }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_access_key_cannot_authorize_other_keys_sanity() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let access_key_addr = nondet_address();
    let authorized_key_id = nondet_address();

    cvlr_assume!(access_key_addr != authorized_key_id);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: authorized_key_id,
            expiry: nondet_expiry(),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Keychain(MockKeychainSignature {
            user_address: root_account,
            access_key_addr: Ok(access_key_addr),
            signature: MockPrimitiveSignature { signature_type },
        }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[rule]
pub fn sunbeam_access_key_expiry_in_past() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let expiry: u64 = nondet();
    let current_timestamp: u64 = nondet();

    cvlr_assume!(expiry <= current_timestamp);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: Some(expiry),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    evm.inner.ctx.block.timestamp = U256::from(current_timestamp);
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_access_key_expiry_in_past_sanity() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let expiry: u64 = nondet();
    let current_timestamp: u64 = nondet();

    cvlr_assume!(expiry <= current_timestamp);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: expected_chain_id,
            key_type: signature_type,
            key_id: nondet_address(),
            expiry: Some(expiry),
            limits: nondet_limits(),
        },
        signature: MockPrimitiveSignature { signature_type },
        recovered_signer: Ok(root_account),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(MockPrimitiveSignature { signature_type }),
        key_authorization: Some(key_auth),
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    evm.inner.ctx.block.timestamp = U256::from(current_timestamp);
    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[rule]
pub fn sunbeam_keychain_validation_fails() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let access_key_addr = nondet_address();

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Keychain(MockKeychainSignature {
            user_address: root_account,
            access_key_addr: Ok(access_key_addr),
            signature: MockPrimitiveSignature { signature_type },
        }),
        key_authorization: None,
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    evm.inner
        .ctx
        .journaled_state
        .set_keychain_validation_error(Some(TempoPrecompileError::Fatal(
            "mock keychain validation failure",
        )));

    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}

#[rule]
pub fn sunbeam_keychain_validation_fails_sanity() {
    let root_account = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();
    let expected_chain_id: u64 = nondet();
    let signature_type = nondet_signature_type();
    let access_key_addr = nondet_address();

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Keychain(MockKeychainSignature {
            user_address: root_account,
            access_key_addr: Ok(access_key_addr),
            signature: MockPrimitiveSignature { signature_type },
        }),
        key_authorization: None,
        ..Default::default()
    };

    let (mut evm, handler) = prepare_evm_and_handler(
        root_account,
        fee_token,
        fee_payer,
        expected_chain_id,
        nondet_balance(),
        aa_env,
    );
    evm.inner
        .ctx
        .journaled_state
        .set_keychain_validation_error(Some(TempoPrecompileError::Fatal(
            "mock keychain validation failure",
        )));

    let _result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_satisfy!(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_revm::certora::{
        get_token_balance, BlockEnv, CfgEnv, JournaledState, StorageCtx, TempoInvalidTransaction,
        TempoPrecompileError, U256,
    };

    #[test]
    fn signed_key_authorization_uses_configured_signer_and_chain_id() {
        let signer = Address::new(7);
        let key_auth = SignedKeyAuthorization {
            authorization: KeyAuthorization {
                chain_id: 1,
                key_type: SignatureType::Secp256k1,
                key_id: Address::new(11),
                expiry: None,
                limits: None,
            },
            signature: MockPrimitiveSignature {
                signature_type: SignatureType::Secp256k1,
            },
            recovered_signer: Ok(signer),
        };

        assert_eq!(key_auth.recover_signer(), Ok(signer));
        assert!(key_auth.validate_chain_id(1, false).is_ok());
        assert!(key_auth.validate_chain_id(2, true).is_err());
    }

    #[test]
    fn fee_payer_defaults_to_caller_and_rejects_invalid_signature() {
        let caller = Address::new(3);

        let default_fee_payer = TempoTxEnv {
            caller,
            fee_payer: None,
            ..Default::default()
        };
        assert_eq!(default_fee_payer.fee_payer(), Ok(caller));

        let explicit_fee_payer = TempoTxEnv {
            caller,
            fee_payer: Some(Some(Address::new(9))),
            ..Default::default()
        };
        assert_eq!(explicit_fee_payer.fee_payer(), Ok(Address::new(9)));

        let invalid_fee_payer = TempoTxEnv {
            caller,
            fee_payer: Some(None),
            ..Default::default()
        };
        assert_eq!(
            invalid_fee_payer.fee_payer(),
            Err(TempoInvalidTransaction::InvalidFeePayerSignature)
        );
    }

    #[test]
    fn max_balance_spending_matches_gas_plus_value() {
        let tx = TempoTxEnv {
            gas_limit: 100,
            max_fee_per_gas: 3,
            value: U256::from(4u64),
            ..Default::default()
        };

        assert_eq!(tx.max_balance_spending(), Ok(U256::from(304u64)));
    }

    #[test]
    fn storage_ctx_enter_evm_executes_closure() {
        let mut journal = JournaledState::<EmptyDB>::default();
        let block = BlockEnv::default();
        let cfg = CfgEnv::default();
        let tx = TempoTxEnv::default();

        let result: Result<u64, _> = StorageCtx::enter_evm(&mut journal, &block, &cfg, &tx, || {
            Ok::<u64, TempoPrecompileError>(17)
        });

        assert_eq!(result, Ok(17));
    }

    #[test]
    fn get_token_balance_returns_configured_balance() {
        let mut journal = JournaledState::<EmptyDB>::default();
        journal.set_token_balance(Address::new(1), Address::new(2), U256::from(55u64));

        let balance = get_token_balance(&mut journal, Address::new(1), Address::new(2));

        assert_eq!(balance, Ok(U256::from(55u64)));
        assert_eq!(
            get_token_balance(&mut journal, Address::new(1), Address::new(3)),
            Ok(U256::ZERO)
        );
    }
}
