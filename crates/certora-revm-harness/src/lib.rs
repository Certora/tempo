use cvlr::{cvlr_assert, cvlr_assume, nondet, rule};
use tempo_revm::{
    certora::{
        Address, EmptyDB, KeyAuthorization, MockPrimitiveSignature, SignatureType,
        SignedKeyAuthorization, TempoBatchCallEnv, TempoContext, TempoEvm, TempoSignature,
        TempoTxEnv, U256,
    },
    handler::TempoEvmHandler,
};

fn nondet_address() -> Address {
    Address::new(nondet())
}

#[rule]
pub fn sunbeam_entry() {
    let root_account = nondet_address();
    let auth_signer = nondet_address();
    let fee_token = nondet_address();
    let fee_payer = nondet_address();

    cvlr_assume!(auth_signer != root_account);

    let key_auth = SignedKeyAuthorization {
        authorization: KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: nondet_address(),
            expiry: None,
            limits: None,
        },
        signature: MockPrimitiveSignature {
            signature_type: SignatureType::Secp256k1,
        },
        recovered_signer: Ok(auth_signer),
    };

    let tx = TempoTxEnv {
        caller: root_account,
        fee_token: Some(fee_token),
        fee_payer: Some(Some(fee_payer)),
        tempo_tx_env: Some(TempoBatchCallEnv {
            signature: TempoSignature::Primitive(MockPrimitiveSignature {
                signature_type: SignatureType::Secp256k1,
            }),
            key_authorization: Some(key_auth),
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = TempoContext::<EmptyDB> {
        tx,
        ..Default::default()
    };
    let mut evm = TempoEvm::new(ctx, ());
    evm.inner
        .ctx
        .journaled_state
        .set_token_balance(fee_token, fee_payer, U256::from(1_000_000u64));
    let mut handler = TempoEvmHandler::<EmptyDB, ()>::new();

    handler.load_fee_fields(&mut evm).unwrap();
    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
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
    fn get_token_balance_returns_large_nonzero_balance() {
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
