use cvlr::{cvlr_assert, cvlr_assume, nondet, rule};
use tempo_revm::{
    certora::{
        Address, EmptyDB, KeyAuthorization, MockPrimitiveSignature, SignatureType,
        SignedKeyAuthorization, TempoBatchCallEnv, TempoContext, TempoEvm, TempoSignature,
        TempoTxEnv,
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
    let handler = TempoEvmHandler::<EmptyDB, ()>::new();

    let result = handler.validate_against_state_and_deduct_caller(&mut evm);
    cvlr_assert!(result.is_err());
}
