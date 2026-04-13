use std::{cell::UnsafeCell, fmt, marker::PhantomData, ops::Deref};

use thiserror::Error;

pub const EXPIRING_NONCE_MAX_EXPIRY_SECS: u64 = 30;
pub const TEMPO_EXPIRING_NONCE_KEY: U256 = U256::ZERO;

#[derive(Debug)]
pub struct Arc<T>(T);

impl<T> Arc<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Clone> Clone for Arc<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for Arc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct OnceLock<T> {
    value: UnsafeCell<Option<T>>,
}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            value: UnsafeCell::new(None),
        }
    }

    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        unsafe {
            let slot = &mut *self.value.get();
            if slot.is_none() {
                *slot = Some(f());
            }
            match &*self.value.get() {
                Some(value) => value,
                None => unreachable!(),
            }
        }
    }
}

unsafe impl<T: Send> Send for OnceLock<T> {}
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}

const CERTORA_VEC_MAX: usize = 8; // hardcoded size

pub struct Vec<T> {
    len: usize,
    items: [Option<T>; CERTORA_VEC_MAX],
}

impl<T> Vec<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, value: T) {
        assert!(self.len < CERTORA_VEC_MAX, "certora Vec capacity exceeded");
        self.items[self.len] = Some(value);
        self.len += 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items[..self.len].iter().filter_map(Option::as_ref)
    }
}

impl<T> Default for Vec<T> {
    fn default() -> Self {
        Self {
            len: 0,
            items: std::array::from_fn(|_| None),
        }
    }
}

impl<T: Clone> Clone for Vec<T> {
    fn clone(&self) -> Self {
        let mut cloned = Self::default();
        for item in self.iter() {
            cloned.push(item.clone());
        }
        cloned
    }
}

impl<T: PartialEq> PartialEq for Vec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<T: Eq> Eq for Vec<T> {}

impl<T: fmt::Debug> fmt::Debug for Vec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T> FromIterator<T> for Vec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut collected = Self::default();
        for item in iter {
            collected.push(item);
        }
        collected
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Address(u64);

impl Address {
    pub const ZERO: Self = Self(0);

    pub fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct B256(u64); // fix this later

impl B256 {
    pub const ZERO: Self = Self(0);

    pub fn new(value: u64) -> Self {
        Self(value)
    }
}

pub trait SaturatingFromU128 {
    fn saturating_from_u128(value: u128) -> Self;
}

impl SaturatingFromU128 for u64 {
    fn saturating_from_u128(value: u128) -> Self {
        value.min(u128::from(u64::MAX)) as u64
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(u128); // fix later

impl U256 {
    pub const ZERO: Self = Self(0);

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    pub fn saturating_to<T: SaturatingFromU128>(self) -> T {
        T::saturating_from_u128(self.0)
    }

    pub fn to<T: SaturatingFromU128>(self) -> T {
        T::saturating_from_u128(self.0)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl core::ops::Mul for U256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_mul(rhs.0))
    }
}

impl core::ops::Sub for U256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    Call(Address),
    Create,
}

impl TxKind {
    pub fn is_call(self) -> bool {
        matches!(self, Self::Call(_))
    }

    pub fn is_create(self) -> bool {
        matches!(self, Self::Create)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    Secp256k1,
    P256,
    WebAuthn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileSignatureType {
    Secp256k1,
    P256,
    WebAuthn,
}

impl From<SignatureType> for PrecompileSignatureType {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::Secp256k1 => Self::Secp256k1,
            SignatureType::P256 => Self::P256,
            SignatureType::WebAuthn => Self::WebAuthn,
        }
    }
}

impl From<SignatureType> for u8 {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::Secp256k1 => 0,
            SignatureType::P256 => 1,
            SignatureType::WebAuthn => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAuthorizationTokenLimit {
    pub token: Address,
    pub limit: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLimit {
    pub token: Address,
    pub amount: U256,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeKeyCall {
    pub keyId: Address,
    pub signatureType: PrecompileSignatureType,
    pub expiry: u64,
    pub enforceLimits: bool,
    pub limits: Vec<TokenLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthorizationChainIdError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthorization {
    pub chain_id: u64,
    pub key_type: SignatureType,
    pub key_id: Address,
    pub expiry: Option<u64>,
    pub limits: Option<Vec<KeyAuthorizationTokenLimit>>,
}

impl KeyAuthorization {
    pub fn validate_chain_id(
        &self,
        expected_chain_id: u64,
        is_t1c: bool,
    ) -> Result<(), KeyAuthorizationChainIdError> {
        if is_t1c {
            if self.chain_id != expected_chain_id {
                return Err(KeyAuthorizationChainIdError);
            }
        } else if self.chain_id != 0 && self.chain_id != expected_chain_id {
            return Err(KeyAuthorizationChainIdError);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyAuthorization {
    pub authorization: KeyAuthorization,
    pub signature: MockPrimitiveSignature,
    pub recovered_signer: Result<Address, ()>,
}

impl SignedKeyAuthorization {
    pub fn recover_signer(&self) -> Result<Address, ()> {
        self.recovered_signer
    }
}

impl core::ops::Deref for SignedKeyAuthorization {
    type Target = KeyAuthorization;

    fn deref(&self) -> &Self::Target {
        &self.authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockPrimitiveSignature {
    pub signature_type: SignatureType,
}

impl MockPrimitiveSignature {
    pub fn signature_type(&self) -> SignatureType {
        self.signature_type
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockKeychainSignature {
    pub user_address: Address,
    pub access_key_addr: Result<Address, ()>,
    pub signature: MockPrimitiveSignature,
}

impl MockKeychainSignature {
    pub fn key_id(&self, _signature_hash: &B256) -> Result<Address, ()> {
        self.access_key_addr
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TempoSignature {
    Primitive(MockPrimitiveSignature),
    Keychain(MockKeychainSignature),
}

impl Default for TempoSignature {
    fn default() -> Self {
        Self::Primitive(MockPrimitiveSignature {
            signature_type: SignatureType::Secp256k1,
        })
    }
}

impl TempoSignature {
    pub fn as_keychain(&self) -> Option<&MockKeychainSignature> {
        match self {
            Self::Keychain(sig) => Some(sig),
            Self::Primitive(_) => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TempoBatchCallEnv {
    pub signature: TempoSignature,
    pub valid_before: Option<u64>,
    pub nonce_key: U256,
    pub key_authorization: Option<SignedKeyAuthorization>,
    pub signature_hash: B256,
    pub tx_hash: B256,
    pub expiring_nonce_hash: Option<B256>,
    pub override_key_id: Option<Address>,
    pub subblock_transaction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempoTxEnv {
    pub caller: Address,
    pub nonce: u64,
    pub kind: TxKind,
    pub gas_limit: u64,
    pub value: U256,
    pub max_fee_per_gas: u128,
    pub fee_token: Option<Address>,
    pub disable_fee_charge: bool,
    pub fee_payer: Option<Option<Address>>,
    pub tempo_tx_env: Option<TempoBatchCallEnv>,
}

impl Default for TempoTxEnv {
    fn default() -> Self {
        Self {
            caller: Address::ZERO,
            nonce: 0,
            kind: TxKind::Call(Address::ZERO),
            gas_limit: 100_000,
            value: U256::ZERO,
            max_fee_per_gas: 0,
            fee_token: None,
            disable_fee_charge: false,
            fee_payer: None,
            tempo_tx_env: None,
        }
    }
}

impl TempoTxEnv {
    pub fn caller(&self) -> Address {
        self.caller
    }

    pub fn fee_payer(&self) -> Result<Address, TempoInvalidTransaction> {
        if let Some(fee_payer) = self.fee_payer {
            fee_payer.ok_or(TempoInvalidTransaction::InvalidFeePayerSignature)
        } else {
            Ok(self.caller)
        }
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn kind(&self) -> TxKind {
        self.kind
    }

    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    pub fn value(&self) -> U256 {
        self.value
    }

    pub fn max_balance_spending(&self) -> Result<U256, TempoInvalidTransaction> {
        let gas_spending = U256::from(self.gas_limit) * U256::from(self.max_fee_per_gas);
        gas_spending
            .checked_add(self.value)
            .ok_or(TempoInvalidTransaction::EthInvalidTransaction(
                InvalidTransaction::OverflowPaymentInTransaction,
            ))
    }

    pub fn is_subblock_transaction(&self) -> bool {
        self.tempo_tx_env
            .as_ref()
            .is_some_and(|aa| aa.subblock_transaction)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasId(usize);

impl GasId {
    pub fn new_account_cost() -> Self {
        Self(0)
    }

    pub fn sstore_set_without_load_cost() -> Self {
        Self(1)
    }

    pub fn warm_storage_read_cost() -> Self {
        Self(2)
    }

    pub fn as_usize(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct GasParams {
    values: Arc<[u64; 256]>,
}

impl Default for GasParams {
    fn default() -> Self {
        Self::new(Arc::new([0; 256]))
    }
}

impl GasParams {
    pub fn new(values: Arc<[u64; 256]>) -> Self {
        Self { values }
    }

    pub fn get(&self, id: GasId) -> u64 {
        self.values[id.as_usize()]
    }

    pub fn warm_storage_read_cost(&self) -> u64 {
        self.get(GasId::warm_storage_read_cost())
    }

    pub fn cold_storage_additional_cost(&self) -> u64 {
        0
    }
}

/// Ordered mock of the Tempo hardfork sequence.
///
/// Variants are ordered from oldest to newest; `PartialOrd`/`Ord` derive uses
/// declaration order, so `T1B >= T1` holds exactly as in the real `TempoHardfork`.
/// This means activation checks like `is_t1b()` correctly imply `is_t1()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MockHardfork {
    /// Pre-hardfork baseline (no Tempo features active).
    Genesis,
    /// T0 hardfork (default — matches `TempoHardfork` default).
    #[default]
    T0,
    /// T1 hardfork — expiring nonce transactions.
    T1,
    /// T1.A hardfork — removes EIP-7825 per-transaction gas limit.
    T1A,
    /// T1.B hardfork.
    T1B,
    /// T1.C hardfork — chain-id wildcard removed from key authorizations.
    T1C,
    /// T2 hardfork — compound transfer policies.
    T2,
}

impl MockHardfork {
    pub fn is_t1(self) -> bool {
        self >= Self::T1
    }

    pub fn is_t1b(self) -> bool {
        self >= Self::T1B
    }

    pub fn is_t1c(self) -> bool {
        self >= Self::T1C
    }

    pub fn is_t2(self) -> bool {
        self >= Self::T2
    }
}


#[derive(Debug, Clone)]
pub struct CfgEnv {
    pub spec: MockHardfork,
    pub disable_fee_charge: bool,
    pub chain_id: u64,
    pub gas_params: GasParams,
    pub nonce_check_disabled: bool,
    pub eip3607_disabled: bool,
}

impl Default for CfgEnv {
    fn default() -> Self {
        Self {
            spec: MockHardfork::default(),
            disable_fee_charge: false,
            chain_id: 1,
            gas_params: GasParams::default(),
            nonce_check_disabled: false,
            eip3607_disabled: false,
        }
    }
}

impl CfgEnv {
    pub fn spec(&self) -> MockHardfork {
        self.spec
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn gas_params(&self) -> &GasParams {
        &self.gas_params
    }

    pub fn is_nonce_check_disabled(&self) -> bool {
        self.nonce_check_disabled
    }

    pub fn is_eip3607_disabled(&self) -> bool {
        self.eip3607_disabled
    }
}

#[derive(Debug, Clone)]
pub struct BlockEnv {
    pub timestamp: U256,
    pub beneficiary: Address,
}

impl Default for BlockEnv {
    fn default() -> Self {
        Self {
            timestamp: U256::ZERO,
            beneficiary: Address::ZERO,
        }
    }
}

impl BlockEnv {
    pub fn timestamp(&self) -> U256 {
        self.timestamp
    }

    pub fn beneficiary(&self) -> Address {
        self.beneficiary
    }
}

#[derive(Debug, Clone)]
pub struct AccountInfo;

#[derive(Debug, Clone)]
pub struct Account {
    pub info: AccountInfo,
}

#[derive(Debug, Clone)]
pub struct CallerAccount {
    pub nonce: u64,
    pub info: AccountInfo,
}

impl CallerAccount {
    pub fn account(&self) -> Account {
        Account {
            info: self.info.clone(),
        }
    }

    pub fn touch(&mut self) {}

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn bump_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }
}

#[derive(Debug, Clone)]
pub struct LoadedAccount {
    pub data: CallerAccount,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checkpoint;

#[derive(Debug, Clone)]
pub struct JournaledState<DB: Database> {
    pub caller_account: CallerAccount,
    /// Configurable mock balance entry used by `get_token_balance`.
    pub mock_balance_token: Address,
    /// Configurable mock balance entry used by `get_token_balance`.
    pub mock_balance_owner: Address,
    /// Configurable mock balance entry used by `get_token_balance`.
    pub mock_token_balance: U256,
    /// Authorized (user, key_id) pair checked by `validate_keychain_authorization`.
    /// Defaults to (ZERO, ZERO) — no key is authorized.
    pub mock_authorized_user: Address,
    pub mock_authorized_key_id: Address,
    _phantom: PhantomData<DB>,
}

impl<DB: Database> Default for JournaledState<DB> {
    fn default() -> Self {
        Self {
            caller_account: CallerAccount {
                nonce: 0,
                info: AccountInfo,
            },
            mock_balance_token: Address::ZERO,
            mock_balance_owner: Address::ZERO,
            mock_token_balance: U256::ZERO,
            mock_authorized_user: Address::ZERO,
            mock_authorized_key_id: Address::ZERO,
            _phantom: PhantomData,
        }
    }
}

impl<DB: Database> JournaledState<DB> {
    /// Sets the single `(token, owner) -> balance` entry used by the certora model.
    pub fn set_token_balance(&mut self, token: Address, owner: Address, balance: U256) {
        self.mock_balance_token = token;
        self.mock_balance_owner = owner;
        self.mock_token_balance = balance;
    }

    /// Sets the authorized (user, key_id) pair checked by `validate_keychain_authorization`.
    pub fn set_authorized_key_pair(&mut self, user: Address, key_id: Address) {
        self.mock_authorized_user = user;
        self.mock_authorized_key_id = key_id;
    }

    pub fn get_fee_token(
        &mut self,
        tx: &TempoTxEnv,
        _fee_payer: Address,
        _spec: MockHardfork,
    ) -> Result<Address, TempoPrecompileError> {
        Ok(tx.fee_token.unwrap_or(Address::ZERO))
    }

    pub fn is_tip20_usd(
        &mut self,
        _spec: MockHardfork,
        _fee_token: Address,
    ) -> Result<bool, TempoPrecompileError> {
        Ok(cvlr::nondet())
    }

    pub fn load_account_with_code_mut(
        &mut self,
        _address: Address,
    ) -> Result<LoadedAccount, EVMError<DB::Error, TempoInvalidTransaction>> {
        Ok(LoadedAccount {
            data: self.caller_account.clone(),
        })
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint
    }

    pub fn checkpoint_revert(&mut self, _checkpoint: Checkpoint) {}

    pub fn checkpoint_commit(&mut self) {}
}

#[derive(Debug, Clone)]
pub struct TempoContext<DB: Database> {
    pub block: BlockEnv,
    pub tx: TempoTxEnv,
    pub cfg: CfgEnv,
    pub journaled_state: JournaledState<DB>,
}

impl<DB: Database> Default for TempoContext<DB> {
    fn default() -> Self {
        Self {
            block: BlockEnv::default(),
            tx: TempoTxEnv::default(),
            cfg: CfgEnv::default(),
            journaled_state: JournaledState::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvmInner<DB: Database> {
    pub ctx: TempoContext<DB>,
}

#[derive(Debug, Clone)]
pub struct TempoEvm<DB: Database, I> {
    pub inner: EvmInner<DB>,
    pub initial_gas: u64,
    pub collected_fee: U256,
    pub inspector: I,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        Self {
            inner: EvmInner { ctx },
            initial_gas: 0,
            collected_fee: U256::ZERO,
            inspector,
        }
    }

    pub fn ctx_mut(&mut self) -> &mut TempoContext<DB> {
        &mut self.inner.ctx
    }
}

pub trait Database {
    type Error;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyDB;

impl Database for EmptyDB {
    type Error = ();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidTransaction {
    NonceTooHigh { tx: u64, state: u64 },
    NonceTooLow { tx: u64, state: u64 },
    OverflowPaymentInTransaction,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TempoInvalidTransaction {
    #[error("invalid fee payer signature")]
    InvalidFeePayerSignature,
    #[error("invalid fee token")]
    InvalidFeeToken(Address),
    #[error("insufficient intrinsic gas")]
    InsufficientGasForIntrinsicCost { gas_limit: u64, intrinsic_gas: u64 },
    #[error("expiring nonce missing tx env")]
    ExpiringNonceMissingTxEnv,
    #[error("expiring nonce requires nonce 0")]
    ExpiringNonceNonceNotZero,
    #[error("expiring nonce missing valid_before")]
    ExpiringNonceMissingValidBefore,
    #[error("nonce manager error: {0}")]
    NonceManagerError(&'static str),
    #[error("access key recovery failed")]
    AccessKeyRecoveryFailed,
    #[error("access key cannot authorize other keys")]
    AccessKeyCannotAuthorizeOtherKeys,
    #[error("key authorization signature recovery failed")]
    KeyAuthorizationSignatureRecoveryFailed,
    #[error("key authorization not signed by root")]
    KeyAuthorizationNotSignedByRoot { expected: Address, actual: Address },
    #[error("access key expiry in past")]
    AccessKeyExpiryInPast { expiry: u64, current_timestamp: u64 },
    #[error("keychain precompile error: {reason}")]
    KeychainPrecompileError { reason: &'static str },
    #[error("keychain user address mismatch")]
    KeychainUserAddressMismatch {
        user_address: Address,
        caller: Address,
    },
    #[error("keychain validation failed: {reason}")]
    KeychainValidationFailed { reason: &'static str },
    #[error("invalid chain id")]
    InvalidChainId,
    #[error("upstream invalid transaction")]
    EthInvalidTransaction(InvalidTransaction),
}

impl From<KeyAuthorizationChainIdError> for TempoInvalidTransaction {
    fn from(_: KeyAuthorizationChainIdError) -> Self {
        Self::InvalidChainId
    }
}

impl From<InvalidTransaction> for TempoInvalidTransaction {
    fn from(value: InvalidTransaction) -> Self {
        Self::EthInvalidTransaction(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeePaymentError {
    InsufficientAmmLiquidity { fee: U256 },
    InsufficientFeeTokenBalance { fee: U256, balance: U256 },
    Other(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TempoHaltReason {
    Validation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EVMError<DBError, TxError> {
    Custom(&'static str),
    Database(DBError),
    Transaction(TxError),
}

impl<DBError, TxError> From<TxError> for EVMError<DBError, TxError> {
    fn from(value: TxError) -> Self {
        Self::Transaction(value)
    }
}

impl<DBError> From<InvalidTransaction> for EVMError<DBError, TempoInvalidTransaction> {
    fn from(value: InvalidTransaction) -> Self {
        Self::Transaction(value.into())
    }
}

impl<DBError> From<FeePaymentError> for EVMError<DBError, TempoInvalidTransaction> {
    fn from(value: FeePaymentError) -> Self {
        let _ = value;
        Self::Custom("fee payment error")
    }
}

pub struct StorageCtx;

impl StorageCtx {
    pub fn enter_evm<J, B, C, T, F, R, E>(
        _journal: &mut J,
        _block: &B,
        _cfg: &C,
        _tx: &T,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce() -> Result<R, E>,
    {
        f()
    }

    pub fn enter<P, F, R, E>(_provider: &mut P, f: F) -> Result<R, E>
    where
        F: FnOnce() -> Result<R, E>,
    {
        f()
    }

    pub fn enter_precompile<DB: Database, B, C, T, F, R>(
        journal: &mut JournaledState<DB>,
        _block: &B,
        _cfg: &C,
        _tx: &T,
        f: F,
    ) -> Result<R, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnOnce(AccountKeychain) -> Result<R, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        f(AccountKeychain {
            authorized_user: journal.mock_authorized_user,
            authorized_key_id: journal.mock_authorized_key_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    InvalidExpiringNonceExpiry(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsufficientBalance {
    pub available: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TIP20Error {
    InsufficientBalance(InsufficientBalance),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TIPFeeAMMError {
    InsufficientLiquidity(U256),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TempoPrecompileError {
    OutOfGas,
    Fatal(&'static str),
    NonceError(NonceError),
    TIP20(TIP20Error),
    TIPFeeAMMError(TIPFeeAMMError),
}

impl core::fmt::Display for TempoPrecompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TempoPrecompileError {
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::OutOfGas => "out of gas",
            Self::Fatal(_) => "fatal precompile error",
            Self::NonceError(_) => "nonce precompile error",
            Self::TIP20(_) => "tip20 precompile error",
            Self::TIPFeeAMMError(_) => "tip fee amm error",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct AccountKeychain {
    authorized_user: Address,
    authorized_key_id: Address,
}

impl AccountKeychain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_tx_origin(&mut self, _origin: Address) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    pub fn authorize_key(
        &mut self,
        _root_account: Address,
        _call: AuthorizeKeyCall,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    pub fn validate_keychain_authorization(
        &self,
        account: Address,
        key_id: Address,
        _current_timestamp: u64,
        _expected_sig_type: Option<u8>,
    ) -> Result<(), TempoPrecompileError> {
        if account == self.authorized_user && key_id == self.authorized_key_id {
            Ok(())
        } else {
            Err(TempoPrecompileError::Fatal("keychain: key not authorized"))
        }
    }

    pub fn set_transaction_key(
        &mut self,
        _access_key_addr: Address,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct TipFeeManager;

impl TipFeeManager {
    pub fn new() -> Self {
        Self
    }

    pub fn set_fee_token(&mut self, _fee_token: Address) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    pub fn collect_fee_pre_tx(
        &mut self,
        _fee_payer: Address,
        _fee_token: Address,
        _amount: U256,
        _beneficiary: Address,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub struct getNonceCall {
    #[allow(non_snake_case)]
    pub account: Address,
    #[allow(non_snake_case)]
    pub nonce_key: U256,
}

#[derive(Debug, Default, Clone)]
pub struct NonceManager;

impl NonceManager {
    pub fn new() -> Self {
        Self
    }

    pub fn check_and_mark_expiring_nonce(
        &mut self,
        _hash: B256,
        _valid_before: u64,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    pub fn get_nonce(&mut self, _call: getNonceCall) -> Result<u64, TempoPrecompileError> {
        Ok(0)
    }

    pub fn increment_nonce(
        &mut self,
        _account: Address,
        _nonce_key: U256,
    ) -> Result<(), TempoPrecompileError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct EvmInternals;

impl EvmInternals {
    pub fn new<J, B, C, T>(_journal: &mut J, _block: &B, _cfg: &C, _tx: &T) -> Self {
        Self
    }
}

#[derive(Debug, Default, Clone)]
pub struct EvmPrecompileStorageProvider {
    gas_used: u64,
}

impl EvmPrecompileStorageProvider {
    pub fn new(
        _internals: EvmInternals,
        _gas_limit: u64,
        _spec: MockHardfork,
        _track_refunds: bool,
        _gas_params: GasParams,
    ) -> Self {
        Self { gas_used: 0 }
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }
}

pub mod pre_execution {
    use super::{AccountInfo, CfgEnv, InvalidTransaction, TempoTxEnv, U256};

    pub fn validate_account_nonce_and_code(
        _account_info: &AccountInfo,
        _tx_nonce: u64,
        _eip3607_disabled: bool,
        _skip_nonce_check: bool,
    ) -> Result<(), InvalidTransaction> {
        Ok(())
    }

    pub fn calculate_caller_fee(
        account_balance: U256,
        _tx: &TempoTxEnv,
        _block: &super::BlockEnv,
        _cfg: &CfgEnv,
    ) -> Result<U256, InvalidTransaction> {
        Ok(account_balance)
    }
}

pub fn is_tip20_prefix(_token: Address) -> bool {
    true
}

pub fn get_token_balance<DB: Database>(
    journal: &mut JournaledState<DB>,
    token: Address,
    sender: Address,
) -> Result<U256, EVMError<DB::Error, TempoInvalidTransaction>> {
    if token == journal.mock_balance_token && sender == journal.mock_balance_owner {
        Ok(journal.mock_token_balance)
    } else {
        Ok(U256::from(cvlr::nondet::<u64>()))
    }
}
