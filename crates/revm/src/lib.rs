//! Tempo revm specific implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "certora")]
pub mod certora;

#[cfg(not(feature = "certora"))]
mod block;
// Suppress unused_crate_dependencies warning for tracing
#[cfg(all(not(test), not(feature = "certora")))]
use tracing as _;

#[cfg(not(feature = "certora"))]
mod common;
#[cfg(not(feature = "certora"))]
pub use common::{TempoStateAccess, TempoTx};
#[cfg(not(feature = "certora"))]
pub mod error;
#[cfg(not(feature = "certora"))]
pub mod evm;
#[cfg(not(feature = "certora"))]
pub mod exec;
#[cfg(not(feature = "certora"))]
pub mod gas_params;
pub mod handler;
#[cfg(not(feature = "certora"))]
mod instructions;
#[cfg(not(feature = "certora"))]
mod tx;

#[cfg(not(feature = "certora"))]
pub use block::TempoBlockEnv;
#[cfg(not(feature = "certora"))]
pub use error::{TempoHaltReason, TempoInvalidTransaction};
#[cfg(not(feature = "certora"))]
pub use evm::TempoEvm;
#[cfg(not(feature = "certora"))]
pub use handler::calculate_aa_batch_intrinsic_gas;
#[cfg(not(feature = "certora"))]
pub use revm::interpreter::instructions::utility::IntoAddress;
#[cfg(not(feature = "certora"))]
pub use tx::{TempoBatchCallEnv, TempoTxEnv};
