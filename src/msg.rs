use generic_ec::{Curve, NonZero, Point, Scalar};
use round_based::ProtocolMessage;
use serde::{Deserialize, Serialize};

/// Messages for one repair run.
///
/// Every seat sends exactly one message to every other seat in each round.
/// `pad`, `sigma`, and `metadata` are set only on the edges the specification names.
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve> {
    /// A pad when the sender is an earlier helper.
    Round1(MsgRound1<E>),
    /// Share-dependent value and metadata, present only from a helper to the repairing party.
    Round2(MsgRound2<E>),
}

/// Round 1 payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound1<E: Curve> {
    /// Pad addressed to this recipient. `None` when this edge carries no pad.
    pub pad: Option<Scalar<E>>,
}

/// Round 2 payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2<E: Curve> {
    /// Sigma addressed to the repairing party. `None` on every other edge.
    pub sigma: Option<Scalar<E>>,
    /// Share metadata addressed to the repairing party. `None` on every other edge.
    pub metadata: Option<ShareMetadata<E>>,
}

/// Public description of this repair.
///
/// Sent in the clear with each helper's sigma. The repairing party accepts the
/// share only when every helper's copy equals its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShareMetadata<E: Curve> {
    /// Domain-separation string for this key and this repair.
    pub sid: Vec<u8>,
    /// Key-share index being restored.
    pub repairing: u16,
    /// Helper key-share indexes, strictly increasing.
    pub helpers: Vec<u16>,
    /// Joint public key.
    pub shared_public_key: NonZero<Point<E>>,
    /// Public share of every signer.
    pub public_shares: Vec<NonZero<Point<E>>>,
    /// Shamir evaluation point of every signer.
    pub evaluation_points: Vec<NonZero<Scalar<E>>>,
    /// Reconstruction threshold.
    pub threshold: u16,
    /// Chain code, present when the `hd-wallet` feature is enabled.
    #[cfg(feature = "hd-wallet")]
    pub chain_code: Option<[u8; 32]>,
}
