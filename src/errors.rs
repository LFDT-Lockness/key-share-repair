// Used by the private protocol, which itself is only called from tests.
#![allow(dead_code)]

use round_based::rounds_router::errors::CompleteRoundError;
use round_based::rounds_router::simple_store::RoundInputError;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub(crate) enum Error {
    /// Caller inputs do not describe a repair this protocol can run
    #[displaydoc("invalid arguments")]
    InvalidArgs,
    /// A helper's share metadata does not match the repairing party's copy
    #[displaydoc("helpers disagree on the share metadata")]
    MetadataMismatch,
    /// An earlier helper omitted the pad this seat needs
    #[displaydoc("missing pad from an earlier helper")]
    MissingPad,
    /// A helper omitted the value owed to the repairing party
    #[displaydoc("missing sigma from a helper")]
    MissingSigma,
    /// `x_r * G` is not the public share at the repairing index
    #[displaydoc("reconstructed share does not match the public share")]
    BadReconstruction,
    /// Sending or receiving a round failed
    #[displaydoc("i/o error")]
    Io(#[source] IoError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub(crate) enum IoError {
    /// Outgoing sink rejected a message
    #[displaydoc("send message")]
    Send(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Incoming stream ended or a round could not be completed
    #[displaydoc("receive message")]
    Receive(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub(crate) fn send<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Io(IoError::Send(Box::new(err)))
    }

    pub(crate) fn receive<E>(err: CompleteRoundError<RoundInputError, E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Io(IoError::Receive(Box::new(err)))
    }
}
