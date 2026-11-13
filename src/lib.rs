//! Threshold key-share repair.
//!
//! Restores one lost Shamir share of an existing threshold key. The protocol
//! entry point is crate-private.

mod errors;
mod msg;
mod repair;
