use thiserror::Error;

use crate::typed::Proof;

#[derive(Error, Debug, PartialEq)]
pub enum Srp6Error {
    #[error(
        "The provided key length ({given:?} byte) does not match the expected ({expected:?} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[error("The provided proof length ({given:?} byte) does not match the expected ({expected:?} byte)")]
    InvalidProofLength { given: usize, expected: usize },

    #[error("The provided proof is invalid")]
    InvalidProof,

    #[error("The provided strong proof is invalid")]
    InvalidStrongProof(Proof),

    /// The scrambler `u = H(A | B)` reduced to zero; `protocol_details` requires
    /// both sides to abort, since `u == 0` collapses the shared-secret exponent.
    #[error("the scrambler parameter u must not be zero")]
    InvalidScrambler,

    /// The client derived a zero premaster secret `S`; a malicious server can
    /// force this with `B = k*v`. Refuse before deriving the session key `K`.
    #[error("the derived premaster secret must not be zero")]
    InvalidPremaster,

    /// A [`crate::SaltBytes::custom`] width outside the safe range: below the
    /// NIST 64-bit floor or over the RFC 5054 `opaque srp_s<1..2^8-1>` wire cap.
    #[error("The requested salt length ({given:?} byte) is outside {min:?}..={max:?}")]
    InvalidSaltLength {
        given: usize,
        min: usize,
        max: usize,
    },

    /// The bytes did not decode to a non-zero element modulo the group's `N`.
    #[error("The provided bytes are not a valid field element of the group")]
    InvalidFieldElement,

    /// The server's public key `B` did not decode to a non-zero element
    /// modulo the local group's `N`. The check is re-run on the received
    /// handshake before any arithmetic, so a hand-crafted or corrupted
    /// handshake fails closed even if it never crossed the typed constructor.
    #[error("the server public key B must be a non-zero element of the local group")]
    InvalidPublicKey,

    /// The generator `g` carried by the handshake does not match the one the
    /// local group fixes. The client must never compute with a
    /// server-supplied `g`, or a malicious server could downgrade the group
    /// arithmetic behind the caller's back.
    #[error("the handshake generator g does not match the local group")]
    InvalidGenerator,

    /// The multiplier `k` carried by the handshake does not match the one the
    /// local group derives. Like `g`, `k` is a group parameter, not a
    /// per-session value, so a mismatch aborts the handshake.
    #[error("the handshake multiplier k does not match the local group")]
    InvalidMultiplier,

    /// The string was not an even-length run of hex digits.
    #[error("The provided string is not an even-length hex string")]
    InvalidHexString,
}
