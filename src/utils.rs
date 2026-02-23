// src/utils.rs
use crypto_rs::field::{ScalarField, Secp256k1ScalarField};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::{CryptoRng, Rng};

use crate::error::MusigError;

/// Samples a uniformly random secp256k1 scalar in the range `[1, n-1]` using rejection sampling.
pub fn sample_nonzero_scalar_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> Secp256k1Scalar {
    let n = Secp256k1ScalarField::order();
    loop {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let x = BigUint::from_bytes_be(&buf);
        // Reject x == 0 or x >= n
        if x.is_zero() || x >= n {
            continue;
        }
        return Secp256k1Scalar::new(x);
    }
}

/// Fixed-length encoding of a point: x(32) || y(32).
/// Deterministic transcript encoding (NOT SEC serialization).
pub(crate) fn encode_point_xy(
    p: &Secp256k1Point,
    identity_err: MusigError,
) -> Result<[u8; 64], MusigError> {
    if p.is_identity() {
        return Err(identity_err);
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.x_only_bytes());
    // y may be shorter: pad to 32
    let yb = p.y.to_bytes_be();
    if yb.len() > 32 {
        // Should never happen for secp256k1 field elements
        return Err(identity_err);
    }
    out[64 - yb.len()..].copy_from_slice(&yb);
    Ok(out)
}

/// x-only (32 bytes). Useful for pubkeys (BIP340-style).
pub(crate) fn encode_xonly(
    p: &Secp256k1Point,
    identity_err: MusigError,
) -> Result<[u8; 32], MusigError> {
    if p.is_identity() {
        return Err(identity_err);
    }
    Ok(p.x_only_bytes())
}

/// Append x||y encoding to an existing transcript buffer.
pub(crate) fn append_point_xy(
    buf: &mut Vec<u8>,
    p: &Secp256k1Point,
    identity_err: MusigError,
) -> Result<(), MusigError> {
    buf.extend_from_slice(&encode_point_xy(p, identity_err)?);
    Ok(())
}
