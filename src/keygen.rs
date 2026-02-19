use crate::utils::sample_nonzero_scalar_with_rng as sample_secret_scalar;
use crypto_rs::field::{ScalarField, Secp256k1ScalarField};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

use num_traits::Zero;
use rand::{CryptoRng, Rng};

/// BIP340-style keypair:
/// - `pk` is a full point, but canonicalized so its Y is even.
/// - `pk_xonly()` gives the x-only encoding.
/// Invariant: `pk` always has **even** Y (canonical x-only pubkey),
/// achieved by potentially negating `sk` and `pk`.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyPair {
    pub sk: Secp256k1Scalar,
    pub pk: Secp256k1Point,
}

impl KeyPair {
    /// Canonical BIP340 x-only public key encoding (32-byte X coordinate).
    #[inline]
    pub fn pk_xonly(&self) -> [u8; 32] {
        self.pk.x_only_bytes()
    }
}

/// Negate scalar modulo curve order: (-x mod n) = n - x, assuming x != 0.
fn negate_scalar(sk: &Secp256k1Scalar) -> Secp256k1Scalar {
    let n = Secp256k1ScalarField::order();
    let x = sk.value();
    debug_assert!(!x.is_zero());
    Secp256k1Scalar::new(&n - x)
}

/// KeyGen(): returns (sk, pk) with pk normalized to even-Y (BIP340 convention).
pub fn keygen_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    let mut sk = sample_secret_scalar(rng);
    let g = Secp256k1Point::generator();
    let pk_raw = &g * &sk;
    let pk = pk_raw.normalize_parity();
    // If normalization changed the point, pk_raw had odd Y,
    if pk != pk_raw {
        sk = negate_scalar(&sk);
        debug_assert_eq!((&g * &sk), pk);
    }
    debug_assert_eq!(pk, pk.normalize_parity());
    KeyPair { sk, pk }
}

pub fn keygen() -> KeyPair {
    let mut rng = rand::rng();
    keygen_with_rng(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::ChaCha20Rng};

    #[test]
    fn keygen_produces_valid_pair_and_even_y_pk() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let kp = keygen_with_rng(&mut rng);
        assert!(!kp.sk.value().is_zero());
        // pk must be even-Y (i.e., already normalized)
        assert_eq!(kp.pk, kp.pk.normalize_parity());
        // pk must equal sk*G
        let g = Secp256k1Point::generator();
        assert_eq!((&g * &kp.sk), kp.pk);
    }

    #[test]
    fn pk_xonly_is_even() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let kp = keygen_with_rng(&mut rng);
        let x = kp.pk_xonly();
        assert_eq!(x.len(), 32);
    }
}
