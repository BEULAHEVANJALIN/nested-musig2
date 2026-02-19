// src/utils.rs
use crypto_rs::field::{ScalarField, Secp256k1ScalarField};
use crypto_rs::secp256k1::Secp256k1Scalar;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::{CryptoRng, Rng};

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
