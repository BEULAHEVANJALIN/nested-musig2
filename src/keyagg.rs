use crate::error::MusigError;
use crate::params::Params;
use crate::utils::encode_point_xy;
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

/// Deterministically sort pubkeys by their 64-byte encoding.
fn sort_pubkeys(pubkeys: &[Secp256k1Point]) -> Result<Vec<Secp256k1Point>, MusigError> {
    let mut pairs: Vec<([u8; 64], Secp256k1Point)> = Vec::with_capacity(pubkeys.len());
    for pk in pubkeys {
        pairs.push((encode_point_xy(pk, MusigError::InvalidPubkey)?, pk.clone()));
    }
    pairs.sort_by(|(ea, _), (eb, _)| ea.cmp(eb));
    Ok(pairs.into_iter().map(|(_, pk)| pk).collect())
}

/// Encode L as concatenation of sorted `encode_pubkey_xy(pk)` encodings.
fn encode_pubkey_list(pubkeys: &[Secp256k1Point]) -> Result<Vec<u8>, MusigError> {
    let sorted = sort_pubkeys(pubkeys)?;
    let mut out = Vec::with_capacity(sorted.len() * 64);
    for pk in &sorted {
        out.extend_from_slice(&encode_point_xy(pk, MusigError::InvalidPubkey)?);
    }
    Ok(out)
}

/// KeyAggCoef(L, Xi) = Hagg( encode(L) || encode(Xi) )
#[allow(non_snake_case)]
pub fn key_agg_coef(
    par: &Params,
    L: &[Secp256k1Point],
    Xi: &Secp256k1Point,
) -> Result<Secp256k1Scalar, MusigError> {
    if L.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let mut buf = encode_pubkey_list(L)?;
    buf.extend_from_slice(&encode_point_xy(Xi, MusigError::InvalidPubkey)?);
    Ok(par.hagg(&buf))
}

/// KeyAgg(L): aggregate key X̃ = Π Xi^{ai}
/// In additive notation: X̃ = Σ ai * Xi.
///
/// Deterministic: uses sorted L for coefficient transcript and iteration.
#[allow(non_snake_case)]
pub fn key_agg(par: &Params, L: &[Secp256k1Point]) -> Result<Secp256k1Point, MusigError> {
    if L.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let sorted = sort_pubkeys(L)?;
    let mut acc = Secp256k1Point::identity();
    for Xi in &sorted {
        let ai = key_agg_coef(par, &sorted, Xi)?;
        acc = acc + &(Xi.clone() * &ai);
    }
    // Aggregate key should not be infinity/identity.
    if acc.is_identity() {
        return Err(MusigError::InvalidPubkey);
    }
    Ok(acc)
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_with_rng;
    use rand::{SeedableRng, rngs::ChaCha20Rng};

    #[test]
    fn keyaggcoef_is_deterministic() {
        let par = Params::default();
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let k1 = keygen_with_rng(&mut rng).pk;
        let k2 = keygen_with_rng(&mut rng).pk;
        let L = vec![k1.clone(), k2.clone()];
        let a1 = key_agg_coef(&par, &L, &k1).unwrap();
        let a2 = key_agg_coef(&par, &L, &k1).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn keyagg_is_permutation_invariant() {
        let par = Params::default();
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let k1 = keygen_with_rng(&mut rng).pk;
        let k2 = keygen_with_rng(&mut rng).pk;
        let k3 = keygen_with_rng(&mut rng).pk;
        let L1 = vec![k1.clone(), k2.clone(), k3.clone()];
        let L2 = vec![k3, k1, k2];
        let a = key_agg(&par, &L1).unwrap();
        let b = key_agg(&par, &L2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn keyagg_multiset_duplicates_are_handled() {
        let par = Params::default();
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let k1 = keygen_with_rng(&mut rng).pk;
        let k2 = keygen_with_rng(&mut rng).pk;
        // L has a duplicate k1
        let L = vec![k1.clone(), k1.clone(), k2.clone()];
        let X = key_agg(&par, &L).unwrap();
        assert!(!X.is_identity());
        // Sanity: removing a duplicate should (overwhelmingly likely) change the result
        let L2 = vec![k1, k2];
        let Y = key_agg(&par, &L2).unwrap();
        assert_ne!(X, Y);
    }

    #[test]
    fn identity_pubkey_is_rejected() {
        let par = Params::default();
        let id = Secp256k1Point::identity();
        let err = key_agg(&par, &[id]).unwrap_err();
        assert!(matches!(err, MusigError::InvalidPubkey));
    }
}
