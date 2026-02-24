use crate::error::MusigError;
use crate::params::Params;
use crate::utils::sample_nonzero_scalar_with_rng;
use crate::utils::{append_point_xy, encode_xonly};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use rand::{CryptoRng, Rng};

/// First-round public output of a signer (or an aggregator-as-a-signer):
/// `out = (R_1, ..., R_ν)` where `R_j = r_j*G`.
pub type Round1Out = Vec<Secp256k1Point>;

/// First-round secret state held by an actual signer:
/// `state = (r_1, ..., r_ν)`.
#[allow(dead_code)]
#[derive(Clone)]
pub struct Round1State {
    nonces: Vec<Secp256k1Scalar>,
}

impl Round1State {
    pub(crate) fn len(&self) -> usize {
        self.nonces.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Secp256k1Scalar> {
        self.nonces.iter()
    }
}

/// Round 1 (signer): generate ν random nonces and corresponding nonce points.
/// - `out[j]   = R_j = r_j * G`  (public)
/// - `state[j] = r_j`            (secret)
#[allow(non_snake_case)]
pub fn sign_round1_with_rng<R: Rng + CryptoRng>(
    nu: usize,
    rng: &mut R,
) -> Result<(Round1Out, Round1State), MusigError> {
    if nu == 0 {
        return Err(MusigError::InvalidInput);
    }
    let g = Secp256k1Point::generator();
    let mut out = Vec::with_capacity(nu);
    let mut state = Vec::with_capacity(nu);

    for _ in 0..nu {
        let r = sample_nonzero_scalar_with_rng(rng);
        let R = &g * &r;
        if R.is_identity() {
            return Err(MusigError::InvalidNonce);
        }
        state.push(r);
        out.push(R);
    }
    Ok((out, Round1State { nonces: state }))
}

pub fn sign_round1(nu: usize) -> Result<(Round1Out, Round1State), MusigError> {
    let mut rng = rand::rng();
    sign_round1_with_rng(nu, &mut rng)
}

/// Aggregate first-round outputs from multiple signers.
/// `outs[i][j]` is signer `i`'s public nonce point for index `j`.
/// Returns `agg[j] = Σ_i outs[i][j]`.
#[allow(non_snake_case)]
pub fn sign_agg(outs: &[Round1Out]) -> Result<Round1Out, MusigError> {
    if outs.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let nu = outs[0].len();
    if nu == 0 {
        return Err(MusigError::InvalidInput);
    }
    for o in outs {
        if o.len() != nu {
            return Err(MusigError::InvalidInput);
        }
        for R in o {
            if R.is_identity() {
                return Err(MusigError::InvalidNonce);
            }
        }
    }
    let mut agg = vec![Secp256k1Point::identity(); nu];
    for o in outs {
        for (j, R_ij) in o.iter().enumerate() {
            agg[j] = agg[j].clone() + R_ij;
        }
    }
    for R in &agg {
        if R.is_identity() {
            return Err(MusigError::InvalidNonce);
        }
    }
    Ok(agg)
}

/// Compute `b = Hnon( X̃_xonly || encode(out_internal) )`.
///
/// Transcript format:
/// - `X̃` included as x-only (32 bytes)
/// - Each `R'_j` included as fixed-length `x(32) || y(32)`
#[allow(non_snake_case)]
fn compute_b(
    par: &Params,
    X_tilde: &Secp256k1Point,
    out_internal: &[Secp256k1Point],
) -> Result<Secp256k1Scalar, MusigError> {
    let mut t = Vec::with_capacity(32 + out_internal.len() * 64);
    // X̃ x-only
    t.extend_from_slice(&encode_xonly(X_tilde, MusigError::InvalidPubkey)?);
    // each R'_j as x||y
    for R in out_internal {
        append_point_xy(&mut t, R, MusigError::InvalidNonce)?;
    }
    Ok(par.hnon(&t))
}

/// SignAggExt(out_internal, X̃):
/// b := Hnon(X̃, out_internal)
/// Paper uses j in 1..ν and exponent b^(j-1).
/// Our vectors are 0-indexed, so index i corresponds to j=i+1 and exponent b^i.
/// R[i] := b^i * R'[i]
#[allow(non_snake_case)]
pub fn sign_agg_ext(
    par: &Params,
    out_internal: &[Secp256k1Point],
    X_tilde: &Secp256k1Point,
) -> Result<Round1Out, MusigError> {
    if out_internal.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let b = compute_b(par, X_tilde, out_internal)?;
    let mut out_external = Vec::with_capacity(out_internal.len());
    let mut e = Secp256k1Scalar::one(); // e = b^0
    for Rj_prime in out_internal {
        // R_j = e * R'_j
        out_external.push(Rj_prime.clone() * &e);
        // Update exponent so next loop uses b^(j+1)
        e = &e * &b;
    }
    Ok(out_external)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_with_rng;
    use crate::params::Params;
    use rand::{SeedableRng, rngs::ChaCha20Rng};

    #[test]
    fn sign_round1_shapes() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let (out, state) = sign_round1_with_rng(3, &mut rng).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(state.len(), 3);
    }

    #[test]
    fn sign_agg_coordinate_wise_sum() {
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let (o1, _) = sign_round1_with_rng(2, &mut rng).unwrap();
        let (o2, _) = sign_round1_with_rng(2, &mut rng).unwrap();
        let agg = sign_agg(&[o1.clone(), o2.clone()]).unwrap();
        assert_eq!(agg.len(), 2);
        assert_eq!(agg[0], o1[0].clone() + &o2[0]);
        assert_eq!(agg[1], o1[1].clone() + &o2[1]);
    }

    #[test]
    #[allow(non_snake_case)]
    fn sign_agg_ext_is_deterministic_given_inputs() {
        let par = Params::default();
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let Xtilde = crate::keyagg::key_agg(
            &par,
            &[keygen_with_rng(&mut rng).pk, keygen_with_rng(&mut rng).pk],
        )
        .unwrap();
        let (o1, _) = sign_round1_with_rng(2, &mut rng).unwrap();
        let (o2, _) = sign_round1_with_rng(2, &mut rng).unwrap();
        let internal = sign_agg(&[o1, o2]).unwrap();
        let ext1 = sign_agg_ext(&par, &internal, &Xtilde).unwrap();
        let ext2 = sign_agg_ext(&par, &internal, &Xtilde).unwrap();
        assert_eq!(ext1, ext2);
    }

    #[test]
    #[allow(non_snake_case)]
    fn sign_agg_ext_matches_definition() {
        let par = Params::default();
        let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
        let Xtilde = crate::keyagg::key_agg(
            &par,
            &[keygen_with_rng(&mut rng).pk, keygen_with_rng(&mut rng).pk],
        )
        .unwrap();
        let (o1, _) = sign_round1_with_rng(3, &mut rng).unwrap();
        let (o2, _) = sign_round1_with_rng(3, &mut rng).unwrap();
        let internal = sign_agg(&[o1, o2]).unwrap();
        let b = super::compute_b(&par, &Xtilde, &internal).unwrap();
        let ext = sign_agg_ext(&par, &internal, &Xtilde).unwrap();
        let mut e = Secp256k1Scalar::one();
        for j in 0..3 {
            let expected = internal[j].clone() * &e;
            assert_eq!(ext[j], expected);
            e = &e * &b;
        }
    }
}
