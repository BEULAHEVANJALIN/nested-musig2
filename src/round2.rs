#![allow(non_snake_case)]

use crate::error::MusigError;
use crate::keyagg::{key_agg, key_agg_coef};
use crate::params::Params;
use crate::round1::{Round1Out, Round1State};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

/// Round2 signer output: (state'_1, out'_1) = (R, s1)
pub type Round2State = Secp256k1Point;
pub type Round2Out = Secp256k1Scalar;

/// Fixed-length point encoding for transcripts: x(32) || y(32).
fn encode_point_xy(p: &Secp256k1Point) -> Result<[u8; 64], MusigError> {
    if p.is_identity() {
        return Err(MusigError::InvalidNonce);
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.x_only_bytes());

    let yb = p.y.to_bytes_be();
    if yb.len() > 32 {
        return Err(MusigError::InvalidNonce);
    }
    out[64 - yb.len()..].copy_from_slice(&yb);
    Ok(out)
}

/// b_{d+1} := Hnon( pk_{1,d} , out^{d+1} )
/// Transcript: pk_{1,d}.xonly || encode(out^{d+1}[0]) || ... || encode(out^{d+1}[nu-1])
fn compute_b_nested(
    par: &Params,
    pk_1_d: &Secp256k1Point,
    out_next: &Round1Out,
) -> Result<Secp256k1Scalar, MusigError> {
    if pk_1_d.is_identity() {
        return Err(MusigError::InvalidPubkey);
    }
    if out_next.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let mut t = Vec::with_capacity(32 + out_next.len() * 64);
    t.extend_from_slice(&pk_1_d.x_only_bytes());
    for R in out_next {
        t.extend_from_slice(&encode_point_xy(R)?);
    }
    Ok(par.hnon(&t))
}

/// b0 := Hnon_bar( X~ , out^0 , m )
/// Transcript: X~.xonly || encode(out^0[0]) || ... || encode(out^0[nu-1]) || m
fn compute_b0(
    par: &Params,
    X_tilde: &Secp256k1Point,
    out0: &Round1Out,
    msg: &[u8],
) -> Result<Secp256k1Scalar, MusigError> {
    if X_tilde.is_identity() {
        return Err(MusigError::InvalidPubkey);
    }
    let mut t = Vec::with_capacity(32 + out0.len() * 64 + msg.len());
    t.extend_from_slice(&X_tilde.x_only_bytes());
    for R in out0 {
        t.extend_from_slice(&encode_point_xy(R)?);
    }
    t.extend_from_slice(msg);
    Ok(par.hnon_bar(&t))
}

/// c := Hsig( X~ , R , m )
/// Transcript: X~.xonly || encode(R) || m
////// Transcript for c = Hsig(X̃, R, m)
#[allow(non_snake_case)]
fn compute_challenge_c(
    par: &Params,
    X_tilde: &Secp256k1Point,
    R: &Secp256k1Point,
    msg: &[u8],
) -> Result<Secp256k1Scalar, MusigError> {
    if X_tilde.is_identity() || R.is_identity() {
        return Err(MusigError::InvalidInput);
    }
    let mut t = Vec::with_capacity(32 + 64 + msg.len());
    t.extend_from_slice(&X_tilde.x_only_bytes());
    t.extend_from_slice(&encode_point_xy(R)?);
    t.extend_from_slice(msg);
    Ok(par.hsig(&t))
}

/// Compute R := Σ_j out0[j] * (b0^(j))  with exponent starting at 0 (b0^0 = 1).
fn compute_effective_R(
    out0: &Round1Out,
    b0: &Secp256k1Scalar,
) -> Result<Secp256k1Point, MusigError> {
    if out0.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let mut R = Secp256k1Point::identity();
    let mut e = Secp256k1Scalar::one(); // b0^0
    for Rj in out0 {
        if Rj.is_identity() {
            return Err(MusigError::InvalidNonce);
        }
        R = R + &(Rj.clone() * &e);
        e = &e * b0;
    }
    if R.is_identity() {
        return Err(MusigError::InvalidNonce);
    }
    Ok(R)
}

/// Compute Σ_j r_j * (b_hat^j) with exponent starting at 0 (b_hat^0 = 1).
fn compute_nonce_scalar_sum(
    state: &Round1State,
    b_hat: &Secp256k1Scalar,
) -> Result<Secp256k1Scalar, MusigError> {
    let nonces = state.nonces();
    if nonces.is_empty() {
        return Err(MusigError::InvalidInput);
    }
    let mut acc = Secp256k1Scalar::zero();
    let mut e = Secp256k1Scalar::one(); // b_hat^0
    for rj in nonces {
        let term = rj.clone() * &e;
        acc = acc + &term;
        e = &e * b_hat;
    }
    Ok(acc)
}

/// Sign′ (second-round signing) for arbitrary nesting depth Λ.
///
/// Inputs:
/// - `state1` is consumed to prevent nonce reuse.
/// - `outs_by_depth[d]` is out^d (INTERNAL aggregate), with d=0 as top level.
/// - `cosigners_by_depth[d]` are other pubkeys at that depth (excluding the signer’s pk_{1,d}).
///
/// Output: (R, s_i)
pub fn sign_prime(
    par: &Params,
    state1: Round1State,
    outs_by_depth: &[Round1Out],
    sk_leaf: &Secp256k1Scalar,
    msg: &[u8],
    cosigners_by_depth: &[Vec<Secp256k1Point>],
) -> Result<(Round2State, Round2Out), MusigError> {
    let lambda = outs_by_depth.len();
    if lambda == 0 || cosigners_by_depth.len() != lambda {
        return Err(MusigError::InvalidInput);
    }
    // ν must be consistent across all out^d and match state nonces.
    let nu = outs_by_depth[0].len();
    if nu == 0 || state1.nonces().len() != nu {
        return Err(MusigError::InvalidInput);
    }
    for out_d in outs_by_depth {
        if out_d.len() != nu {
            return Err(MusigError::InvalidInput);
        }
        for R in out_d {
            if R.is_identity() {
                return Err(MusigError::InvalidNonce);
            }
        }
    }
    let g = Secp256k1Point::generator();
    // pk_{1,Λ-1} := g^sk_leaf
    let pk_leaf = &g * sk_leaf;
    if pk_leaf.is_identity() {
        return Err(MusigError::InvalidPubkey);
    }
    // We accumulate:
    // a_prod := Π_{d=0..Λ-1} a_{1,d}
    // b_nested_prod := Π_{d=1..Λ-1} b_d
    let mut a_prod = Secp256k1Scalar::one();
    let mut b_nested_prod = Secp256k1Scalar::one();
    let X_tilde: Secp256k1Point;
    if lambda == 1 {
        // L0 := {pk_leaf} ∪ cosigners[0]
        let mut L0 = Vec::with_capacity(1 + cosigners_by_depth[0].len());
        L0.push(pk_leaf.clone());
        L0.extend_from_slice(&cosigners_by_depth[0]);
        let a0 = key_agg_coef(par, &L0, &pk_leaf)?;
        a_prod = &a_prod * &a0;
        X_tilde = key_agg(par, &L0)?;
    } else {
        // Leaf depth: d = Λ-1
        let d_leaf = lambda - 1;
        let mut L_leaf = Vec::with_capacity(1 + cosigners_by_depth[d_leaf].len());
        L_leaf.push(pk_leaf.clone());
        L_leaf.extend_from_slice(&cosigners_by_depth[d_leaf]);
        let a_leaf = key_agg_coef(par, &L_leaf, &pk_leaf)?;
        a_prod = &a_prod * &a_leaf;
        // pk_{1,Λ-2} := KeyAgg(L_{Λ-1})
        let mut pk_1_d = key_agg(par, &L_leaf)?;
        if pk_1_d.is_identity() {
            return Err(MusigError::InvalidPubkey);
        }
        // for d := Λ-2,...,0
        for d in (0..=lambda - 2).rev() {
            // b_{d+1} := Hnon(pk_{1,d}, out^{d+1})
            let b_next = compute_b_nested(par, &pk_1_d, &outs_by_depth[d + 1])?;
            b_nested_prod = &b_nested_prod * &b_next;
            // L_d := {pk_{1,d}} ∪ cosigners[d]
            let mut L_d = Vec::with_capacity(1 + cosigners_by_depth[d].len());
            L_d.push(pk_1_d.clone());
            L_d.extend_from_slice(&cosigners_by_depth[d]);
            // a_{1,d} := KeyAggCoef(L_d, pk_{1,d})
            let a_d = key_agg_coef(par, &L_d, &pk_1_d)?;
            a_prod = &a_prod * &a_d;
            // pk_{1,d-1} := KeyAgg(L_d)
            pk_1_d = key_agg(par, &L_d)?;
            if pk_1_d.is_identity() {
                return Err(MusigError::InvalidPubkey);
            }
        }
        // After d=0 iteration, pk_1_d is pk_{1,-1} = X~
        X_tilde = pk_1_d;
        if X_tilde.is_identity() {
            return Err(MusigError::InvalidPubkey);
        }
    }
    // b0 := Hnon_bar(X~, out^0, m)
    let b0 = compute_b0(par, &X_tilde, &outs_by_depth[0], msg)?;
    // R := Σ_j out^0[j] * (b0^j)
    let R = compute_effective_R(&outs_by_depth[0], &b0)?;
    // b_hat := b0 * Π_{d=1..Λ-1} b_d
    let b_hat = &b0 * &b_nested_prod;
    // c := Hsig(X~, R, m)
    let c = compute_challenge_c(par, &X_tilde, &R, msg)?;
    // c_hat := c * a_prod
    let c_hat = &c * &a_prod;
    // nonce_sum := Σ_j r_j * (b_hat^j)
    let nonce_sum = compute_nonce_scalar_sum(&state1, &b_hat)?;
    // s_i := c_hat*sk_leaf + nonce_sum
    let s_key = &c_hat * sk_leaf;
    let s = s_key + &nonce_sum;
    Ok((R, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyagg::key_agg;
    use crate::keygen::keygen_with_rng;
    use crate::round1::{sign_agg, sign_agg_ext, sign_round1_with_rng};
    use rand::{SeedableRng, rngs::ChaCha20Rng};

    fn schnorr_verify_like(
        par: &Params,
        X: &Secp256k1Point,
        msg: &[u8],
        R: &Secp256k1Point,
        s: &Secp256k1Scalar,
    ) -> bool {
        if X.is_identity() || R.is_identity() {
            return false;
        }
        let c = match super::compute_challenge_c(par, X, R, msg) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let g = Secp256k1Point::generator();
        let lhs = &g * s;
        let rhs = R.clone() + &(X.clone() * &c);
        lhs == rhs
    }

    #[test]
    fn signprime_lambda1_musig2_basecase_verifies() {
        let par = Params::default();
        let msg = b"test message";
        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
        // Two signers at depth 0 (Λ=1)
        let k1 = keygen_with_rng(&mut rng);
        let k2 = keygen_with_rng(&mut rng);
        let X = key_agg(&par, &[k1.pk.clone(), k2.pk.clone()]).unwrap();
        let (o1, st1) = sign_round1_with_rng(2, &mut rng).unwrap();
        let (o2, st2) = sign_round1_with_rng(2, &mut rng).unwrap();
        let out0 = sign_agg(&[o1, o2]).unwrap();
        // signer1 view: cosigner is pk2
        let (R1, s1) = sign_prime(
            &par,
            st1,
            &[out0.clone()],
            &k1.sk,
            msg,
            &[vec![k2.pk.clone()]],
        )
        .unwrap();
        // signer2 view: cosigner is pk1
        let (R2, s2) = sign_prime(
            &par,
            st2,
            &[out0.clone()],
            &k2.sk,
            msg,
            &[vec![k1.pk.clone()]],
        )
        .unwrap();
        assert_eq!(R1, R2);
        let s = s1 + &s2;
        assert!(schnorr_verify_like(&par, &X, msg, &R1, &s));
    }

    #[test]
    fn signprime_lambda2_nested_example_verifies() {
        let par = Params::default();
        let msg = b"nested musig2 test";
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
        // Alice, Bob (depth 1 under Abby), Carol (depth 0 direct)
        let alice = keygen_with_rng(&mut rng);
        let bob = keygen_with_rng(&mut rng);
        let carol = keygen_with_rng(&mut rng);
        // --- Depth 1 group: Alice+Bob ---
        let (oa, sta) = sign_round1_with_rng(2, &mut rng).unwrap();
        let (ob, stb) = sign_round1_with_rng(2, &mut rng).unwrap();
        let out1_internal = sign_agg(&[oa.clone(), ob.clone()]).unwrap();
        // Abby's pubkey at depth 0 for group = KeyAgg(pkA, pkB)
        let pk_abby0 = key_agg(&par, &[alice.pk.clone(), bob.pk.clone()]).unwrap();
        // Abby externalizes out1 to appear as one signer at depth 0
        let out1_external = sign_agg_ext(&par, &out1_internal, &pk_abby0).unwrap();
        // --- Carol at depth 0 ---
        let (oc, stc) = sign_round1_with_rng(2, &mut rng).unwrap();
        // Root internal out^0 aggregates (Abby-as-signer, Carol)
        let out0_internal = sign_agg(&[out1_external.clone(), oc.clone()]).unwrap();
        // Root aggregate key X = KeyAgg(pk_abby0, pk_carol)
        let X_root = key_agg(&par, &[pk_abby0.clone(), carol.pk.clone()]).unwrap();
        // --- Alice Sign′ with Λ=2 ---
        // outs_by_depth[0]=out^0, outs_by_depth[1]=out^1
        let (R_a, s_a) = sign_prime(
            &par,
            sta,
            &[out0_internal.clone(), out1_internal.clone()],
            &alice.sk,
            msg,
            &[
                vec![carol.pk.clone()], // depth 0 cosigner
                vec![bob.pk.clone()],   // depth 1 cosigner
            ],
        )
        .unwrap();
        // --- Bob Sign′ with Λ=2 ---
        let (R_b, s_b) = sign_prime(
            &par,
            stb,
            &[out0_internal.clone(), out1_internal.clone()],
            &bob.sk,
            msg,
            &[
                vec![carol.pk.clone()], // depth 0 cosigner
                vec![alice.pk.clone()], // depth 1 cosigner
            ],
        )
        .unwrap();
        assert_eq!(R_a, R_b);
        // Abby aggregates partial sigs at depth 0: s_abby = s_a + s_b
        let s_abby = s_a + &s_b;
        // --- Carol Sign′ with Λ=1 ---
        let (R_c, s_c) = sign_prime(
            &par,
            stc,
            &[out0_internal.clone()],
            &carol.sk,
            msg,
            &[vec![pk_abby0.clone()]], // depth 0 cosigner is Abby-group key
        )
        .unwrap();
        // All participants must agree on the same R from out^0
        assert_eq!(R_a, R_c);
        // Root final signature scalar s = s_abby + s_c
        let s_final = s_abby + &s_c;
        assert!(schnorr_verify_like(&par, &X_root, msg, &R_a, &s_final));
    }
}
