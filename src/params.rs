use crypto_rs::secp256k1::Secp256k1Scalar;
use crypto_rs::tagged_hash::hash_to_scalar;

/// Parameters returned by Setup(1^λ).
///
/// In the paper this includes (G, p, g) and four hash functions.
/// In Rust we "fix" the group to secp256k1 and represent hash functions
/// via tagged hashing wrappers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params {
    pub tag_hagg: &'static str,
    pub tag_hnon: &'static str,
    pub tag_hnon_bar: &'static str,
    pub tag_hsig: &'static str,
}

impl Default for Params {
    fn default() -> Self {
        Self::v1()
    }
}

impl Params {
    // todo: introduce a `Params::bip327()`; we'll choose BIP327's exact tag strings later.
    pub const fn v1() -> Self {
        Self {
            tag_hagg: "NestedMuSig2/Hagg",
            tag_hnon: "NestedMuSig2/Hnon",
            tag_hnon_bar: "NestedMuSig2/Hnon_bar",
            tag_hsig: "NestedMuSig2/Hsig",
        }
    }
    /// Setup(1^λ): return public protocol parameters.
    ///
    /// No runtime randomness is required;
    /// this function simply returns a fixed selection of domain-separated hash tags.
    pub fn setup() -> Self {
        Self::default()
    }

    /// Hagg : {0,1}* -> Z_n  (scalar field)
    pub fn hagg(&self, msg: &[u8]) -> Secp256k1Scalar {
        hash_to_scalar(self.tag_hagg, msg)
    }

    /// Hnon : {0,1}* -> Z_n
    pub fn hnon(&self, msg: &[u8]) -> Secp256k1Scalar {
        hash_to_scalar(self.tag_hnon, msg)
    }

    /// Hnon_bar : {0,1}* -> Z_n
    pub fn hnon_bar(&self, msg: &[u8]) -> Secp256k1Scalar {
        hash_to_scalar(self.tag_hnon_bar, msg)
    }

    /// Hsig : {0,1}* -> Z_n
    pub fn hsig(&self, msg: &[u8]) -> Secp256k1Scalar {
        hash_to_scalar(self.tag_hsig, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_rs::field::ScalarField;
    use crypto_rs::field::Secp256k1ScalarField;

    #[test]
    fn hashes_are_deterministic() {
        let p = Params::default();
        let msg = b"hello world";
        assert_eq!(p.hagg(msg), p.hagg(msg));
        assert_eq!(p.hnon(msg), p.hnon(msg));
        assert_eq!(p.hnon_bar(msg), p.hnon_bar(msg));
        assert_eq!(p.hsig(msg), p.hsig(msg));
    }

    #[test]
    fn setup_is_stable_and_domain_separated() {
        let par = Params::setup();

        let m = b"hello";

        let a = par.hagg(m).to_bytes_be();
        let b = par.hnon(m).to_bytes_be();
        let c = par.hnon_bar(m).to_bytes_be();
        let d = par.hsig(m).to_bytes_be();

        // Domain separation: tags must produce different outputs (overwhelmingly likely).
        // sanity test; not a proof!
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(b, c);
        assert_ne!(b, d);
        assert_ne!(c, d);
    }

    #[test]
    fn secp256k1_scalar_order_is_group_order_n() {
        // secp256k1 group order n
        let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let expected_n = num_bigint::BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        assert_eq!(Secp256k1ScalarField::order(), expected_n);
    }

    #[test]
    fn hash_to_scalar_is_reduced_mod_n() {
        let cases: [(&str, &[u8]); 4] = [
            ("T", &[]),
            ("T", &b"hello"[..]),
            ("NestedMuSig2/Hsig", &b"some transcript bytes"[..]),
            ("NestedMuSig2/Hnon", &b"\x00\x01\x02\x03\xff"[..]),
        ];
        // result must always be < n.
        for (tag, msg) in cases {
            let s = hash_to_scalar(tag, msg);
            // convert to BigUint for comparison.
            let x = num_bigint::BigUint::from_bytes_be(&s.to_bytes_be());
            assert!(
                x < Secp256k1ScalarField::order(),
                "scalar not reduced mod n"
            );
        }
    }
}
