//! X-Wing draft-06 section 5.6 adapter. HPKE key scheduling is provided by hpke.
use hpke::{
    Deserializable, HpkeError, Kem, Serializable,
    generic_array::typenum::{Sum, U32, U96, U192, U1024},
    kem::SharedSecret,
    rand_core::{CryptoRng, RngCore},
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use x_wing::{Decapsulate, Decapsulator, KeyExport};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type U1120 = Sum<U1024, U96>;
type U1216 = Sum<U1024, U192>;
pub(super) struct XWing;
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(super) struct Secret([u8; 32]);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Public([u8; 1216]);
#[derive(Clone)]
pub(super) struct Encapped([u8; 1120]);
macro_rules! encoding {
    ($name:ident, $size:ty, $len:expr) => {
        impl Serializable for $name {
            type OutputSize = $size;
            fn write_exact(&self, out: &mut [u8]) {
                out.copy_from_slice(&self.0);
            }
        }
        impl Deserializable for $name {
            fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
                Ok(Self(bytes.try_into().map_err(|_| {
                    HpkeError::IncorrectInputLength($len, bytes.len())
                })?))
            }
        }
    };
}
encoding!(Secret, U32, 32);
encoding!(Encapped, U1120, 1120);
impl Serializable for Public {
    type OutputSize = U1216;
    fn write_exact(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0);
    }
}
impl Deserializable for Public {
    fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        x_wing::EncapsulationKey::try_from(bytes).map_err(|_| HpkeError::ValidationError)?;
        Ok(Self(
            bytes.try_into().map_err(|_| HpkeError::ValidationError)?,
        ))
    }
}
impl Kem for XWing {
    type PublicKey = Public;
    type PrivateKey = Secret;
    type EncappedKey = Encapped;
    type NSecret = U32;
    const KEM_ID: u16 = 0x647a;
    fn sk_to_pk(sk: &Secret) -> Public {
        Public(
            x_wing::DecapsulationKey::from(sk.0)
                .encapsulation_key()
                .to_bytes()
                .into(),
        )
    }
    fn derive_keypair(ikm: &[u8]) -> (Secret, Public) {
        let mut hash = Shake256::default();
        hash.update(ikm);
        let mut secret = Secret([0; 32]);
        hash.finalize_xof().read(&mut secret.0);
        let public = Self::sk_to_pk(&secret);
        (secret, public)
    }
    fn decap(
        sk: &Secret,
        sender: Option<&Public>,
        enc: &Encapped,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if sender.is_some() {
            return Err(HpkeError::DecapError);
        }
        let mut shared = x_wing::DecapsulationKey::from(sk.0)
            .decapsulate_slice(&enc.0)
            .map_err(|_| HpkeError::DecapError)?;
        let mut result = SharedSecret::<Self>::default();
        result.0.copy_from_slice(&shared);
        shared.zeroize();
        Ok(result)
    }
    fn encap<R: CryptoRng + RngCore>(
        pk: &Public,
        sender: Option<(&Secret, &Public)>,
        rng: &mut R,
    ) -> Result<(SharedSecret<Self>, Encapped), HpkeError> {
        if sender.is_some() {
            return Err(HpkeError::EncapError);
        }
        let public = x_wing::EncapsulationKey::try_from(pk.0.as_slice())
            .map_err(|_| HpkeError::EncapError)?;
        let mut randomness = Zeroizing::new([0; 64]);
        rng.fill_bytes(randomness.as_mut());
        let (enc, mut shared) = public.encapsulate_deterministic((&*randomness).into());
        let mut result = SharedSecret::<Self>::default();
        result.0.copy_from_slice(&shared);
        shared.zeroize();
        Ok((result, Encapped(enc.into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct VectorRng(Vec<u8>);
    impl RngCore for VectorRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            out.copy_from_slice(&self.0[..out.len()]);
            self.0.drain(..out.len());
        }
    }
    impl CryptoRng for VectorRng {}
    fn bytes(v: &serde_json::Value, field: &str) -> Vec<u8> {
        v[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn adapter_matches_independent_draft06_vectors() {
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../tests/fixtures/xwing-draft06.json")).unwrap();
        for v in vectors {
            let sk = Secret::from_bytes(&bytes(&v, "sk")).unwrap();
            let pk = Public::from_bytes(&bytes(&v, "pk")).unwrap();
            assert_eq!(XWing::sk_to_pk(&sk), pk);
            let (ss, enc) = XWing::encap(&pk, None, &mut VectorRng(bytes(&v, "eseed"))).unwrap();
            assert_eq!(ss.0.as_slice(), bytes(&v, "ss"));
            assert_eq!(enc.to_bytes().as_slice(), bytes(&v, "ct"));
            assert_eq!(XWing::decap(&sk, None, &enc).unwrap().0, ss.0);
            assert!(XWing::encap(&pk, Some((&sk, &pk)), &mut VectorRng(vec![])).is_err());
            assert!(XWing::decap(&sk, Some(&pk), &enc).is_err());
        }
    }
}
