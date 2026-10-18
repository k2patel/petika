//! Synthetic capability probe only; not a vault format or validation claim.
#[cfg(all(feature = "fips", feature = "non-fips"))]
compile_error!("Select either non-fips or fips; use --no-default-features for fips");

use aws_lc_rs::aead::{AES_256_GCM, Aad, RandomizedNonceKey};

#[cfg(feature = "fips")]
mod evidence;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        if args.len() != 2 || args[0] != "--expect-module" {
            eprintln!("usage: petika-crypto-provider-spike [--expect-module EXACT_VERSION]");
            std::process::exit(2);
        }
        #[cfg(feature = "fips")]
        {
            let actual = evidence::module_version();
            if actual != args[1] {
                eprintln!(
                    "module mismatch: expected {:?}, observed {:?}",
                    args[1], actual
                );
                std::process::exit(2);
            }
        }
        #[cfg(not(feature = "fips"))]
        {
            eprintln!("module expectation requires the FIPS-provider build");
            std::process::exit(2);
        }
    }
    println!("Synthetic AES-256-GCM probe; no Petika/FIPS validation claim");
    println!("fips feature requested: {}", cfg!(feature = "fips"));
    #[cfg(feature = "fips")]
    aws_lc_rs::try_fips_mode().expect("requested FIPS provider must report FIPS mode");
    #[cfg(feature = "fips")]
    println!("runtime module: {}", evidence::module_version());
    let mut key_bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut key_bytes).expect("provider randomness");
    let key = RandomizedNonceKey::new(&AES_256_GCM, &key_bytes).expect("AES-256-GCM key");
    key_bytes.fill(0); // Best effort only; this spike does not claim verified zeroization.
    let aad = b"petika:synthetic-provider-probe:v1";
    let mut ciphertext = b"synthetic password, never a real secret".to_vec();
    let nonce = key
        .seal_in_place_append_tag(Aad::from(aad), &mut ciphertext)
        .expect("seal");
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut ciphertext)
        .expect("open");
    assert_eq!(plaintext, b"synthetic password, never a real secret");
    println!("provider-generated nonce round trip: PASS");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::aead::Nonce;

    fn sample() -> (RandomizedNonceKey, [u8; 12], Vec<u8>) {
        let mut bytes = [0; 32];
        aws_lc_rs::rand::fill(&mut bytes).unwrap();
        let key = RandomizedNonceKey::new(&AES_256_GCM, &bytes).unwrap();
        let mut encrypted = b"synthetic entry".to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(b"collection-A:epoch-1"), &mut encrypted)
            .unwrap();
        (key, *nonce.as_ref(), encrypted)
    }

    #[cfg(feature = "fips")]
    #[test]
    fn randomized_gcm_reports_approved_services() {
        aws_lc_rs::try_fips_mode().unwrap();
        let key = RandomizedNonceKey::new(&AES_256_GCM, &[42; 32]).unwrap();
        let mut data = b"synthetic indicator check".to_vec();
        let (sealed, approved) =
            evidence::approved(|| key.seal_in_place_append_tag(Aad::from(b"context"), &mut data));
        let nonce = sealed.unwrap();
        assert!(approved, "encryption did not report approved service");
        let (opened, approved) =
            evidence::approved(|| key.open_in_place(nonce, Aad::from(b"context"), &mut data));
        assert_eq!(opened.unwrap(), b"synthetic indicator check");
        assert!(approved, "decryption did not report approved service");
    }

    #[test]
    fn round_trip() {
        #[cfg(feature = "fips")]
        aws_lc_rs::try_fips_mode().expect("FIPS mode required");
        let (key, nonce, mut encrypted) = sample();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"collection-A:epoch-1"),
                &mut encrypted,
            )
            .unwrap();
        assert_eq!(plaintext, b"synthetic entry");
    }

    #[test]
    fn rejects_modified_ciphertext_tag_nonce_and_context() {
        let (key, nonce, encrypted) = sample();
        for offset in [0, encrypted.len() - 1] {
            let mut changed = encrypted.clone();
            changed[offset] ^= 1;
            assert!(
                key.open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(b"collection-A:epoch-1"),
                    &mut changed
                )
                .is_err()
            );
        }
        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        assert!(
            key.open_in_place(
                Nonce::assume_unique_for_key(changed_nonce),
                Aad::from(b"collection-A:epoch-1"),
                &mut encrypted.clone()
            )
            .is_err()
        );
        assert!(
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"collection-B:epoch-1"),
                &mut encrypted.clone()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_wrong_key_and_truncated_tag() {
        let (_, nonce, encrypted) = sample();
        let key = RandomizedNonceKey::new(&AES_256_GCM, &[42; 32]).unwrap();
        assert!(
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"collection-A:epoch-1"),
                &mut encrypted.clone()
            )
            .is_err()
        );
        let (key, nonce, mut encrypted) = sample();
        encrypted.truncate(8);
        assert!(
            key.open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"collection-A:epoch-1"),
                &mut encrypted
            )
            .is_err()
        );
    }
}
