//! Windows Hello PRF releases the wrapping key only after platform user verification.
use super::super::Result;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{ffi::c_void, ptr};
use windows_sys::{
    Win32::{
        Networking::WindowsWebServices::*,
        System::{
            Console::GetConsoleWindow,
            LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        },
    },
    core::w,
};
use zeroize::{Zeroize, Zeroizing};

const UNAVAILABLE: &str =
    "Windows Hello with PRF support is unavailable; use your vault passphrase";
const DENIED: &str = "Windows Hello approval failed or was cancelled; use your vault passphrase";
const INVALID: &str = "invalid Windows Hello vault enrollment";
// WebAuthn flags UP and UV are required. BE and BS must both be clear.
const LOCAL_VERIFICATION_MASK: u8 = 0x01 | 0x04 | 0x08 | 0x10;
const REQUIRED_VERIFICATION_FLAGS: u8 = 0x01 | 0x04;

type MakeCredential = unsafe extern "system" fn(
    *mut c_void,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> i32;
type GetAssertion = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> i32;

struct Api {
    make: MakeCredential,
    get: GetAssertion,
    free_attestation: unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION),
    free_assertion: unsafe extern "system" fn(*const WEBAUTHN_ASSERTION),
}

impl Api {
    fn load() -> Result<Self> {
        // Resolve optional APIs from System32. Older Windows keeps its passphrase path.
        // The system DLL stays loaded until process exit so all returned buffers and
        // function pointers remain valid during unwinding.
        unsafe {
            let module = LoadLibraryExW(
                w!("webauthn.dll"),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if module.is_null() {
                return Err(UNAVAILABLE.into());
            }
            macro_rules! symbol {
                ($name:literal, $kind:ty) => {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $kind>(
                        GetProcAddress(module, concat!($name, "\0").as_ptr()).ok_or(UNAVAILABLE)?,
                    )
                };
            }
            let version = symbol!(
                "WebAuthNGetApiVersionNumber",
                unsafe extern "system" fn() -> u32
            );
            let available = symbol!(
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
                unsafe extern "system" fn(*mut i32) -> i32
            );
            let mut enabled = 0;
            if version() < 6 || available(&mut enabled) < 0 || enabled == 0 {
                return Err(UNAVAILABLE.into());
            }
            Ok(Self {
                make: symbol!("WebAuthNAuthenticatorMakeCredential", MakeCredential),
                get: symbol!("WebAuthNAuthenticatorGetAssertion", GetAssertion),
                free_attestation: symbol!(
                    "WebAuthNFreeCredentialAttestation",
                    unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION)
                ),
                free_assertion: symbol!(
                    "WebAuthNFreeAssertion",
                    unsafe extern "system" fn(*const WEBAUTHN_ASSERTION)
                ),
            })
        }
    }

    fn create(&self) -> Result<Vec<u8>> {
        let user = random::<32>()?;
        let mut json = client_data("webauthn.create")?;
        let client = client(&mut json);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: 1,
            pwszId: w!("petika.local"),
            pwszName: w!("Petika local vault"),
            ..Default::default()
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: 1,
            cbId: user.len() as u32,
            pbId: user.as_ptr().cast_mut(),
            pwszName: w!("Petika CLI"),
            pwszDisplayName: w!("Petika local vault"),
            ..Default::default()
        };
        let parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: w!("public-key"),
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &parameter as *const _ as *mut _,
        };
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: 6,
            dwTimeoutMilliseconds: 60_000,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            bEnablePrf: 1,
            ..Default::default()
        };
        let mut result = ptr::null_mut();
        // All borrowed buffers outlive this synchronous OS operation.
        let status = unsafe {
            (self.make)(
                GetConsoleWindow(),
                &rp,
                &user,
                &parameters,
                &client,
                &options,
                &mut result,
            )
        };
        if status < 0 || result.is_null() {
            return Err(DENIED.into());
        }
        // The API owns this result until FreeCredentialAttestation.
        unsafe {
            let record = &*result;
            let rp_hash = ring::digest::digest(&ring::digest::SHA256, b"petika.local");
            let id = if record.dwVersion >= 5
                && record.bPrfEnabled != 0
                && record.dwUsedTransport == WEBAUTHN_CTAP_TRANSPORT_INTERNAL
                && (1..=1024).contains(&record.cbCredentialId)
                && !record.pbCredentialId.is_null()
                && record.cbAuthenticatorData >= 37
                && !record.pbAuthenticatorData.is_null()
                && std::slice::from_raw_parts(record.pbAuthenticatorData, 32) == rp_hash.as_ref()
                && *record.pbAuthenticatorData.add(32) & LOCAL_VERIFICATION_MASK
                    == REQUIRED_VERIFICATION_FLAGS
            {
                Ok(std::slice::from_raw_parts(
                    record.pbCredentialId,
                    record.cbCredentialId as usize,
                )
                .to_vec())
            } else {
                Err(INVALID.into())
            };
            (self.free_attestation)(result);
            id
        }
    }

    fn prf(&self, id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let mut json = client_data("webauthn.get")?;
        let client = client(&mut json);
        let credential = WEBAUTHN_CREDENTIAL {
            dwVersion: 1,
            cbId: id.len() as u32,
            pbId: id.as_ptr().cast_mut(),
            pwszCredentialType: w!("public-key"),
        };
        let mut evaluation = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: salt.as_ptr().cast_mut(),
            ..Default::default()
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut evaluation,
            ..Default::default()
        };
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: 6,
            dwTimeoutMilliseconds: 60_000,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 1,
                pCredentials: &credential as *const _ as *mut _,
            },
            pHmacSecretSaltValues: &mut salts,
            ..Default::default()
        };
        let mut result = ptr::null_mut();
        // No reusable approval context is retained between commands.
        let status = unsafe {
            (self.get)(
                GetConsoleWindow(),
                w!("petika.local"),
                &client,
                &options,
                &mut result,
            )
        };
        if status < 0 || result.is_null() {
            return Err(DENIED.into());
        }
        // Validate the OS assertion and copy its PRF into zeroizing storage before
        // freeing the API allocation. The AEAD below also authenticates this key.
        unsafe {
            let assertion = &*result;
            let output = (|| -> Result<Zeroizing<Vec<u8>>> {
                let rp_hash = ring::digest::digest(&ring::digest::SHA256, b"petika.local");
                if assertion.dwVersion < 4
                    || assertion.pHmacSecret.is_null()
                    || assertion.cbAuthenticatorData < 37
                    || assertion.pbAuthenticatorData.is_null()
                    || assertion.dwUsedTransport != WEBAUTHN_CTAP_TRANSPORT_INTERNAL
                    || std::slice::from_raw_parts(assertion.pbAuthenticatorData, 32)
                        != rp_hash.as_ref()
                    || assertion.Credential.cbId as usize != id.len()
                    || assertion.Credential.pbId.is_null()
                    || std::slice::from_raw_parts(assertion.Credential.pbId, id.len()) != id
                    || *assertion.pbAuthenticatorData.add(32) & LOCAL_VERIFICATION_MASK
                        != REQUIRED_VERIFICATION_FLAGS
                {
                    return Err(INVALID.into());
                }
                let prf = &*assertion.pHmacSecret;
                if prf.cbFirst != 32 || prf.pbFirst.is_null() {
                    return Err(UNAVAILABLE.into());
                }
                let bytes = std::slice::from_raw_parts_mut(prf.pbFirst, 32);
                let output = Zeroizing::new(bytes.to_vec());
                Ok(output)
            })();
            if assertion.dwVersion >= 3 && !assertion.pHmacSecret.is_null() {
                let prf = &*assertion.pHmacSecret;
                if prf.cbFirst == 32 && !prf.pbFirst.is_null() {
                    std::slice::from_raw_parts_mut(prf.pbFirst, 32).zeroize();
                }
            }
            (self.free_assertion)(result);
            output
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    version: u8,
    id: Vec<u8>,
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

impl Credential {
    fn aad(&self) -> Vec<u8> {
        let mut binding = b"petika.cli.local-vault.windows-hello-prf.v1".to_vec();
        binding.extend(&self.id);
        binding.extend(self.salt);
        binding
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "OS random source failed")?;
    Ok(bytes)
}

fn client_data(kind: &str) -> Result<Vec<u8>> {
    let challenge = random::<32>()?;
    let challenge: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(serde_json::to_vec(&serde_json::json!({
        "type":kind, "challenge":challenge, "origin":"https://petika.local"
    }))?)
}

fn client(json: &mut [u8]) -> WEBAUTHN_CLIENT_DATA {
    WEBAUTHN_CLIENT_DATA {
        dwVersion: 1,
        cbClientDataJSON: json.len() as u32,
        pbClientDataJSON: json.as_mut_ptr(),
        pwszHashAlgId: w!("SHA-256"),
    }
}

pub(super) fn available() -> Result<()> {
    Api::load().map(|_| ())
}

pub(super) fn run(operation: &str, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let api = Api::load()?;
    match operation {
        "enroll" => {
            if input.len() != 32 {
                return Err(INVALID.into());
            }
            let mut record = Credential {
                version: 1,
                id: api.create()?,
                salt: random()?,
                nonce: random()?,
                ciphertext: input.to_vec(),
            };
            let prf = api.prf(&record.id, &record.salt)?;
            let key = LessSafeKey::new(
                UnboundKey::new(&aead::CHACHA20_POLY1305, &prf).map_err(|_| INVALID)?,
            );
            let aad = record.aad();
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(record.nonce),
                Aad::from(aad),
                &mut record.ciphertext,
            )
            .map_err(|_| INVALID)?;
            Ok(Zeroizing::new(serde_json::to_vec(&record)?))
        }
        "unlock" => {
            let mut record: Credential = serde_json::from_slice(input)?;
            if record.version != 1
                || record.id.is_empty()
                || record.id.len() > 1024
                || record.ciphertext.len() != 48
            {
                return Err(INVALID.into());
            }
            let prf = api.prf(&record.id, &record.salt)?;
            let key = LessSafeKey::new(
                UnboundKey::new(&aead::CHACHA20_POLY1305, &prf).map_err(|_| INVALID)?,
            );
            let aad = record.aad();
            let opened = key
                .open_in_place(
                    Nonce::assume_unique_for_key(record.nonce),
                    Aad::from(aad),
                    &mut record.ciphertext,
                )
                .map_err(|_| INVALID)?;
            let key = Zeroizing::new(opened.to_vec());
            record.ciphertext.zeroize();
            Ok(key)
        }
        _ => Err(INVALID.into()),
    }
}
