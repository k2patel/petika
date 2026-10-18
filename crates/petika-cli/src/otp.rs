//! Local RFC 6238 codes compatible with the web client's stored setup format.
use crate::Result;
use ring::hmac;
use zeroize::Zeroizing;

pub struct Config {
    key: Zeroizing<Vec<u8>>,
    algorithm: hmac::Algorithm,
    digits: u32,
    pub period: u64,
}
pub struct Code {
    pub value: Zeroizing<String>,
    pub remaining: u64,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = "invalid TOTP setup; use a Base32 key or TOTP link with SHA1/SHA256/SHA512, 6/8 digits, and a 30/60-second period";
        let mut secret = Zeroizing::new(input.trim().to_string());
        let mut algorithm = hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;
        let mut digits = 6;
        let mut period = 30;
        if secret.starts_with("otpauth:") {
            let uri = url::Url::parse(&secret).map_err(|_| invalid)?;
            if uri.scheme() != "otpauth" || uri.host_str() != Some("totp") {
                return Err(invalid.into());
            }
            let parameter = |name: &str| {
                uri.query_pairs()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.into_owned())
            };
            secret = Zeroizing::new(parameter("secret").ok_or(invalid)?);
            algorithm = match parameter("algorithm")
                .as_deref()
                .unwrap_or("SHA1")
                .to_ascii_uppercase()
                .as_str()
            {
                "SHA1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                "SHA256" => hmac::HMAC_SHA256,
                "SHA512" => hmac::HMAC_SHA512,
                _ => return Err(invalid.into()),
            };
            digits = parameter("digits")
                .unwrap_or_else(|| "6".into())
                .parse()
                .map_err(|_| invalid)?;
            period = parameter("period")
                .unwrap_or_else(|| "30".into())
                .parse()
                .map_err(|_| invalid)?;
        }
        let normalized = Zeroizing::new(
            secret
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let normalized = normalized.trim_end_matches('=');
        if !(16..=1024).contains(&normalized.len())
            || ![6, 8].contains(&digits)
            || ![30, 60].contains(&period)
        {
            return Err(invalid.into());
        }
        let mut key = Zeroizing::new(Vec::new());
        let mut buffer = 0u32;
        let mut bits = 0;
        for byte in normalized.bytes() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(invalid.into()),
            };
            buffer = (buffer << 5) | u32::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                key.push((buffer >> bits) as u8);
            }
        }
        if bits > 0 && buffer & ((1 << bits) - 1) != 0 {
            return Err(invalid.into());
        }
        Ok(Self {
            key,
            algorithm,
            digits,
            period,
        })
    }
    pub fn at(&self, seconds: u64) -> Code {
        let key = hmac::Key::new(self.algorithm, &self.key);
        let tag = hmac::sign(&key, &(seconds / self.period).to_be_bytes());
        let bytes = tag.as_ref();
        let offset = usize::from(bytes[bytes.len() - 1] & 15);
        let binary = u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("HMAC offset"))
            & 0x7fff_ffff;
        Code {
            value: Zeroizing::new(format!(
                "{:0width$}",
                binary % 10u32.pow(self.digits),
                width = self.digits as usize
            )),
            remaining: self.period - seconds % self.period,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_vectors_and_remaining_time() {
        let cases = [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        for (i, (algorithm, length)) in [
            (hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, 20),
            (hmac::HMAC_SHA256, 32),
            (hmac::HMAC_SHA512, 64),
        ]
        .into_iter()
        .enumerate()
        {
            let config = Config {
                key: Zeroizing::new(b"1234567890".repeat(7)[..length].to_vec()),
                algorithm,
                digits: 8,
                period: 30,
            };
            for (seconds, expected) in cases {
                let code = config.at(seconds);
                assert_eq!(code.value.as_str(), expected[i]);
                assert_eq!(code.remaining, 30 - seconds % 30);
            }
        }
        let config =
            Config::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=60").unwrap();
        assert_eq!(config.at(59).remaining, 1);
        assert_eq!(config.at(60).remaining, 60);
        assert_eq!(
            Config::parse("jbsw y3dp ehpk 3pxp=")
                .unwrap()
                .at(59)
                .value
                .as_str(),
            "996554"
        );
    }
    #[test]
    fn invalid_setup_never_echoes_the_secret() {
        for value in [
            "secret",
            "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7",
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ] {
            assert!(Config::parse(value).is_err());
        }
    }
}
