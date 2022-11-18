use core::{fmt::Display, iter::repeat_with};

use hmac::{Hmac, Mac};

#[derive(Debug)]
pub struct Secret(pub Vec<u8>);

#[allow(clippy::new_without_default)]
impl Secret {
    pub fn new() -> Self {
        Self(repeat_with(|| fastrand::u8(..)).take(20).collect())
    }

    pub fn from<S: AsRef<str>>(secret: S) -> Self {
        Self(base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret.as_ref()).unwrap())
    }

    pub fn get_base32(&self) -> String {
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.0)
    }
}

#[derive(Debug, PartialEq)]
pub enum Algorithm {
    SHA256,
    SHA512,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::SHA256 => f.write_str("SHA256"),
            Algorithm::SHA512 => f.write_str("SHA512"),
        }
    }
}

impl Algorithm {
    fn hash<D>(mut digest: D, data: &[u8]) -> Vec<u8>
    where
        D: Mac,
    {
        digest.update(data);
        digest.finalize().into_bytes().to_vec()
    }

    fn sign(&self, key: &Secret, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::SHA256 => {
                Algorithm::hash(<Hmac<sha2::Sha256> as Mac>::new_from_slice(&key.0).unwrap(), data)
            }
            Algorithm::SHA512 => {
                Algorithm::hash(<Hmac<sha2::Sha512> as Mac>::new_from_slice(&key.0).unwrap(), data)
            }
        }
    }
}

#[derive(Debug)]
pub struct TOTP<S> {
    pub alg: Algorithm,
    pub digits: usize,
    pub skew: u8,
    pub step: u64,
    pub secret: Secret,
    pub issuer: S,
    pub account: S,
}

impl<S: AsRef<str>> TOTP<S> {
    pub fn new(secret: Secret, issuer: S, account: S) -> TOTP<S> {
        let secret = secret;
        assert!(
            !(secret.0.len() < 16 || issuer.as_ref().contains(':') || account.as_ref().contains(':')),
            "wrong format"
        );
        let alg = Algorithm::SHA256;
        let digits = 6;
        let skew = 1;
        let step = 30;
        TOTP { alg, digits, skew, step, secret, issuer, account }
    }

    fn sign(&self, time: u64) -> Vec<u8> {
        self.alg.sign(&self.secret, &(time / self.step).to_be_bytes())
    }

    pub fn generate(&self, time: u64) -> String {
        let result: &[u8] = &self.sign(time);
        let offset = (result.last().unwrap() & 15) as usize;
        let result = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!("{1:00$}", self.digits, result % 10_u32.pow(self.digits as u32))
    }

    pub fn get_url(&self) -> String {
        let label = format!("{0}:{1}?issuer={0}&", self.issuer.as_ref(), self.account.as_ref());
        let secret = self.secret.get_base32();
        format!("otpauth://totp/{label}secret={secret}&digits={}&algorithm={}", self.digits, self.alg)
    }

    pub fn verify(&self, token: &str, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..self.skew * 2 + 1 {
            let step_time = (basestep + (i as u64)) * self.step;
            if self.generate(step_time) == token {
                return true;
            }
        }
        false
    }
}
