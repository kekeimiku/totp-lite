use hmac::{Hmac, Mac};

#[derive(Debug, PartialEq)]
pub enum Algorithm {
    SHA256,
    SHA512,
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Algorithm::SHA256 => f.write_str("SHA256"),
            Algorithm::SHA512 => f.write_str("SHA512"),
        }
    }
}

impl Algorithm {
    fn hash<T: Mac>(mut digest: T, data: &[u8]) -> Vec<u8> {
        digest.update(data);
        digest.finalize().into_bytes().to_vec()
    }

    fn sign<S: AsRef<[u8]>, D: AsRef<[u8]>>(&self, secret: S, data: D) -> Vec<u8> {
        match self {
            Algorithm::SHA256 => Algorithm::hash(
                <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_ref()).unwrap(),
                data.as_ref(),
            ),
            Algorithm::SHA512 => Algorithm::hash(
                <Hmac<sha2::Sha512> as Mac>::new_from_slice(secret.as_ref()).unwrap(),
                data.as_ref(),
            ),
        }
    }
}

#[derive(Debug)]
pub struct TOTP<S, I, A> {
    alg: Algorithm,
    digits: usize,
    skew: u8,
    step: u64,
    secret: S,
    issuer: I,
    account: A,
}

impl<S: AsRef<[u8]>, I: AsRef<str>, A: AsRef<str>> TOTP<S, I, A> {
    pub fn with_default(secret: S, issuer: I, account: A) -> Self {
        assert!(
            !(secret.as_ref().len() < 16 || issuer.as_ref().contains(':') || account.as_ref().contains(':')),
            "wrong format"
        );
        let alg = Algorithm::SHA256;
        let digits = 6;
        let skew = 1;
        let step = 30;
        Self { alg, digits, skew, step, secret, issuer, account }
    }

    pub fn new(alg: Algorithm, digits: usize, skew: u8, step: u64, secret: S, issuer: I, account: A) -> Self {
        assert!(
            !(secret.as_ref().len() < 16
                || (6..=8).contains(&digits)
                || issuer.as_ref().contains(':')
                || account.as_ref().contains(':')),
            "wrong format"
        );

        Self { alg, digits, skew, step, secret, issuer, account }
    }

    pub fn generate(&self, time: u64) -> String {
        let result = self.alg.sign(&self.secret, (time / self.step).to_be_bytes());
        let offset = (result.last().unwrap() & 15) as usize;
        let result = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!("{1:00$}", self.digits, result % 10_u32.pow(self.digits as u32))
    }

    pub fn get_url(&self) -> String {
        let label = format!("{0}:{1}?issuer={0}&", self.issuer.as_ref(), self.account.as_ref());
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, self.secret.as_ref());
        format!("otpauth://totp/{label}secret={secret}&digits={}&algorithm={}", self.digits, self.alg)
    }

    pub fn verify<T: AsRef<str>>(&self, token: T, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..self.skew * 2 + 1 {
            let step_time = (basestep + (i as u64)) * self.step;
            if self.generate(step_time) == token.as_ref() {
                return true;
            }
        }
        false
    }
}
