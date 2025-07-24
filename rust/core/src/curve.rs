//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod curve25519;
mod utils;

use std::cmp::Ordering;
use std::fmt;

use curve25519_dalek::scalar;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;
// === PQC: Dilithium constants (stub values, update as needed) ===
pub const DILITHIUM_PUBLIC_KEY_LENGTH: usize = 1312; // For Dilithium2
pub const DILITHIUM_PRIVATE_KEY_LENGTH: usize = 2528; // For Dilithium2

// --- Add imports for Dilithium2 ---
use dilithium2::{Keypair as Dilithium2Keypair, PublicKey as Dilithium2PublicKey, SecretKey as Dilithium2SecretKey, Signature as Dilithium2Signature};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    Djb,
    Dilithium2, // PQC
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
            KeyType::Dilithium2 => 0x20u8, // Arbitrary, must be unique
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum CurveError {
    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),
}

impl std::error::Error for CurveError {}

impl TryFrom<u8> for KeyType {
    type Error = CurveError;

    fn try_from(x: u8) -> Result<Self, CurveError> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            0x20u8 => Ok(KeyType::Dilithium2),
            t => Err(CurveError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
    DilithiumPublicKey([u8; DILITHIUM_PUBLIC_KEY_LENGTH]), // PQC
}

#[derive(Clone, Copy, Eq, derive_more::From)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        let (key_type, value) = value.split_first().ok_or(CurveError::NoKeyTypeIdentifier)?;
        let key_type = KeyType::try_from(*key_type)?;
        match key_type {
            KeyType::Djb => {
                let (key, tail): (&[u8; curve25519::PUBLIC_KEY_LENGTH], _) = value
                    .split_first_chunk()
                    .ok_or(CurveError::BadKeyLength(KeyType::Djb, value.len() + 1))?;
                if !tail.is_empty() {
                    log::warn!(
                        "ECPublicKey deserialized with {} trailing bytes",
                        tail.len()
                    );
                }
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(*key),
                })
            }
            KeyType::Dilithium2 => {
                let (key, tail): (&[u8; DILITHIUM_PUBLIC_KEY_LENGTH], _) = value
                    .split_first_chunk()
                    .ok_or(CurveError::BadKeyLength(KeyType::Dilithium2, value.len() + 1))?;
                if !tail.is_empty() {
                    log::warn!(
                        "DilithiumPublicKey deserialized with {} trailing bytes",
                        tail.len()
                    );
                }
                Ok(PublicKey {
                    key: PublicKeyData::DilithiumPublicKey(*key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => v,
            PublicKeyData::DilithiumPublicKey(v) => v,
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let (type_byte, value) = match &self.key {
            PublicKeyData::DjbPublicKey(v) => (KeyType::Djb.value(), &v[..]),
            PublicKeyData::DilithiumPublicKey(v) => (KeyType::Dilithium2.value(), &v[..]),
        };
        let mut result = Vec::with_capacity(1 + value.len());
        result.push(type_byte);
        result.extend_from_slice(value);
        result.into_boxed_slice()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                let Ok(signature) = signature.try_into() else {
                    return false;
                };
                curve25519::PrivateKey::verify_signature(pub_key, message, signature)
            }
            PublicKeyData::DilithiumPublicKey(ref pk_bytes) => {
                let pk = match Dilithium2PublicKey::from_bytes(pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };
                let msg = message.concat();
                let sig = match Dilithium2Signature::from_bytes(signature) {
                    Ok(sig) => sig,
                    Err(_) => return false,
                };
                pk.verify(&msg, &sig)
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(ref k) => k.as_ref(),
            PublicKeyData::DilithiumPublicKey(ref k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
            PublicKeyData::DilithiumPublicKey(_) => KeyType::Dilithium2,
        }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        utils::constant_time_cmp(self.key_data(), other.key_data())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    DjbPrivateKey([u8; curve25519::PRIVATE_KEY_LENGTH]),
    DilithiumPrivateKey([u8; DILITHIUM_PRIVATE_KEY_LENGTH]), // PQC
}

#[derive(Clone, Copy, Eq, PartialEq, derive_more::From)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        // For Djb, no type byte; for Dilithium, expect type byte
        if value.len() == curve25519::PRIVATE_KEY_LENGTH {
            // Legacy Djb
            let mut key: [u8; curve25519::PRIVATE_KEY_LENGTH] = value
                .try_into()
                .map_err(|_| CurveError::BadKeyLength(KeyType::Djb, value.len()))?;
            key = scalar::clamp_integer(key);
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey(key),
            })
        } else if value.len() == 1 + DILITHIUM_PRIVATE_KEY_LENGTH && value[0] == KeyType::Dilithium2.value() {
            let key: [u8; DILITHIUM_PRIVATE_KEY_LENGTH] = value[1..]
                .try_into()
                .map_err(|_| CurveError::BadKeyLength(KeyType::Dilithium2, value.len()))?;
            Ok(Self {
                key: PrivateKeyData::DilithiumPrivateKey(key),
            })
        } else {
            Err(CurveError::BadKeyLength(KeyType::Djb, value.len()))
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
            PrivateKeyData::DilithiumPrivateKey(v) => {
                let mut result = Vec::with_capacity(1 + v.len());
                result.push(KeyType::Dilithium2.value());
                result.extend_from_slice(v);
                result
            }
        }
    }

    pub fn generate_dilithium2() -> Result<Self, CurveError> {
        let keypair = Dilithium2Keypair::generate(None);
        let sk_bytes = keypair.secret.as_bytes();
        let mut priv_bytes = [0u8; DILITHIUM_PRIVATE_KEY_LENGTH];
        priv_bytes.copy_from_slice(sk_bytes);
        Ok(PrivateKey {
            key: PrivateKeyData::DilithiumPrivateKey(priv_bytes),
        })
    }

    pub fn public_key(&self) -> Result<PublicKey, CurveError> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(private_key) => {
                let public_key =
                    curve25519::PrivateKey::from(*private_key).derive_public_key_bytes();
                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(public_key)))
            }
            PrivateKeyData::DilithiumPrivateKey(private_key_bytes) => {
                let sk = Dilithium2SecretKey::from_bytes(private_key_bytes)
                    .map_err(|_| CurveError::BadKeyType(KeyType::Dilithium2.value()))?;
                let pk = Dilithium2PublicKey::from_secret_key(&sk);
                let mut pub_bytes = [0u8; DILITHIUM_PUBLIC_KEY_LENGTH];
                pub_bytes.copy_from_slice(pk.as_bytes());
                Ok(PublicKey::new(PublicKeyData::DilithiumPublicKey(pub_bytes)))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(_) => KeyType::Djb,
            PrivateKeyData::DilithiumPrivateKey(_) => KeyType::Dilithium2,
        }
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    pub fn calculate_signature_for_multipart_message<R: CryptoRng + Rng>(
        &self,
        message: &[&[u8]],
        _csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let private_key = curve25519::PrivateKey::from(k);
                Ok(Box::new(private_key.calculate_signature(_csprng, message)))
            }
            PrivateKeyData::DilithiumPrivateKey(ref sk_bytes) => {
                let sk = Dilithium2SecretKey::from_bytes(sk_bytes)
                    .map_err(|_| CurveError::BadKeyType(KeyType::Dilithium2.value()))?;
                let pk = Dilithium2PublicKey::from_secret_key(&sk);
                let keypair = Dilithium2Keypair { public: pk, secret: sk };
                let msg = message.concat();
                let signature = keypair.sign(&msg);
                Ok(signature.as_bytes().to_vec().into_boxed_slice())
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let private_key = curve25519::PrivateKey::from(priv_key);
                Ok(Box::new(private_key.calculate_agreement(&pub_key)))
            }
            // No agreement for Dilithium
            _ => Err(CurveError::BadKeyType(KeyType::Dilithium2.value())),
        }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let private_key = curve25519::PrivateKey::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::DjbPublicKey(
            private_key.derive_public_key_bytes(),
        ));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey(
            private_key.private_key_bytes(),
        ));

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Self, CurveError> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_agreement(their_key)
    }
}

impl TryFrom<PrivateKey> for KeyPair {
    type Error = CurveError;

    fn try_from(value: PrivateKey) -> Result<Self, CurveError> {
        let public_key = value.public_key()?;
        Ok(Self::new(public_key, value))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;

    #[test]
    fn test_generate_dilithium_identity_key_pair() {
        // This test will fail until Dilithium key generation is implemented
        let dilithium_identity = IdentityKeyPair::generate_dilithium(&mut OsRng.unwrap_err());
        let msg = b"test message";
        let sig = dilithium_identity.private_key().calculate_signature_for_multipart_message(&[msg.as_ref()], &mut OsRng.unwrap_err()).unwrap();
        assert!(dilithium_identity.public_key().verify_signature_for_multipart_message(&[msg.as_ref()], &sig));
    }

    #[test]
    fn test_large_signatures() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature));

        assert!(public_key
            .verify_signature_for_multipart_message(&[&message[..7], &message[7..]], &signature));

        let signature = key_pair
            .private_key
            .calculate_signature_for_multipart_message(
                &[&message[..20], &message[20..]],
                &mut csprng,
            )?;
        assert!(public_key.verify_signature(&message, &signature));

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..])?;

        assert!(PublicKey::try_from(&serialized_public[1..]).is_err());
        assert!(PublicKey::try_from(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(PublicKey::try_from(&bad_key_type[..]).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = PublicKey::try_from(&extra_space[..]);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }

    #[test]
    fn curve_error_impls_std_error() {
        let error = CurveError::BadKeyType(u8::MAX);
        let error = Box::new(error) as Box<dyn std::error::Error>;
        assert_matches!(error.downcast_ref(), Some(CurveError::BadKeyType(_)));
    }
}
