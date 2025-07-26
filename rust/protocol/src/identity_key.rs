//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over cryptographic primitives from [`libsignal_core::curve`] to represent a user.

#![warn(missing_docs)]

use prost::Message;
use rand::{CryptoRng, Rng};

use crate::{proto, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

// Used for domain separation between alternate-identity signatures and other key-to-key signatures.
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1: &[u8] = &[0xFF; 32];
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2: &[u8] = b"Signal_PNI_Signature";

/// A public key that represents the identity of a user.
///
/// Wrapper for [`PublicKey`].
#[derive(
    Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, derive_more::From, derive_more::Into,
)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    /// Initialize a public-facing identity from a public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Return the public key representing this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return an owned byte slice which can be deserialized with [`Self::decode`].
    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    /// Deserialize a public identity from a byte slice.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self { public_key: pk })
    }

    /// Given a trusted identity `self`, verify that `other` represents an alternate identity for
    /// this user.
    ///
    /// `signature` must be calculated from [`IdentityKeyPair::sign_alternate_identity`].
    pub fn verify_alternate_identity(&self, other: &IdentityKey, signature: &[u8]) -> Result<bool> {
        Ok(self.public_key.verify_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            signature,
        ))
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

/// The private identity of a user.
///
/// Can be converted to and from [`KeyPair`].
#[derive(Copy, Clone)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    /// Create a key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    /// Generate a random new EC identity from randomness in `csprng`.
    ///
    /// TODO: This only generates EC (Curve25519) keys. Use `generate_dilithium` for PQC.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    /// Generate a random new Dilithium identity from randomness in `csprng`.
    pub fn generate_dilithium<R: CryptoRng + Rng>(_csprng: &mut R) -> Self {
        let private_key = PrivateKey::generate_dilithium2().expect("Failed to generate Dilithium2 key");
        let public_key = private_key.public_key().expect("Failed to get public key from Dilithium2 private key");
        let identity_key = IdentityKey::new(public_key);
        Self {
            identity_key,
            private_key,
        }
    }

    /// Return the public identity of this user.
    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Return the public key that defines this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        self.identity_key.public_key()
    }

    /// Return the private key that defines this identity.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Return a byte slice which can later be deserialized with [`Self::try_from`].
    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        };

        let result = structure.encode_to_vec();
        result.into_boxed_slice()
    }

    /// Generate a signature claiming that `other` represents the same user as `self`.
    pub fn sign_alternate_identity<R: Rng + CryptoRng>(
        &self,
        other: &IdentityKey,
        rng: &mut R,
    ) -> Result<Box<[u8]>> {
        Ok(self.private_key.calculate_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            rng,
        )?)
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: PrivateKey::deserialize(&structure.private_key)?,
        })
    }
}

impl TryFrom<PrivateKey> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(private_key: PrivateKey) -> Result<Self> {
        let identity_key = IdentityKey::new(private_key.public_key()?);
        Ok(Self::new(identity_key, private_key))
    }
}

impl From<KeyPair> for IdentityKeyPair {
    fn from(value: KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
        }
    }
}

impl From<IdentityKeyPair> for KeyPair {
    fn from(value: IdentityKeyPair) -> Self {
        Self::new(value.identity_key.into(), value.private_key)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..])?;
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().key_type(),
            deserialized_identity_key_pair.private_key().key_type()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );

        Ok(())
    }

    #[test]
    fn test_generate_dilithium_identity_key_pair() {
        use rand::rngs::OsRng;
        use libsignal_core::curve::KeyType;
        
        let dilithium_identity = IdentityKeyPair::generate_dilithium(&mut OsRng.unwrap_err());
        assert_eq!(dilithium_identity.private_key().key_type(), KeyType::Dilithium2);
        assert_eq!(dilithium_identity.public_key().key_type(), KeyType::Dilithium2);
    }

    #[test]
    fn test_mixed_ec_dilithium_identity_keys() {
        use rand::rngs::OsRng;
        use libsignal_core::curve::KeyType;
        
        // Generate both EC and Dilithium identity key pairs
        let ec_identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let dilithium_identity = IdentityKeyPair::generate_dilithium(&mut OsRng.unwrap_err());
        
        // Verify key types
        assert_eq!(ec_identity.private_key().key_type(), KeyType::Djb);
        assert_eq!(ec_identity.public_key().key_type(), KeyType::Djb);
        assert_eq!(dilithium_identity.private_key().key_type(), KeyType::Dilithium2);
        assert_eq!(dilithium_identity.public_key().key_type(), KeyType::Dilithium2);
        
        // Test serialization of both
        let ec_serialized = ec_identity.serialize();
        let dilithium_serialized = dilithium_identity.serialize();
        
        // Different lengths for different key types
        assert_ne!(ec_serialized.len(), dilithium_serialized.len());
        
        // Test deserialization
        let ec_deserialized = IdentityKeyPair::try_from(ec_serialized.as_ref()).expect("EC deserialization failed");
        let dilithium_deserialized = IdentityKeyPair::try_from(dilithium_serialized.as_ref()).expect("Dilithium deserialization failed");
        
        // Verify key types after deserialization
        assert_eq!(ec_deserialized.private_key().key_type(), KeyType::Djb);
        assert_eq!(dilithium_deserialized.private_key().key_type(), KeyType::Dilithium2);
    }

    #[test]
    fn test_dilithium_signature_verification() {
        use rand::rngs::OsRng;
        
        let dilithium_identity = IdentityKeyPair::generate_dilithium(&mut OsRng.unwrap_err());
        let message = b"Test message for Dilithium signature";
        
        // Sign with Dilithium private key
        let signature = dilithium_identity.private_key().calculate_signature(message, &mut OsRng.unwrap_err()).expect("Dilithium signing failed");
        
        // Verify with Dilithium public key
        let verification_result = dilithium_identity.public_key().verify_signature(message, &signature);
        assert!(verification_result, "Dilithium signature verification failed");
        
        // Test with wrong message should fail
        let wrong_message = b"Wrong message";
        let wrong_verification = dilithium_identity.public_key().verify_signature(wrong_message, &signature);
        assert!(!wrong_verification, "Dilithium signature should fail for wrong message");
    }

    #[test]
    fn test_cross_key_type_signature_failure() {
        use rand::rngs::OsRng;
        
        let ec_identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let dilithium_identity = IdentityKeyPair::generate_dilithium(&mut OsRng.unwrap_err());
        let message = b"Test message";
        
        // Sign with EC key
        let ec_signature = ec_identity.private_key().calculate_signature(message, &mut OsRng.unwrap_err()).expect("EC signing failed");
        
        // Try to verify EC signature with Dilithium key (should fail)
        let cross_verification = dilithium_identity.public_key().verify_signature(message, &ec_signature);
        assert!(!cross_verification, "Cross key type verification should fail");
    }

    #[test]
    fn test_alternate_identity_signing() -> Result<()> {
        let mut rng = OsRng.unwrap_err();
        let primary = IdentityKeyPair::generate(&mut rng);
        let secondary = IdentityKeyPair::generate(&mut rng);

        let signature = secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);
        // Not symmetric.
        assert!(!primary
            .identity_key()
            .verify_alternate_identity(secondary.identity_key(), &signature)?);

        let another_signature =
            secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert_ne!(signature, another_signature);
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &another_signature)?);

        let unrelated = IdentityKeyPair::generate(&mut rng);
        assert!(!secondary
            .identity_key()
            .verify_alternate_identity(unrelated.identity_key(), &signature)?);
        assert!(!unrelated
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);

        Ok(())
    }
}
