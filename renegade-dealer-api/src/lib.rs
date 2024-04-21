//! API type implementations for the Renegade Dealer

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

use k256::PublicKey;
use serde::{Deserialize, Serialize};

/// Serialize a public key
use serde::{de::Error as DeError, Deserializer, Serializer};

/// Custom serialization for `PublicKey`
fn serialize_key<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = key.to_sec1_bytes().to_vec();
    serializer.serialize_bytes(&bytes)
}

/// Custom deserialization for `PublicKey`
fn deserialize_key<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = <Vec<u8>>::deserialize(deserializer)?;
    PublicKey::from_sec1_bytes(&bytes)
        .map_err(|e| DeError::custom(format!("Invalid public key bytes: {}", e)))
}

// -------------
// | Api Types |
// -------------

/// The header name for the party ID
pub const PARTY_ID_HEADER: &str = "X-Party-Id";
/// The header name for the signature
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// A type alias for the request
pub type RequestId = uuid::Uuid;

/// The curve used for testing
type Curve = ark_bn254::G1Projective;
/// A type alias for a scalar
type Scalar = ark_mpc::algebra::Scalar<Curve>;
/// A type alias for a scalar share
type ScalarShare = ark_mpc::algebra::ScalarShare<Curve>;

/// A response to a bad request
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error code associated with the response
    pub code: u32,
    /// The error message associated with the response
    pub message: &'static str,
}

/// A request for offline phase randomness from the dealer
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct DealerRequest {
    /// The public key of the first party in the exchange
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    pub first_party_key: PublicKey,
    /// The public key of the second party in the exchange
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    pub second_party_key: PublicKey,

    /// The number of random bits to generate
    #[serde(default)]
    pub n_random_bits: u32,
    /// The number of shared random values to generate  
    #[serde(default)]
    pub n_random_values: u32,
    /// The number of input masks to generate
    ///
    /// An input mask is a random value wherein one party knows the cleartext
    /// value, allowing them to mask an input with the share
    #[serde(default)]
    pub n_input_masks: u32,
    /// The number of inverse pairs to generate
    #[serde(default)]
    pub n_inverse_pairs: u32,
    /// The number of Beaver triples to generate
    #[serde(default)]
    pub n_triples: u32,
}

impl DealerRequest {
    /// Create a new request from a pair of keys
    pub fn new(first_party_key: PublicKey, second_party_key: PublicKey) -> Self {
        Self {
            first_party_key,
            second_party_key,
            n_random_bits: 0,
            n_random_values: 0,
            n_input_masks: 0,
            n_inverse_pairs: 0,
            n_triples: 0,
        }
    }

    /// Return the total number of requested values
    pub fn total_values(&self) -> u32 {
        self.n_random_bits
            + self.n_random_values
            + self.n_input_masks
            + self.n_inverse_pairs
            + self.n_triples
    }

    /// Set the number of random bits to generate
    pub fn with_n_random_bits(mut self, n_random_bits: u32) -> Self {
        self.n_random_bits = n_random_bits;
        self
    }

    /// Set the number of shared random values to generate
    pub fn with_n_random_values(mut self, n_random_values: u32) -> Self {
        self.n_random_values = n_random_values;
        self
    }

    /// Set the number of input masks to generate
    pub fn with_n_input_masks(mut self, n_input_masks: u32) -> Self {
        self.n_input_masks = n_input_masks;
        self
    }

    /// Set the number of inverse pairs to generate
    pub fn with_n_inverse_pairs(mut self, n_inverse_pairs: u32) -> Self {
        self.n_inverse_pairs = n_inverse_pairs;
        self
    }

    /// Set the number of Beaver triples to generate
    pub fn with_n_triples(mut self, n_triples: u32) -> Self {
        self.n_triples = n_triples;
        self
    }
}

/// A response from the Dealer
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DealerResponse {
    /// The share of the mac key
    pub mac_key_share: Scalar,
    /// The random bits
    pub random_bits: Vec<ScalarShare>,
    /// The random values
    pub random_values: Vec<ScalarShare>,
    /// The input masks
    ///
    /// Holds the plaintext values of the input masks, the shares of these
    /// cleartext values, and the shares of the counterparty's input masks in
    /// order
    pub input_masks: (Vec<Scalar>, Vec<ScalarShare>, Vec<ScalarShare>),
    /// The inverse pairs
    ///
    /// Random values r, r^-1 in the scalar field
    pub inverse_pairs: (Vec<ScalarShare>, Vec<ScalarShare>),
    /// The triples
    pub beaver_triples: (Vec<ScalarShare>, Vec<ScalarShare>, Vec<ScalarShare>),
}

impl DealerResponse {
    /// Set the bits
    pub fn set_random_bits(&mut self, bits: Vec<ScalarShare>) {
        self.random_bits = bits;
    }

    /// Set the random values
    pub fn set_random_values(&mut self, values: Vec<ScalarShare>) {
        self.random_values = values;
    }

    /// Set the input masks
    pub fn set_input_masks(
        &mut self,
        cleartext: Vec<Scalar>,
        shares1: Vec<ScalarShare>,
        shares2: Vec<ScalarShare>,
    ) {
        self.input_masks = (cleartext, shares1, shares2);
    }

    /// Set the inverse pairs
    pub fn set_inverse_pairs(&mut self, r: Vec<ScalarShare>, r_inv: Vec<ScalarShare>) {
        self.inverse_pairs = (r, r_inv);
    }

    /// Set the triples
    pub fn set_triples(&mut self, a: Vec<ScalarShare>, b: Vec<ScalarShare>, c: Vec<ScalarShare>) {
        let n = a.len();
        assert_eq!(n, b.len());
        assert_eq!(n, c.len());

        self.beaver_triples = (a, b, c);
    }
}

#[cfg(test)]
mod test {
    use k256::SecretKey;
    use rand::thread_rng;

    use crate::DealerRequest;

    /// Test serialization + deserialization of the `DealerRequest`
    #[test]
    fn test_req_serialization() {
        let mut rng = thread_rng();
        let key1 = SecretKey::random(&mut rng);
        let key2 = SecretKey::random(&mut rng);

        let req = DealerRequest::new(key1.public_key(), key2.public_key())
            .with_n_triples(100)
            .with_n_input_masks(10);

        let ser = serde_json::to_vec(&req).unwrap();
        let de: DealerRequest = serde_json::from_slice(&ser).unwrap();

        assert_eq!(req, de);
    }
}
