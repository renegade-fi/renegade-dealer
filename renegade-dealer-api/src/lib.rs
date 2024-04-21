//! API type implementations for the Renegade Dealer

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

use serde::{Deserialize, Serialize};

/// A type alias for the request
pub type RequestId = uuid::Uuid;

/// The curve used for testing
type Curve = ark_bn254::G1Projective;
/// A type alias for a scalar
type Scalar = ark_mpc::algebra::Scalar<Curve>;
/// A type alias for a scalar share
type ScalarShare = ark_mpc::algebra::ScalarShare<Curve>;

/// A request for offline phase randomness from the dealer
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct DealerRequest {
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
