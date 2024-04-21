//! The dealer implementation
//!
//! Separated from the main API server to give a "stateless" implementation of
//! the server that merely delegates requests to the dealer
//!
//! The dealer aggregates requests between matching parties and generates
//! offline phase results

use ark_mpc::network::PartyId;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver as Receiver, UnboundedSender as Sender,
};

use renegade_dealer_api::{DealerRequest, DealerResponse, RequestId};
use uuid::Uuid;

use crate::BadRequestError;

// ---------
// | Types |
// ---------

/// The curve that the server generates scalars for
type Curve = ark_bn254::G1Projective;
/// A type alias for a scalar over the correct curve
type Scalar = ark_mpc::algebra::Scalar<Curve>;
/// A type alias for a scalar share over the correct curve
type ScalarShare = ark_mpc::algebra::ScalarShare<Curve>;

/// A sender to the Dealer's queue
pub type DealerSender = Sender<DealerJob>;
/// A receiver from the Dealer's queue
pub type DealerReceiver = Receiver<DealerJob>;
/// Create a new sender and receiver
pub fn create_dealer_sender_receiver() -> (DealerSender, DealerReceiver) {
    unbounded_channel()
}

/// The response channel sender from the dealer
pub type ResponseSender = Sender<Result<DealerResponse, BadRequestError>>;
/// The response channel receiver from the dealer
pub type ResponseReceiver = Receiver<Result<DealerResponse, BadRequestError>>;
/// Create a new sender and receiver
pub fn create_response_sender_receiver() -> (ResponseSender, ResponseReceiver) {
    unbounded_channel()
}

/// The job received by a Dealer to handle a pair of requests
pub struct DealerJob {
    /// The request ID
    pub request_id: RequestId,
    /// The id of the requesting party
    pub party_id: PartyId,
    /// The request
    pub request: DealerRequest,
    /// The channel on which to respond
    pub chan: ResponseSender,
}

impl DealerJob {
    /// Constructor
    pub fn new(
        request_id: RequestId,
        party_id: PartyId,
        request: DealerRequest,
        chan: ResponseSender,
    ) -> Self {
        Self { request_id, party_id, request, chan }
    }
}

// -------------------------
// | Dealer Implementation |
// -------------------------

/// The dealer, handles requests wherein two parties connect and are dealt
/// correlated randomness implementing the SPDZ offline phase
#[derive(Clone)]
pub struct Dealer {
    /// The map of all open requests
    ///
    /// Maps request ID to the request
    pub open_requests: Arc<Mutex<HashMap<Uuid, DealerJob>>>,
}

impl Dealer {
    /// Start a dealer implementation
    pub fn start(job_queue: DealerReceiver) {
        let self_ = Self { open_requests: Arc::new(Mutex::new(HashMap::new())) };
        tokio::spawn(async move {
            self_.run(job_queue).await;
        });
    }

    /// Main loop
    async fn run(self, mut job_queue: DealerReceiver) {
        loop {
            let request = job_queue.recv().await.unwrap();
            let self_ = self.clone();
            tokio::spawn(async move {
                self_.handle_request(request);
            });
        }
    }

    /// Handle a request
    fn handle_request(&self, request: DealerJob) {
        // Lock the requests
        let id = request.request_id;
        let mut open_requests = self.open_requests.lock().unwrap();
        if let Some(existing_req) = open_requests.remove(&id) {
            assert_eq!(existing_req.request, request.request);

            // Requests should be from different parties
            if existing_req.party_id == request.party_id {
                let err = BadRequestError("Duplicate party ID");
                request.chan.send(Err(err.clone())).unwrap();
                existing_req.chan.send(Err(err)).unwrap();
                return;
            }

            Self::handle_ready_pair(&existing_req, &request);
        } else {
            open_requests.insert(id, request);
        }
    }

    /// Handle a pair of requests that are ready for setup
    fn handle_ready_pair(req1: &DealerJob, req2: &DealerJob) {
        let mut rng = thread_rng();
        let req = &req1.request;

        // Generate the mac key
        let mac_key = Scalar::random(&mut rng);
        let mac_share1 = Scalar::random(&mut rng);
        let mac_share2 = mac_key - mac_share1;

        let mut resp1 = DealerResponse { mac_key_share: mac_share1, ..Default::default() };
        let mut resp2 = DealerResponse { mac_key_share: mac_share2, ..Default::default() };

        // Setup the values
        Self::gen_random_bits(req.n_random_bits as usize, mac_key, &mut resp1, &mut resp2);
        Self::gen_random_values(req.n_random_values as usize, mac_key, &mut resp1, &mut resp2);
        Self::gen_input_masks(req.n_input_masks as usize, mac_key, &mut resp1, &mut resp2);
        Self::gen_inverse_pairs(req.n_inverse_pairs as usize, mac_key, &mut resp1, &mut resp2);
        Self::gen_triples(req.n_triples as usize, mac_key, &mut resp1, &mut resp2);

        req1.chan.send(Ok(resp1)).unwrap();
        req2.chan.send(Ok(resp2)).unwrap();
    }

    // ------------------------------------
    // | Correlated Randomness Generation |
    // ------------------------------------

    /// Setup the random bits of the response
    ///
    /// I.e. shares of values in {0, 1}
    fn gen_random_bits(
        n: usize,
        mac_key: Scalar,
        resp1: &mut DealerResponse,
        resp2: &mut DealerResponse,
    ) {
        let mut rng = thread_rng();
        let bits = (0..n).map(|_| Scalar::from(rng.gen_bool(0.5 /* p */))).collect_vec();
        let (share1, share2) = Self::gen_authenticated_secret_shares(mac_key, &bits);

        resp1.set_random_bits(share1);
        resp2.set_random_bits(share2);
    }

    /// Setup the shared random values of the response
    fn gen_random_values(
        n: usize,
        mac_key: Scalar,
        resp1: &mut DealerResponse,
        resp2: &mut DealerResponse,
    ) {
        let mut rng = thread_rng();
        let values = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let (share1, share2) = Self::gen_authenticated_secret_shares(mac_key, &values);

        resp1.set_random_values(share1);
        resp2.set_random_values(share2);
    }

    /// Generate input masks for the response
    fn gen_input_masks(
        n: usize,
        mac_key: Scalar,
        resp1: &mut DealerResponse,
        resp2: &mut DealerResponse,
    ) {
        let mut rng = thread_rng();
        let masks1 = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let masks2 = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

        let (mask1_share1, mask1_share2) = Self::gen_authenticated_secret_shares(mac_key, &masks1);
        let (mask2_share1, mask2_share2) = Self::gen_authenticated_secret_shares(mac_key, &masks2);

        resp1.set_input_masks(masks1, mask1_share1, mask2_share1);
        resp2.set_input_masks(masks2, mask2_share2, mask1_share2);
    }

    /// Setup the inverse pairs of the response
    fn gen_inverse_pairs(
        n: usize,
        mac_key: Scalar,
        resp1: &mut DealerResponse,
        resp2: &mut DealerResponse,
    ) {
        let mut rng = thread_rng();
        let r = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let r_inv = r.iter().map(|r| r.inverse()).collect_vec();

        let (r_shares1, r_shares2) = Self::gen_authenticated_secret_shares(mac_key, &r);
        let (r_inv_shares1, r_inv_shares2) = Self::gen_authenticated_secret_shares(mac_key, &r_inv);

        resp1.set_inverse_pairs(r_shares1, r_inv_shares1);
        resp2.set_inverse_pairs(r_shares2, r_inv_shares2);
    }

    /// Setup the Beaver triples of the response
    ///
    /// These are vectors of values a, b, c such that a * b = c
    fn gen_triples(
        n: usize,
        mac_key: Scalar,
        resp1: &mut DealerResponse,
        resp2: &mut DealerResponse,
    ) {
        let mut rng = thread_rng();
        let a = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect_vec();

        let (a_shares1, a_shares2) = Self::gen_authenticated_secret_shares(mac_key, &a);
        let (b_shares1, b_shares2) = Self::gen_authenticated_secret_shares(mac_key, &b);
        let (c_shares1, c_shares2) = Self::gen_authenticated_secret_shares(mac_key, &c);

        resp1.set_triples(a_shares1, b_shares1, c_shares1);
        resp2.set_triples(a_shares2, b_shares2, c_shares2);
    }

    // -----------
    // | Helpers |
    // -----------

    /// Generate authenticated secret shares of a given set of values
    fn gen_authenticated_secret_shares(
        mac_key: Scalar,
        values: &[Scalar],
    ) -> (Vec<ScalarShare>, Vec<ScalarShare>) {
        let macs = Self::compute_macs(mac_key, values);
        let (shares1, shares2) = Self::gen_secret_shares(values);
        let (mac_shares1, mac_shares2) = Self::gen_secret_shares(&macs);

        // Collect into shares
        (Self::collect_shares(&shares1, &mac_shares1), Self::collect_shares(&shares2, &mac_shares2))
    }

    /// Compute the macs of a set of values
    fn compute_macs(mac_key: Scalar, values: &[Scalar]) -> Vec<Scalar> {
        values.iter().map(|v| v * mac_key).collect_vec()
    }

    /// Generate secret shares of a given set of values
    fn gen_secret_shares(values: &[Scalar]) -> (Vec<Scalar>, Vec<Scalar>) {
        let mut rng = thread_rng();
        let mut share1 = Vec::with_capacity(values.len());
        let mut share2 = Vec::with_capacity(values.len());
        for value in values {
            let share = Scalar::random(&mut rng);
            share1.push(share);
            share2.push(value - share);
        }

        (share1, share2)
    }

    /// Collect a set of values and macs into a vector of shares
    fn collect_shares(values: &[Scalar], macs: &[Scalar]) -> Vec<ScalarShare> {
        let mut shares = Vec::with_capacity(values.len());
        for (value, mac) in values.iter().zip(macs.iter()) {
            shares.push(ScalarShare::new(*value, *mac));
        }

        shares
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::{PARTY0, PARTY1};
    use itertools::{izip, Itertools};
    use k256::SecretKey;
    use rand::thread_rng;
    use renegade_dealer_api::{DealerRequest, DealerResponse};
    use uuid::Uuid;

    use super::{
        create_dealer_sender_receiver, create_response_sender_receiver, Dealer, DealerJob, Scalar,
        ScalarShare,
    };

    // -----------
    // | Helpers |
    // -----------

    /// Get a mock dealer request
    fn mock_dealer_req(n: u32) -> DealerRequest {
        let mut rng = thread_rng();
        let key1 = SecretKey::random(&mut rng);
        let key2 = SecretKey::random(&mut rng);

        DealerRequest::new(key1.public_key(), key2.public_key())
            .with_n_triples(n)
            .with_n_input_masks(n)
            .with_n_inverse_pairs(n)
            .with_n_random_bits(n)
            .with_n_random_values(n)
    }

    /// Run a mock dealer
    async fn get_mock_dealer_response(n: u32) -> (DealerResponse, DealerResponse) {
        let (send, recv) = create_dealer_sender_receiver();
        Dealer::start(recv);

        let (send1, mut recv1) = create_response_sender_receiver();
        let (send2, mut recv2) = create_response_sender_receiver();
        let rid = Uuid::new_v4();
        let req = mock_dealer_req(n);

        // Simulate two clients
        let job1 = DealerJob::new(rid, PARTY0, req.clone(), send1);
        let job2 = DealerJob::new(rid, PARTY1, req, send2);

        send.send(job1).unwrap();
        send.send(job2).unwrap();

        // Get two responses
        (recv1.recv().await.unwrap().unwrap(), recv2.recv().await.unwrap().unwrap())
    }

    /// Check that the macs correctly authenticate the given pairs of shares
    /// under the given key
    ///
    /// Return the recovered values
    fn recover_and_check_macs(
        mac_key: Scalar,
        share1: &[ScalarShare],
        share2: &[ScalarShare],
    ) -> Vec<Scalar> {
        let vals =
            share1.iter().zip(share2.iter()).map(|(v1, v2)| v1.share() + v2.share()).collect_vec();
        let macs =
            share1.iter().zip(share2.iter()).map(|(v1, v2)| v1.mac() + v2.mac()).collect_vec();
        let expected_macs = vals.iter().map(|v| v * mac_key).collect_vec();

        assert_eq!(macs, expected_macs);
        vals
    }

    // ---------
    // | Tests |
    // ---------

    #[tokio::test]
    async fn test_dealer() {
        const N: u32 = 10;
        let (resp1, resp2) = get_mock_dealer_response(N).await;
        let mac_key = resp1.mac_key_share + resp2.mac_key_share;

        // Check the random bits
        let bits = recover_and_check_macs(mac_key, &resp1.random_bits, &resp2.random_bits);
        assert!(bits.into_iter().all(|b| b == Scalar::zero() || b == Scalar::one()));

        // Check the random values
        recover_and_check_macs(mac_key, &resp1.random_values, &resp2.random_values);

        // Check the input masks
        let (mask1, mask1_share1, mask2_share1) = resp1.input_masks.clone();
        let (mask2, mask2_share2, mask1_share2) = resp2.input_masks.clone();

        let mask1_recovered = recover_and_check_macs(mac_key, &mask1_share1, &mask1_share2);
        let mask2_recovered = recover_and_check_macs(mac_key, &mask2_share1, &mask2_share2);
        assert_eq!(mask1, mask1_recovered);
        assert_eq!(mask2, mask2_recovered);

        // Check the inverse pairs
        let (r1, r_inv1) = resp1.inverse_pairs.clone();
        let (r2, r_inv2) = resp2.inverse_pairs.clone();
        let r1_recovered = recover_and_check_macs(mac_key, &r1, &r2);
        let r2_recovered = recover_and_check_macs(mac_key, &r_inv1, &r_inv2);

        let res = r1_recovered
            .iter()
            .zip(r2_recovered.iter())
            .map(|(r1, r2)| r1 * r2)
            .all(|r| r == Scalar::one());
        assert!(res);

        // Check the triples
        let (a1, b1, c1) = resp1.beaver_triples.clone();
        let (a2, b2, c2) = resp2.beaver_triples.clone();
        let a_recovered = recover_and_check_macs(mac_key, &a1, &a2);
        let b_recovered = recover_and_check_macs(mac_key, &b1, &b2);
        let c_recovered = recover_and_check_macs(mac_key, &c1, &c2);

        for (a, b, c) in izip!(a_recovered, b_recovered, c_recovered) {
            assert_eq!(a * b, c);
        }
    }
}
