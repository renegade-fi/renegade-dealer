//! HTTP server for the Renegade Dealer
//!
//! The dealer implements a trusted dealer in the context on a SPDZ offline
//! phase. We allow parties in the Renegade MPC network to opt in using the
//! dealer as opposed to the Lowgear implementation
//!
//! The dealer awaits two parties to connect (authenticated with a signature)
//! and then deals sets of correlated randomness shares to each party

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

mod dealer;

use ark_mpc::PARTY0;
use ark_mpc::{network::PartyId, PARTY1};
use base64::prelude::*;
use clap::Parser;
use dealer::{
    create_dealer_sender_receiver, create_response_sender_receiver, Dealer, DealerJob, DealerSender,
};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use renegade_dealer_api::{
    DealerRequest, DealerResponse, ErrorResponse, RequestId, PARTY_ID_HEADER, SIGNATURE_HEADER,
};
use uuid::Uuid;
use warp::Filter;

/// The maximum number of values that may be requested at once by a pair
const MAX_REQUEST_SIZE: u32 = 1_500_000;

/// An error type indicating a bad request
#[derive(Debug, Clone)]
struct BadRequestError(&'static str);
impl warp::reject::Reject for BadRequestError {}

/// An error type indicating the request is not authorized
#[derive(Debug)]
struct UnauthorizedError(&'static str);
impl warp::reject::Reject for UnauthorizedError {}

/// Renegade Dealer server configuration
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Port to listen on
    #[clap(short, long, default_value_t = 3000)]
    port: u16,
}

/// Main entry point for the Renegade Dealer
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Start a dealer
    let (dealer_send, dealer_recv) = create_dealer_sender_receiver();
    Dealer::start(dealer_recv);

    // POST /v0/offline-phase/:request_id
    let offline_phase = warp::post()
        .and(warp::path("v0"))
        .and(warp::path("offline-phase"))
        .and(warp::path::param::<RequestId>())
        .and(warp::header::header::<PartyId>(PARTY_ID_HEADER))
        .and(warp::header::header::<String>(SIGNATURE_HEADER))
        .and(warp::body::json::<DealerRequest>())
        .and_then(move |request_id, party_id, sig, body| {
            let dealer_send = dealer_send.clone();
            async move {
                match handle_req(request_id, party_id, sig, body, dealer_send).await {
                    Ok(resp) => Ok(warp::reply::json(&resp)),
                    Err(rej) => Err(rej),
                }
            }
        })
        .recover(handle_rejection);

    // GET /ping
    let ping = warp::get()
        .and(warp::path("ping"))
        .map(|| warp::reply::with_status("PONG", warp::http::StatusCode::OK));

    let routes = offline_phase.or(ping);
    warp::serve(routes).run(([0, 0, 0, 0], cli.port)).await
}

/// Validates the incoming request headers and body.
fn validate_request(
    request_id: Uuid,
    party_id: PartyId,
    signature: &str,
    body: &DealerRequest,
) -> Result<(), warp::Rejection> {
    // Sizing constraints
    if body.total_values() > MAX_REQUEST_SIZE {
        return Err(warp::reject::custom(BadRequestError("Request size too large")));
    }

    // Party ID validation
    if !(party_id == PARTY0 || party_id == PARTY1) {
        return Err(warp::reject::custom(BadRequestError("Invalid party ID")));
    }

    // Verify the signature
    let key: VerifyingKey =
        if party_id == PARTY0 { body.first_party_key } else { body.second_party_key }.into();
    let decoded = BASE64_STANDARD.decode(signature.as_bytes()).unwrap();
    let sig = Signature::from_slice(&decoded).unwrap();

    let body_bytes = serde_json::to_vec(&body).unwrap();
    let payload = [request_id.to_bytes_le().as_ref(), &body_bytes].concat();
    key.verify(&payload, &sig).map_err(|_| UnauthorizedError("Invalid signature"))?;

    Ok(())
}

/// Handle an incoming client request
async fn handle_req(
    request_id: RequestId,
    party_id: PartyId,
    signature: String,
    body: DealerRequest,
    dealer_queue: DealerSender,
) -> Result<DealerResponse, warp::Rejection> {
    validate_request(request_id, party_id, &signature, &body)?;
    let (send, mut recv) = create_response_sender_receiver();
    dealer_queue.send(DealerJob::new(request_id, party_id, body, send)).unwrap();

    recv.recv().await.unwrap().map_err(warp::reject::custom)
}

/// Handle a rejection from the dealer
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(BadRequestError(msg)) = err.find::<BadRequestError>() {
        let json = warp::reply::json(&ErrorResponse { message: msg, code: 400 });
        Ok(warp::reply::with_status(json, warp::http::StatusCode::BAD_REQUEST))
    } else if let Some(UnauthorizedError(msg)) = err.find::<UnauthorizedError>() {
        let json = warp::reply::json(&ErrorResponse { message: msg, code: 401 });
        Ok(warp::reply::with_status(json, warp::http::StatusCode::UNAUTHORIZED))
    } else {
        Err(err)
    }
}
