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

use clap::Parser;
use dealer::{
    create_dealer_sender_receiver, create_response_sender_receiver, Dealer, DealerJob, DealerSender,
};
use renegade_dealer_api::{DealerRequest, DealerResponse, ErrorResponse, RequestId};
use warp::Filter;

/// The maximum number of values that may be requested at once by a pair
const MAX_REQUEST_SIZE: u32 = 1_500_000;

/// An error type indicating a bad request
#[derive(Debug)]
struct BadRequestError(&'static str);
impl warp::reject::Reject for BadRequestError {}

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
    let setup = warp::post()
        .and(warp::path("v0"))
        .and(warp::path("offline-phase"))
        .and(warp::path::param::<RequestId>())
        .and(warp::body::json::<DealerRequest>())
        .and_then(move |request_id, body| {
            let dealer_send = dealer_send.clone();
            async move {
                match handle_req(request_id, body, dealer_send).await {
                    Ok(resp) => Ok(warp::reply::json(&resp)),
                    Err(rej) => Err(rej),
                }
            }
        });

    let routes = setup.recover(handle_rejection);

    warp::serve(routes).run(([127, 0, 0, 1], cli.port)).await
}

/// Handle an incoming client request
async fn handle_req(
    request_id: RequestId,
    body: DealerRequest,
    dealer_queue: DealerSender,
) -> Result<DealerResponse, warp::Rejection> {
    if body.total_values() > MAX_REQUEST_SIZE {
        return Err(warp::reject::custom(BadRequestError("Request size too large")));
    }

    let (send, mut recv) = create_response_sender_receiver();
    dealer_queue.send(DealerJob::new(request_id, body, send)).unwrap();

    Ok(recv.recv().await.unwrap())
}

/// Handle a rejection from the dealer
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(BadRequestError(msg)) = err.find::<BadRequestError>() {
        let json = warp::reply::json(&ErrorResponse { message: msg, code: 400 });
        Ok(warp::reply::with_status(json, warp::http::StatusCode::BAD_REQUEST))
    } else {
        Err(err)
    }
}
