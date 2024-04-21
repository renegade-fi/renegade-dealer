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
use renegade_dealer_api::{DealerRequest, DealerResponse, RequestId};
use warp::Filter;

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
                let resp = handle_req(request_id, body, dealer_send).await;
                Ok::<_, warp::Rejection>(warp::reply::json(&resp))
            }
        });

    warp::serve(setup).run(([127, 0, 0, 1], cli.port)).await
}

/// Handle an incoming client request
async fn handle_req(
    request_id: RequestId,
    body: DealerRequest,
    dealer_queue: DealerSender,
) -> DealerResponse {
    // Send a request to the dealer
    let (send, mut recv) = create_response_sender_receiver();
    dealer_queue.send(DealerJob::new(request_id, body, send)).unwrap();

    recv.recv().await.unwrap()
}
