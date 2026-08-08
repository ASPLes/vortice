// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Serving a BEEP profile with a [`tower::Service`].
//!
//! Enabled by the `tower` feature. A profile becomes a `Service<Request, Response = Response>`,
//! which means every middleware written for tower applies to it unchanged — timeouts, retries,
//! rate limits, concurrency limits, load shedding, tracing — without any of it being written
//! here.
//!
//! ```
//! # #[cfg(feature = "tower")] {
//! use std::time::Duration;
//! use tower::ServiceBuilder;
//! use vortice::service::{Request, Response, service_fn};
//! use vortice::Router;
//!
//! let echo = service_fn(|request: Request| async move {
//!     Ok::<_, std::convert::Infallible>(Response::Rpy(request.message.payload))
//! });
//!
//! let guarded = ServiceBuilder::new()
//!     .timeout(Duration::from_secs(5))
//!     .service(echo);
//!
//! let router = Router::new().service("urn:example:echo", guarded);
//! assert!(router.serves("urn:example:echo"));
//! # }
//! ```
//!
//! # Why the service is cloned per message
//!
//! `Service` takes `&mut self`, but a profile is shared by every session and every channel
//! serving it, and messages arrive concurrently. Cloning per message is the convention the
//! tower ecosystem is built on: a service's clone shares whatever state matters through an
//! `Arc` inside it, and the layers that need exclusive access — the concurrency limit, say —
//! are written to work that way.

use std::fmt::Display;
use std::future::Future;

use bytes::Bytes;
use tower::{Service, ServiceExt};

use crate::channel::Message;
use crate::router::{Handler, HandlerFuture, Responder};

/// One message delivered to a service, with the means to answer it.
#[derive(Debug)]
#[non_exhaustive]
pub struct Request {
    /// The message that arrived.
    pub message: Message,
    /// How to answer it, for a service that wants to stream rather than return.
    pub responder: Responder,
}

/// How a service answers.
///
/// Returning is the simple path; a service that needs to interleave work with its answers
/// can use [`Request::responder`] directly and return [`Response::Deferred`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    /// Answer positively.
    Rpy(Bytes),
    /// Answer negatively.
    Err(Bytes),
    /// Answer with a one-to-many reply; the terminating `NUL` is sent for you.
    Answers(Vec<Bytes>),
    /// The service already answered, or chose not to.
    Deferred,
}

impl Response {
    /// A positive reply carrying `payload`.
    pub fn rpy(payload: impl Into<Bytes>) -> Self {
        Self::Rpy(payload.into())
    }

    /// A negative reply carrying `payload`.
    pub fn err(payload: impl Into<Bytes>) -> Self {
        Self::Err(payload.into())
    }
}

/// Builds a service from an async function, as `tower::service_fn` does.
///
/// Re-exported so that a caller does not have to depend on `tower` directly for the common
/// case of a profile that is one function.
pub fn service_fn<F>(f: F) -> tower::util::ServiceFn<F> {
    tower::service_fn(f)
}

/// Serves a profile with a tower service.
///
/// Built by [`Router::service`](crate::Router::service); there is no reason to name it.
#[derive(Debug, Clone)]
pub struct ServiceHandler<S> {
    service: S,
}

impl<S> ServiceHandler<S> {
    pub(crate) const fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S> Handler for ServiceHandler<S>
where
    S: Service<Request, Response = Response> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Display + Send,
{
    fn handle(&self, responder: Responder, message: Message) -> HandlerFuture {
        let mut service = self.service.clone();
        Box::pin(async move {
            let msgno = message.msgno;
            let request = Request {
                message,
                responder: responder.clone(),
            };

            // `ready` is where a layer refuses work — a concurrency limit that is full, a
            // circuit breaker that is open — so a failure here is answered like any other.
            let outcome = match service.ready().await {
                Ok(service) => service.call(request).await,
                Err(error) => Err(error),
            };

            match outcome {
                Ok(response) => apply(&responder, msgno, response).await,
                Err(error) => {
                    let _ = responder.error(msgno, error.to_string()).await;
                }
            }
        })
    }
}

/// Writes whatever the service returned.
async fn apply(responder: &Responder, msgno: u32, response: Response) {
    match response {
        Response::Rpy(payload) => {
            let _ = responder.reply(msgno, payload).await;
        }
        Response::Err(payload) => {
            let _ = responder.error(msgno, payload).await;
        }
        Response::Answers(answers) => {
            for answer in answers {
                if responder.answer(msgno, answer).await.is_err() {
                    return;
                }
            }
            let _ = responder.finish(msgno).await;
        }
        Response::Deferred => {}
    }
}

/// A future returning a [`Response`], for hand-written services.
pub trait ResponseFuture: Future<Output = Response> + Send {}

impl<F> ResponseFuture for F where F: Future<Output = Response> + Send {}
