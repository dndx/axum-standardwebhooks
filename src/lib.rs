//! Integration of the [standardwebhooks](https://crates.io/crates/standardwebhooks) crate with the
//! [Axum](https://github.com/tokio-rs/axum) web framework.
//!
//! This crate provides an extractor for Axum that verifies webhook requests according to the
//! [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks).
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::post, Json};
//! use axum_standardwebhooks::{StandardWebhook, SharedWebhook, Webhook};
//! use serde_json::Value;
//! use axum::extract::FromRef;
//!
//! async fn webhook_handler(StandardWebhook(Json(payload)): StandardWebhook<Json<Value>>) -> String {
//!     // The webhook signature has been verified, and we can safely use the payload
//!     format!("Received webhook: {}", payload)
//! }
//!
//! #[derive(Clone)]
//! struct AppState {
//!     webhook: SharedWebhook,
//! }
//!
//! impl FromRef<AppState> for SharedWebhook {
//!     fn from_ref(state: &AppState) -> Self {
//!         state.webhook.clone()
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new()
//!         .route("/webhooks", post(webhook_handler))
//!         .with_state(AppState {
//!             webhook: SharedWebhook::new(Webhook::new("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD").unwrap()),
//!         });
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```

#![forbid(unsafe_code)]

use axum::body::Body;
use axum::extract::FromRef;
use axum::extract::rejection::FailedToBufferBody;
use axum::http::StatusCode;
use axum::{
    extract::FromRequest,
    http::{Request, Response},
    response::IntoResponse,
};
use bytes::Bytes;
pub use standardwebhooks::Webhook;
pub use standardwebhooks::WebhookError;
use std::ops::Deref;
use std::sync::Arc;

/// A thread-safe wrapper around [`Webhook`] to make it shareable between Axum handlers.
///
/// This type provides a convenient way to share the webhook verifier across multiple
/// request handlers without needing to clone the underlying `Webhook` for each request.
#[derive(Clone)]
pub struct SharedWebhook(Arc<Webhook>);

impl Deref for SharedWebhook {
    type Target = Webhook;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SharedWebhook {
    /// Creates a new `SharedWebhook` from a `Webhook`
    /// for use during verification.
    ///
    /// # Arguments
    ///
    /// * `webhook` - The `Webhook` to wrap
    ///
    /// # Returns
    ///
    /// A new `SharedWebhook` wrapping the provided `Webhook`
    ///
    /// # Example
    ///
    /// ```rust
    /// use axum_standardwebhooks::{SharedWebhook, Webhook};
    ///
    /// let shared_webhook = SharedWebhook::new(Webhook::new("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD").unwrap());
    /// ```
    pub fn new(webhook: Webhook) -> Self {
        Self(Arc::new(webhook))
    }
}

/// Represents the ways in which webhook verification and extraction can fail.
/// Represents the ways in which webhook verification and extraction can fail.
///
/// This enum combines errors from body buffering, webhook verification, and
/// the extraction of the inner type.
#[derive(Debug)]
pub enum StandardWebhookRejection<E> {
    /// The request body could not be buffered.
    FailedToBufferBody(FailedToBufferBody),
    /// The webhook signature could not be verified.
    FailedToVerifyWebhook(WebhookError),
    /// The request body could not be extracted into the desired type.
    FailedToExtractBody(E),
}

/// An extractor that verifies a webhook request and extracts the inner payload.
///
/// `StandardWebhook<T>` wraps another extractor `T` and ensures that the webhook
/// signature is valid before proceeding with the extraction of `T`. This provides
/// a way to safely handle webhook payloads in Axum handlers.
///
/// The inner extractor `T` can be any type that implements [`FromRequest`],
/// such as [`Json`], [`Form`], or [`Query`].
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct StandardWebhook<T>(pub T);

impl<E> IntoResponse for StandardWebhookRejection<E>
where
    E: IntoResponse,
{
    fn into_response(self) -> Response<Body> {
        match self {
            Self::FailedToBufferBody(e) => e.into_response(),
            Self::FailedToVerifyWebhook(e) => {
                (StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
            Self::FailedToExtractBody(e) => e.into_response(),
        }
    }
}

impl<S, T> FromRequest<S> for StandardWebhook<T>
where
    T: FromRequest<S>,
    S: Send + Sync,
    SharedWebhook: FromRef<S>,
{
    type Rejection = StandardWebhookRejection<T::Rejection>;

    /// Extracts a `StandardWebhook<T>` from the request.
    ///
    /// This method:
    /// 1. Buffers the request body
    /// 2. Verifies the webhook signature
    /// 3. Extracts the inner type `T` from the request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request body could not be buffered
    /// - The webhook signature is invalid
    /// - The inner extractor `T` fails
    async fn from_request(mut req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        // we want to avoid copying the entire request object,
        // so we take the original request's body,
        // create a fake request with the body, perform the buffering,
        // and then replace the original request's body with the buffered one
        let body = std::mem::replace(req.body_mut(), Body::empty());

        let fake_req = Request::new(body);
        let bytes = Bytes::from_request(fake_req, state).await.unwrap();

        let verifier = SharedWebhook::from_ref(state);
        verifier
            .verify(&bytes, req.headers())
            .map_err(StandardWebhookRejection::FailedToVerifyWebhook)?;

        let body = bytes.into();
        *req.body_mut() = body;

        Ok(StandardWebhook(
            T::from_request(req, state)
                .await
                .map_err(StandardWebhookRejection::FailedToExtractBody)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use axum::{Json, Router, routing::post};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use standardwebhooks::{HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, HEADER_WEBHOOK_TIMESTAMP};
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tower::ServiceExt;

    const SECRET: &str = "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";
    const MSG_ID: &str = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk";
    const PAYLOAD: &[u8] = br#"{"email":"test@example.com","username":"test_user"}"#;

    async fn echo(StandardWebhook(body): StandardWebhook<Json<Value>>) -> impl IntoResponse {
        body["username"].as_str().unwrap().to_string()
    }

    async fn body_string(body: Body) -> String {
        String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into()
    }

    fn with_headers(msg_id: &str, signature: &str, body: &'static [u8]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .header(HEADER_WEBHOOK_ID, msg_id)
            .header(HEADER_WEBHOOK_SIGNATURE, signature)
            .header(
                HEADER_WEBHOOK_TIMESTAMP,
                OffsetDateTime::now_utc().unix_timestamp().to_string(),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }

    fn app() -> Router {
        Router::new()
            .route("/", post(echo))
            .with_state(SharedWebhook(Arc::new(Webhook::new(SECRET).unwrap())))
    }

    #[tokio::test]
    async fn header_missing() {
        let req = Request::builder()
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "missing header id");
    }

    #[tokio::test]
    async fn valid_signature() {
        let wh = Webhook::new(SECRET).unwrap();
        let signature = wh
            .sign(MSG_ID, OffsetDateTime::now_utc().unix_timestamp(), PAYLOAD)
            .unwrap();

        let req = with_headers(MSG_ID, &signature, PAYLOAD);
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res.into_body()).await, "test_user");
    }

    #[tokio::test]
    async fn invalid_signature() {
        let wh = Webhook::new(SECRET).unwrap();
        let mut signature = wh
            .sign(MSG_ID, OffsetDateTime::now_utc().unix_timestamp(), PAYLOAD)
            .unwrap();
        signature.pop().unwrap();

        let req = with_headers(MSG_ID, &signature, PAYLOAD);
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature invalid");
    }
}
