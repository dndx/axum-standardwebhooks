# axum-standardwebhooks

[![Crates.io](https://img.shields.io/crates/v/axum-standardwebhooks.svg)](https://crates.io/crates/axum-standardwebhooks)
[![Documentation](https://docs.rs/axum-standardwebhooks/badge.svg)](https://docs.rs/axum-standardwebhooks)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/axum-standardwebhooks.svg)](./LICENSE)

A library providing [Axum](https://github.com/tokio-rs/axum) extractors for validating webhooks according to the [Standard Webhooks specification](https://www.standardwebhooks.com/).

## Features

- Simple, ergonomic extractor for validating Standard Webhooks signatures
- Rejects requests with invalid or missing signatures
- Works with Axum's state management for shared webhook verifier
- Works with any existing body extractor that implements `FromRequest`

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
axum-standardwebhooks = "1"
```

## Usage

### Basic example

```rust
use axum::{Router, routing::post, Json};
use axum_standardwebhooks::{StandardWebhook, SharedWebhook, Webhook};
use serde_json::Value;
use std::sync::Arc;
use axum::extract::FromRef;

async fn webhook_handler(StandardWebhook(Json(payload)): StandardWebhook<Json<Value>>) -> String {
    // The webhook signature has been verified, and we can safely use the payload
    format!("Received webhook: {}", payload)
}

#[derive(Clone)]
struct AppState {
    webhook: SharedWebhook,
}

impl FromRef<AppState> for SharedWebhook {
    fn from_ref(state: &AppState) -> Self {
        state.webhook.clone()
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/webhooks", post(webhook_handler))
        .with_state(AppState {
            webhook: SharedWebhook::new(Webhook::new("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD").unwrap()),
        });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## License

Licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
