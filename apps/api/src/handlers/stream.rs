use std::{convert::Infallible, time::Duration};
use axum::{extract::State, http::HeaderMap, response::sse::{Event, KeepAlive, Sse}};
use futures_util::Stream;
use crate::{auth, error::ApiError, AppState};

pub async fn subscribe(State(state): State<AppState>, headers: HeaderMap) -> Result<Sse<impl Stream<Item=Result<Event, Infallible>>>, ApiError> {
    auth::current_user(&state, &headers).await?;
    let mut rx = state.events.subscribe();
    let output = async_stream::stream! {
        // Streams are deliberately short-lived. Reconnection rechecks the cookie.
        let deadline = tokio::time::sleep(Duration::from_secs(1800));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                message = rx.recv() => match message {
                    Ok(data) => yield Ok(Event::default().data(data)),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => yield Ok(Event::default().data(r#"{"type":"refresh"}"#)),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    };
    Ok(Sse::new(output).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
