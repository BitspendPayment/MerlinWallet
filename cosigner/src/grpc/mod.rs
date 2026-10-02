//! gRPC over `wasi:http`, without tonic.
//!
//! tonic does not build for `wasm32-wasip2` at all, so a guest that wants to serve gRPC writes the
//! parts of it that it needs. There turn out to be three, and none of them is large: the framing
//! ([`framing`], five bytes), the status ([`status`], a code and a message in the trailers), and
//! holding a request body and a response body open at once ([`duplex`], which is specified
//! behaviour rather than a trick).
//!
//! What is deliberately absent is a generated service trait. The router below matches `:path`
//! itself, because the paths are `/cosigner.v1.Cosigner/<Method>` and there are fifteen of them —
//! a table is clearer than a code generator, and it is the only thing tonic was still providing.
//!
//! The messages are still generated: `build.rs` runs prost over the same `.proto` the Dart client
//! generates from, with tonic's service output switched off. A hand-written message set would be
//! the one part of this worth being afraid of.

pub mod duplex;
pub mod framing;
pub mod status;

use bytes::Bytes;
use http_body_util::BodyExt;
use prost::Message as ProstMessage;
use wstd::http::{Body, Error, Response, StatusCode};

pub use duplex::{Duplex, HasBody, SessionBody};
pub use status::{Code, Status};

/// gRPC is always HTTP 200; the real status is in the trailers.
///
/// The `trailer` header is load-bearing on HTTP/1.1, where hyper's encoder drops trailers outright
/// unless the response declares which ones it will send. It is harmless on HTTP/2, where trailers
/// need no announcement — and the runtime negotiates that per connection, so both happen.
fn head() -> http::response::Builder {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc+proto")
        .header("trailer", "grpc-status, grpc-message")
}

/// A streaming method: the response body is the ceremony.
pub fn streaming<Req, Resp>(body: SessionBody<Req, Resp>) -> Response<Body>
where
    Req: ProstMessage + Default + 'static,
    Resp: ProstMessage + 'static,
{
    head()
        .body(Body::from_http_body(body))
        .expect("response is well formed")
}

/// A failure with nothing to say but why: no messages, only trailers.
///
/// This is how *every* gRPC error is reported, including a method that does not exist. A client
/// reading only the head would otherwise see a perfectly successful call.
pub fn failed(status: Status) -> Response<Body> {
    let trailers = duplex::trailers(&status);
    head()
        .body(Body::from_http_body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .with_trailers(async move { Some(Ok::<_, Error>(trailers)) }),
        ))
        .expect("response is well formed")
}

/// One message out, then trailers.
pub fn unary<Resp: ProstMessage>(resp: Resp) -> Response<Body> {
    let trailers = duplex::trailers(&Status::new(Code::Ok, ""));
    head()
        .body(Body::from_http_body(
            http_body_util::Full::new(framing::frame(&resp.encode_to_vec()))
                .map_err(|e: std::convert::Infallible| match e {})
                .with_trailers(async move { Some(Ok::<_, Error>(trailers)) }),
        ))
        .expect("response is well formed")
}

/// The single message a unary call carries.
///
/// Unary bodies are collected whole rather than deframed incrementally: there is exactly one
/// message, the runtime already bounds an ordinary request body because it hashes it, and a second
/// frame is a client bug rather than something to quietly ignore.
pub async fn one_message<Req: ProstMessage + Default>(mut body: Body) -> Result<Req, Status> {
    let bytes = body
        .bytes_contents()
        .await
        .map_err(|e| Status::unavailable(format!("reading the request body: {e}")))?;

    let mut deframer = framing::Deframer::default();
    deframer.push(&bytes);
    let message = deframer
        .next()
        .map_err(|m| Status::invalid_argument(m.to_string()))?
        .ok_or_else(|| Status::invalid_argument("the request carried no complete message"))?;

    let decoded =
        Req::decode(message).map_err(|e| Status::invalid_argument(format!("undecodable request: {e}")))?;

    match deframer.next() {
        Ok(None) => Ok(decoded),
        Ok(Some(_)) => Err(Status::invalid_argument(
            "a unary call carried more than one message",
        )),
        Err(m) => Err(Status::invalid_argument(m.to_string())),
    }
}
