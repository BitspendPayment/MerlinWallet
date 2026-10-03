//! A bidirectional gRPC stream, as one `async fn`.
//!
//! `wasi:http/incoming-handler` looks request/response, and half of it is: the guest is called
//! once and returns once. But `response-outparam.set` is documented to *"allow execution to
//! continue after the response has been sent"*, and `incoming-request.consume` borrows rather than
//! consumes — so the request body and the response body are two independent resource trees the
//! guest may hold at the same time. The response head goes out first, and everything after it is a
//! conversation.
//!
//! [`SessionBody`] is where that happens. It is an `http_body::Body` that owns the *request* body
//! and drives a handler future between reads: each time the host asks for the next response frame
//! it polls the handler, and when the handler wants a message that has not arrived it reads the
//! wire and polls it again. One task alternating, rather than two running — which is exactly what
//! a strict ping-pong ceremony needs, and is worth naming as the limit it is.
//!
//! The handler sees none of that. It takes a [`Duplex`], calls `recv().await` and `send()`, and
//! reads like the `async_stream::try_stream!` blocks it replaces — which is the point: the
//! ceremonies did not change, only what carries them.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use http_body_util::combinators::UnsyncBoxBody;
use prost::Message as ProstMessage;
use wstd::http::{Error, HeaderMap};

use super::framing::{frame, Deframer};
use super::status::{Code, Status};

/// What the body and the handler pass between them.
struct Shared<Req, Resp> {
    inbound: VecDeque<Req>,
    /// The client half-closed. A `recv()` after this returns `None` rather than parking forever.
    closed: bool,
    outbound: VecDeque<Resp>,
}

/// The handler's end of the stream.
pub struct Duplex<Req, Resp> {
    shared: Arc<Mutex<Shared<Req, Resp>>>,
}

impl<Req, Resp> Duplex<Req, Resp> {
    /// Queue one message. Not async: it hands the message to the body, which writes it when the
    /// host next asks. A handler therefore never blocks on a slow reader mid-ceremony — and never
    /// holds a lock across an await, because there is no await here to hold one across.
    pub fn send(&self, msg: Resp) {
        self.shared.lock().expect("duplex").outbound.push_back(msg);
    }

    /// The next message, or `None` if the client half-closed.
    ///
    /// Returns `Pending` without registering a waker, deliberately: the only thing that can make
    /// progress is [`SessionBody::poll_frame`], which polls this future itself and then goes to
    /// the wire. Registering a waker would name a task that does not exist.
    pub async fn recv(&self) -> Option<Req> {
        std::future::poll_fn(|_cx| {
            let mut shared = self.shared.lock().expect("duplex");
            if let Some(msg) = shared.inbound.pop_front() {
                return Poll::Ready(Some(msg));
            }
            if shared.closed {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await
    }

    /// The next message, or a `cancelled` status naming what the ceremony was waiting for.
    ///
    /// Every round in every ceremony needs this, and the message matters: "stream closed before
    /// the share arrived" tells an operator which round died, where a bare cancellation does not.
    pub async fn expect(&self, what: &str) -> Result<Req, Status> {
        self.recv()
            .await
            .ok_or_else(|| Status::cancelled(format!("stream closed before {what}")))
    }
}

/// A stream message whose payload is a `oneof body` — as every client message here is.
pub trait HasBody {
    type Body;

    fn into_body(self) -> Option<Self::Body>;
}

impl<Req: HasBody, Resp> Duplex<Req, Resp> {
    /// The next message's body: [`expect`](Self::expect), and refused if the message is empty.
    pub async fn next_body(&self, what: &str) -> Result<Req::Body, Status> {
        let empty = || Status::invalid_argument(format!("an empty message where {what} belonged"));
        self.expect(what).await?.into_body().ok_or_else(empty)
    }
}

enum Phase {
    Talking,
    Trailers,
    Done,
}

/// The response body: a handler, the request body, and the framing between them.
pub struct SessionBody<Req, Resp> {
    /// The request body, held for the life of the response. This is the whole trick, and it is
    /// specified behaviour rather than a trick — see the module docs.
    inbound: UnsyncBoxBody<Bytes, Error>,
    deframer: Deframer,
    shared: Arc<Mutex<Shared<Req, Resp>>>,
    handler: Option<Pin<Box<dyn Future<Output = Result<(), Status>> + Send>>>,
    phase: Phase,
    status: Status,
}

impl<Req, Resp> SessionBody<Req, Resp>
where
    Req: ProstMessage + Default + 'static,
    Resp: ProstMessage + 'static,
{
    /// Wire `handler` to `inbound`. The closure receives the handler's end of the stream.
    pub fn new<F, Fut>(inbound: UnsyncBoxBody<Bytes, Error>, handler: F) -> Self
    where
        F: FnOnce(Duplex<Req, Resp>) -> Fut,
        Fut: Future<Output = Result<(), Status>> + Send + 'static,
    {
        let shared = Arc::new(Mutex::new(Shared {
            inbound: VecDeque::new(),
            closed: false,
            outbound: VecDeque::new(),
        }));
        let duplex = Duplex { shared: Arc::clone(&shared) };
        Self {
            inbound,
            deframer: Deframer::default(),
            shared,
            handler: Some(Box::pin(handler(duplex))),
            phase: Phase::Talking,
            status: Status::new(Code::Ok, ""),
        }
    }

    fn finish(&mut self, status: Status) {
        self.status = status;
        self.handler = None;
        self.phase = Phase::Trailers;
    }

    /// Everything that has fully arrived, decoded and queued for the handler.
    fn drain_wire(&mut self, data: &[u8]) -> Result<(), Status> {
        self.deframer.push(data);
        loop {
            match self.deframer.next() {
                Ok(Some(message)) => match Req::decode(message) {
                    Ok(msg) => self.shared.lock().expect("duplex").inbound.push_back(msg),
                    Err(e) => {
                        return Err(Status::invalid_argument(format!("undecodable message: {e}")))
                    }
                },
                Ok(None) => return Ok(()),
                Err(malformed) => return Err(Status::invalid_argument(malformed.to_string())),
            }
        }
    }
}

impl<Req, Resp> HttpBody for SessionBody<Req, Resp>
where
    Req: ProstMessage + Default + 'static,
    Resp: ProstMessage + 'static,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        loop {
            // Anything the handler has said goes out first. Each becomes one write on the
            // response stream, so a client that is not reading stops this body being polled
            // rather than letting the queue grow.
            let next_out = this.shared.lock().expect("duplex").outbound.pop_front();
            if let Some(msg) = next_out {
                return Poll::Ready(Some(Ok(Frame::data(frame(&msg.encode_to_vec())))));
            }

            match this.phase {
                Phase::Trailers => {
                    this.phase = Phase::Done;
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers(&this.status)))));
                }
                Phase::Done => return Poll::Ready(None),
                Phase::Talking => {}
            }

            // Drive the ceremony as far as it will go on what it already has.
            if let Some(handler) = this.handler.as_mut() {
                match handler.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {
                        this.finish(Status::new(Code::Ok, ""));
                        continue;
                    }
                    Poll::Ready(Err(status)) => {
                        this.finish(status);
                        continue;
                    }
                    // Waiting for a message. Fall through to the wire.
                    Poll::Pending => {}
                }
            }

            // Polling it may have produced something to write.
            if !this.shared.lock().expect("duplex").outbound.is_empty() {
                continue;
            }

            // It is waiting, and the client will send nothing more. A handler that has already
            // been offered the close and still parked is stuck, not patient — ending the stream
            // is the only honest answer, and it beats spinning here forever.
            if this.shared.lock().expect("duplex").closed {
                this.finish(Status::internal(
                    "the ceremony stalled after the client half-closed",
                ));
                continue;
            }

            match Pin::new(&mut this.inbound).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                // The client half-closed — orderly only if it came between messages. A close with
                // bytes stranded in the deframer is a truncated frame, and reporting OK for it
                // would tell the client its last message was received when it was not.
                Poll::Ready(None) => {
                    if this.deframer.is_empty() {
                        this.shared.lock().expect("duplex").closed = true;
                    } else {
                        this.finish(Status::invalid_argument(
                            "the stream ended part-way through a message",
                        ));
                    }
                }
                Poll::Ready(Some(Err(e))) => this.finish(Status::unavailable(e.to_string())),
                Poll::Ready(Some(Ok(incoming))) => {
                    // Request trailers. gRPC clients send none, and there is nothing a ceremony
                    // would do with them.
                    if let Some(data) = incoming.data_ref() {
                        let data = data.clone();
                        if let Err(status) = this.drain_wire(&data) {
                            this.finish(status);
                        }
                    }
                }
            }
        }
    }
}

/// gRPC reports its real outcome here, never in the HTTP status.
pub fn trailers(status: &Status) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "grpc-status",
        (status.code() as u32).to_string().parse().expect("a number is a header value"),
    );
    if !status.message().is_empty() {
        // A status message is built from operator-facing text, but it is still the one field here
        // that carries anything dynamic, and a stray newline would end the header early.
        let sanitized: String = status
            .message()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if let Ok(value) = sanitized.parse() {
            trailers.insert("grpc-message", value);
        }
    }
    trailers
}
