//! A gRPC status, without tonic.
//!
//! This is `crate::grpc::Status` reduced to what the cosigner actually uses: a code, a message, and the
//! nine constructors named across the handlers. Every one of those handlers returns
//! `Result<_, Status>` and none of them ever touched the parts of tonic's type that are about a
//! transport — metadata, source errors, the HTTP mapping — so replacing it costs an import line
//! per file and nothing else.
//!
//! The numbers are the wire values from the gRPC specification. They go out in the `grpc-status`
//! trailer, which is the only place a gRPC call's real outcome is ever reported: the HTTP status
//! of a failed call is still 200.

use std::fmt;

/// <https://grpc.github.io/grpc/core/md_doc_statuscodes.html>
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Code {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    NotFound = 5,
    PermissionDenied = 7,
    FailedPrecondition = 9,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    Unauthenticated = 16,
}

#[derive(Clone, Debug)]
pub struct Status {
    code: Code,
    message: String,
}

impl Status {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The constructors the handlers name, each `Status::<code>(message)`.
macro_rules! ctors {
    ($($name:ident => $code:ident),* $(,)?) => {
        impl Status {
            $(
                pub fn $name(message: impl Into<String>) -> Self {
                    Self::new(Code::$code, message)
                }
            )*
        }
    };
}

ctors! {
    cancelled => Cancelled,
    unknown => Unknown,
    invalid_argument => InvalidArgument,
    not_found => NotFound,
    permission_denied => PermissionDenied,
    failed_precondition => FailedPrecondition,
    unimplemented => Unimplemented,
    internal => Internal,
    unavailable => Unavailable,
    unauthenticated => Unauthenticated,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Status {}
