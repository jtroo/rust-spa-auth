//! Custom errors that can be turned into Warp `Rejection`s.
//!
//! Also exposes `handle_rejection` which can be used to ensure all rejections become replies.

use serde::Serialize;
use thiserror::Error;
use warp::{Rejection, Reply, http::StatusCode};

#[derive(Clone, Copy, Error, Debug)]
pub enum Error {
    #[error("wrong credentials")]
    WrongCredentialsError,
    #[error("refresh token not valid")]
    RefreshTokenError,
    #[error("jwt token not valid")]
    JwtTokenError,
    #[error("invalid auth header")]
    InvalidAuthHeaderError,
    #[error("no permission")]
    NoPermissionError,
    #[error("internal error")]
    InternalError,
}

impl Error {
    fn status_code(self) -> StatusCode {
        match self {
            // Note regarding FORBIDDEN vs. UNAUTHORIZED:
            //
            // According to RFC 7235 (https://tools.ietf.org/html/rfc7235#section-3.1),
            // UNAUTHORIZED should be used if using HTTP authentication. This can be inferred from
            // the RFC which states that the WWW-Authenticate header must be sent by the server
            // upon replying with UNAUTHORIZED. This server uses its own authentication method —
            // not HTTP authentication — so UNAUTHORIZED must not be used.
            //
            // The WrongCredentialsError variant will have a BAD_REQUEST response.
            Self::RefreshTokenError | Self::NoPermissionError | Self::JwtTokenError
                => StatusCode::FORBIDDEN,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    msg: String,
    status: String,
}

impl warp::reject::Reject for Error {}

/// Turn a rejection into a handled reply.
pub async fn handle_rejection(
    err: Rejection
) -> std::result::Result<warp::reply::Response, std::convert::Infallible> {
    if let Some(e) = err.find::<Error>() {
        eprintln!("custom rejection: {}", e);
        let code = e.status_code();
        let json = warp::reply::json(&ErrorResponse {
            status: code.to_string(),
            msg: e.to_string(),
        });
        Ok(warp::reply::with_status(json, code).into_response())
    } else {
        eprintln!("builtin rejection: {:?}", err);
        Ok(err.default_response())
    }
}
