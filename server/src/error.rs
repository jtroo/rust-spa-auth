use serde::Serialize;
use thiserror::Error;
use warp::{Rejection, Reply, http::StatusCode};

#[derive(Clone, Copy, Error, Debug)]
pub enum Error {
    #[error("wrong credentials")]
    WrongCredentialsError,
    #[error("jwt token not valid")]
    JWTTokenError,
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
            Self::WrongCredentialsError => StatusCode::FORBIDDEN,
            Self::NoPermissionError => StatusCode::UNAUTHORIZED,
            Self::JWTTokenError => StatusCode::UNAUTHORIZED,
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
        return Ok(err.default_response())
    }
}
