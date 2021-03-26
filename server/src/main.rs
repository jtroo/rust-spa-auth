mod auth;
mod error;

use warp::{http, filters, Filter};
use error::Error;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    println!("rust spa auth starting");

    println!("preparing default users");
    auth::init_default_users().expect("Users could not initialize");

    println!("creating routes");
    let login_api = warp::path!("auth"/"login")
        .and(warp::post())
        .and(filters::addr::remote())
        .and(filters::header::header::<String>("user-agent"))
        .and(warp::body::json())
        .and_then(login_handler);

    let access_api = warp::path!("auth"/"access")
        .and(warp::post())
        .and(filters::addr::remote())
        .and(filters::header::header::<String>("user-agent"))
        .and(warp::body::json())
        .and_then(access_handler);

    let user_route = warp::path!("user")
        .and(with_auth(auth::Role::User))
        .and_then(user_handler);
    let admin_route = warp::path!("admin")
        .and(with_auth(auth::Role::Admin))
        .and_then(admin_handler);

    // Note - warp::path is **not** the macro! The macro version would terminate path checking at
    // "api" as opposed to being a prefix for the other handlers.
    let api_routes = warp::path("api").and(
        access_api
        .or(login_api)
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection)
    );

    #[cfg(feature = "dev_cors")]
    let api_routes = {
        const ORIGIN: &str = "http://localhost:8080";
        println!("allowing CORS for development, origin: {}", ORIGIN);
        api_routes
            .with(warp::cors().allow_origin(ORIGIN))
    };

    const WEB_APP_DIR: &str = "./public";
    let spa_handler = warp::fs::dir(WEB_APP_DIR);

    let routes = api_routes
        .or(spa_handler)
        .or(warp::fs::file(format!("{}/index.html", WEB_APP_DIR)));

    println!("running webserver");
    warp::serve(routes)
        .tls()
        .key_path("tls/server.rsa.key")
        .cert_path("tls/server.rsa.crt")
        .run(([127, 0, 0, 1], 9090)).await;
}

/// Convenience function for mapping 'Option<SocketAddr>' to a 'Result' with the proper error.
fn ok_or_addr(addr: Option<SocketAddr>) -> Result<SocketAddr, Error> {
    addr.ok_or_else(|| {
        println!("no src addr for req");
        Error::InternalError
    })
}

/// Used to authenticate with a password and retrieve a refresh token.
async fn login_handler(
    addr: Option<SocketAddr>,
    user_agent: String,
    req: auth::AuthenticateRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    let addr = ok_or_addr(addr)?;
    Ok(auth::authenticate(addr, &user_agent, &req)
        .map(|token| warp::http::Response::builder().body(token))?
    )
}

/// Used to get a new access token using a refresh token
async fn access_handler(
    addr: Option<SocketAddr>,
    user_agent: String,
    req: auth::AccessRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    let addr = ok_or_addr(addr)?;
    Ok(auth::access(addr, &user_agent, req)
        .map(|token| warp::http::Response::builder().body(token))?
    )
}

/// Returns a filter that checks if the request is authorized based on the `required_role`
/// provided.
///
/// For example, if this called with `auth::Role::Admin`, then the returned filter will reject any
/// requests that do not have an access token that states they are an admin.
fn with_auth(
    required_role: auth::Role
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    filters::header::header::<String>(http::header::AUTHORIZATION.as_str())
        .map(move |auth_header| (required_role, auth_header))
        .and_then(authorize)
}

/// Warp-ified wrapper for `auth::authorize`.
async fn authorize(
    (required_role, auth_header): (auth::Role, String)
) -> Result<String, warp::Rejection> {
    auth::authorize(required_role, auth_header).map_err(|e| warp::reject::custom(e))
}

/// Sample handler for a user
async fn user_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("user {}", email))
}

/// Sample handler for an admin
async fn admin_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("admin {}", email))
}
