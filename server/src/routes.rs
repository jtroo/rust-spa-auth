use crate::auth::*;
use crate::error;
use crate::storage::Storage;
use warp::{
    filters::{self, BoxedFilter},
    http, reply, Filter,
};

pub fn api<S: 'static + Storage + Send + Sync + Clone>(
    store: S,
) -> BoxedFilter<(impl reply::Reply,)> {
    log::info!("creating routes");
    let login_api = warp::path!("login")
        .and(with_storage(store.clone()))
        .and(warp::post())
        .and(filters::header::header::<String>("user-agent"))
        .and(warp::body::json())
        .and_then(login_handler);

    // The `access` and `logout` routes have the `auth` prefix because these are the only two
    // routes that require the `refresh_token` cookie. These get a unique prefix so that the cookie
    // can use a more specific path and won't be sent for unnecessary routes.

    let access_api = warp::path!("auth" / "access")
        .and(warp::get())
        .and(with_storage(store.clone()))
        .and(filters::header::header::<String>("user-agent"))
        .and(filters::cookie::cookie("refresh_token"))
        .and_then(access_handler);

    let logout_api = warp::path!("auth" / "logout")
        .and(warp::post())
        .and(with_storage(store))
        .and(filters::header::header::<String>("user-agent"))
        .and(filters::cookie::cookie("refresh_token"))
        .and_then(logout_handler);

    let user_api = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);

    let admin_api = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    // Note: warp::path is **not** the macro! The macro version would terminate path checking at
    // "api" as opposed to being a prefix for the other handlers. This puzzled me for longer than I
    // would have liked. ☹
    //
    // This "api" prefix is used so that API handlers' rejections can all be turned into replies by
    // `error::handle_rejection`. This is needed so that they don't fall back to the SPA handlers.
    let apis = warp::path("api").and(
        access_api
            .or(login_api)
            .or(user_api)
            .or(admin_api)
            .or(logout_api)
            .recover(error::handle_rejection),
    );

    #[cfg(feature = "dev_cors")]
    let apis = {
        const ORIGIN: &str = "http://localhost:8080";
        log::info!("allowing CORS for development, origin: {}", ORIGIN);
        apis.with(
            warp::cors()
                .allow_origin(ORIGIN)
                .allow_methods(vec!["GET", "PUT", "POST", "DELETE"])
                .allow_headers(vec!["content-type", "user-agent", "authorization"])
                .allow_credentials(true),
        )
    };

    apis.boxed()
}

pub fn spa(client_files_dir: String) -> BoxedFilter<(impl reply::Reply,)> {
    warp::fs::dir(client_files_dir.clone())
        .or(warp::fs::file(format!("{}/index.html", client_files_dir)))
        .boxed()
}

/// Creates a filter that passes storage to the receiving fn.
fn with_storage<S: Storage + Send + Sync + Clone>(
    store: S,
) -> impl Filter<Extract = (S,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || store.clone())
}

/// Authenticate with an email and a password to retrieve a refresh token cookie.
async fn login_handler<S: Storage>(
    store: S,
    user_agent: String,
    req: AuthenticateRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(authenticate(&store, &user_agent, "/api/auth", req)
        .await
        .map(|cookie| {
            warp::http::Response::builder()
                .header("set-cookie", &cookie)
                .body("success")
        })?)
}

/// Get a new access token using a refresh token.
async fn access_handler<S: Storage>(
    store: S,
    user_agent: String,
    refresh_token: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(access(&store, &user_agent, &refresh_token)
        .await
        .map(|token| warp::http::Response::builder().body(token))?)
}

/// Explicitly log out by revoking the refresh token.
async fn logout_handler<S: Storage>(
    store: S,
    user_agent: String,
    refresh_token: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Ignore result, always reply with 200. Don't want an attacker to know if they logged out with
    // actual credentials or not.
    let _ = logout(&store, &user_agent, &refresh_token).await;
    Ok(warp::reply())
}

/// Returns a filter that checks if the request is authorized based on the `required_role`
/// provided.
///
/// For example, if this called with `auth::Role::Admin`, then the returned filter will reject any
/// requests that do not have an access token that states they are an admin.
fn with_auth(
    required_role: Role,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    use once_cell::sync::Lazy;
    static AUTH_HEADER: Lazy<&str> = Lazy::new(|| http::header::AUTHORIZATION.as_str());
    filters::header::header::<String>(&AUTH_HEADER)
        .map(move |auth_header| (required_role, auth_header))
        .and_then(auth)
}

/// Warp-ified wrapper for `auth::authorize`.
async fn auth((required_role, auth_header): (Role, String)) -> Result<String, warp::Rejection> {
    authorize(required_role, auth_header).map_err(warp::reject::custom)
}

/// Sample handler for a user
async fn user_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("user {}", email))
}

/// Sample handler for an admin
async fn admin_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("admin {}", email))
}

#[cfg(all(test, feature = "in_memory"))]
mod tests {
    use super::*;
    use warp::Reply;
    use std::str::from_utf8;

    async fn create_api_filter() -> BoxedFilter<(impl reply::Reply,)> {
        let test_store = crate::init_store(None).await;
        api(test_store)
    }

    #[tokio::test]
    async fn test_api_success() {
        let f = create_api_filter().await;

        // check that login with incorrect credentials gets 400 response
        let response = warp::test::request()
            .method("POST")
            .header("user-agent", "cargo test")
            .body(r#"{"email":"user@localhost","pw":"userpassword"}"#)
            .path("/api/login")
            .reply(&f)
            .await;
        assert_eq!(response.status(), 200);
        dbg!(response);
    }

    #[tokio::test]
    async fn test_api_bad_login() {
        let f = create_api_filter().await;

        // check that nonexistent API route gets 404
        let reply = warp::test::request()
            .path("/api/noexist")
            .filter(&f)
            .await
            .unwrap();
        assert_eq!(reply.into_response().status(), 404);

        // login without header has 400 response with missing header
        let reply = warp::test::request()
            .method("POST")
            .body(r#"{"email":"user@localhost","pw":"userpassword"}"#)
            .path("/api/login")
            .reply(&f).await;
        assert_eq!(reply.status(), 400);
        assert!(from_utf8(reply.body()).expect("bad utf8").contains("Missing request header"));

        // login with incorrect credentials gets 400 response with wrong credentials
        let reply = warp::test::request()
            .method("POST")
            .header("user-agent", "cargo test")
            .body(r#"{"email":"hello","pw":"bye"}"#)
            .path("/api/login")
            .reply(&f).await;
        assert_eq!(reply.status(), 400);
        assert!(from_utf8(reply.body()).expect("bad utf8").contains("wrong credentials"));
    }

    #[tokio::test]
    async fn test_api_bad_access() {
        let f = create_api_filter().await;

        // check that nonexistent API route gets 404
        let reply = warp::test::request()
            .path("/api/noexist")
            .filter(&f)
            .await
            .unwrap();
        assert_eq!(reply.into_response().status(), 404);

        // login without header has 400 response with missing header
        let reply = warp::test::request()
            .method("POST")
            .body(r#"{"email":"user@localhost","pw":"userpassword"}"#)
            .path("/api/login")
            .reply(&f).await;
        assert_eq!(reply.status(), 400);
        assert!(from_utf8(reply.body()).expect("bad utf8").contains("Missing request header"));

        // login with incorrect credentials gets 400 response with wrong credentials
        let reply = warp::test::request()
            .method("POST")
            .header("user-agent", "cargo test")
            .body(r#"{"email":"hello","pw":"bye"}"#)
            .path("/api/login")
            .reply(&f).await;
        assert_eq!(reply.status(), 400);
        assert!(from_utf8(reply.body()).expect("bad utf8").contains("wrong credentials"));
    }
}
