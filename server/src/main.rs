mod auth;
mod error;
mod storage;

use log::*;
use std::net::SocketAddrV4;
use std::process::exit;
use storage::Storage;
use warp::{filters, http, Filter};

#[derive(structopt::StructOpt)]
struct Args {
    #[structopt(short, long)]
    address: Option<String>,
}

#[paw::main]
fn main(args: Args) {
    init_log();

    info!("rust spa auth starting");

    info!("preparing default users");
    let store = storage::new_in_memory_storage();
    auth::init_default_users(&store);

    info!("creating routes");
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
        .and(with_storage(store.clone()))
        .and(filters::header::header::<String>("user-agent"))
        .and(filters::cookie::cookie("refresh_token"))
        .and_then(logout_handler);

    let user_api = warp::path!("user")
        .and(with_auth(auth::Role::User))
        .and_then(user_handler);

    let admin_api = warp::path!("admin")
        .and(with_auth(auth::Role::Admin))
        .and_then(admin_handler);

    // Note: warp::path is **not** the macro! The macro version would terminate path checking at
    // "api" as opposed to being a prefix for the other handlers. This puzzled me for longer than I
    // would have liked. ☹
    //
    // This "api" prefix is used so that API handlers' rejections can all be turned into replies by
    // `error::handle_rejection`. This is needed so that they don't fall back to the SPA handlers.
    let api_routes = warp::path("api").and(
        access_api
            .or(login_api)
            .or(user_api)
            .or(admin_api)
            .or(logout_api)
            .recover(error::handle_rejection),
    );

    // This is here to stop an unused variable warning, since with the feature `dev_cors` enabled,
    // the port is reassigned without use.
    let sockaddr: SocketAddrV4 = match &args.address {
        Some(v) => v.parse().unwrap_or_else(|_| {
            error!("Invalid socket address provided");
            exit(1);
        }),
        None => SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080),
    };

    // This could be pretty trivially replaced with CLI arguments instead of a feature flag. A
    // feature flag is used here to serve as an example
    #[cfg(feature = "dev_cors")]
    let (sockaddr, api_routes) = {
        const ORIGIN: &str = "http://localhost:8080";
        info!("allowing CORS for development, origin: {}", ORIGIN);
        if args.address.is_some() {
            warn!(
                "for feature `dev_cors`, address 127.0.0.1:9090 is used instead of input {}",
                sockaddr
            );
        }
        (
            SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 9090),
            api_routes.with(
                warp::cors()
                    .allow_origin(ORIGIN)
                    .allow_methods(vec!["GET", "PUT", "POST", "DELETE"])
                    .allow_headers(vec!["content-type", "user-agent", "authorization"])
                    .allow_credentials(true),
            ),
        )
    };

    const WEB_APP_DIR: &str = "./public";
    let spa_handler = warp::fs::dir(WEB_APP_DIR);

    let routes = api_routes
        .or(spa_handler)
        .or(warp::fs::file(format!("{}/index.html", WEB_APP_DIR)));

    info!("running webserver");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime should start")
        .block_on(async {
            warp::serve(routes)
                .tls()
                .key_path("tls/server.rsa.key")
                .cert_path("tls/server.rsa.crt")
                .run(sockaddr)
                .await;
        });
}

fn init_log() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")) // use info level by default
        .init();
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
    req: auth::AuthenticateRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(auth::authenticate(&store, &user_agent, "/api/auth", req)
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
    Ok(auth::access(&store, &user_agent, &refresh_token)
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
    let _ = auth::logout(&store, &user_agent, &refresh_token).await;
    Ok(warp::reply())
}

/// Returns a filter that checks if the request is authorized based on the `required_role`
/// provided.
///
/// For example, if this called with `auth::Role::Admin`, then the returned filter will reject any
/// requests that do not have an access token that states they are an admin.
fn with_auth(
    required_role: auth::Role,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    use once_cell::sync::Lazy;
    static AUTH_HEADER: Lazy<&str> = Lazy::new(|| http::header::AUTHORIZATION.as_str());
    filters::header::header::<String>(&AUTH_HEADER)
        .map(move |auth_header| (required_role, auth_header))
        .and_then(authorize)
}

/// Warp-ified wrapper for `auth::authorize`.
async fn authorize(
    (required_role, auth_header): (auth::Role, String),
) -> Result<String, warp::Rejection> {
    auth::authorize(required_role, auth_header).map_err(warp::reject::custom)
}

/// Sample handler for a user
async fn user_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("user {}", email))
}

/// Sample handler for an admin
async fn admin_handler(email: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(format!("admin {}", email))
}
