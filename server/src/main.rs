mod auth;
mod error;
mod storage;

use warp::{http, filters, Filter};

fn main() {
    println!("rust spa auth starting");

    println!("preparing default users");
    auth::init_default_users();

    println!("creating routes");
    let login_api = warp::path!("login")
        .and(warp::post())
        .and(filters::header::header::<String>("user-agent"))
        .and(warp::body::json())
        .and_then(login_handler);

    let access_api = warp::path!("auth"/"access")
        .and(warp::get())
        .and(filters::header::header::<String>("user-agent"))
        .and(filters::cookie::cookie("refresh_token"))
        .and_then(access_handler);

    let logout_api = warp::path!("auth"/"logout")
        .and(warp::post())
        .and(filters::header::header::<String>("user-agent"))
        .and(filters::cookie::cookie("refresh_token"))
        .and_then(logout_handler);

    let user_api = warp::path!("user")
        .and(with_auth(auth::Role::User))
        .and_then(user_handler);

    let admin_api = warp::path!("admin")
        .and(with_auth(auth::Role::Admin))
        .and_then(admin_handler);

    // Note - warp::path is **not** the macro! The macro version would terminate path checking at
    // "api" as opposed to being a prefix for the other handlers. This puzzled me for longer than I
    // would have liked. ☹
    let api_routes = warp::path("api")
        .and(
            access_api
                .or(login_api)
                .or(user_api)
                .or(admin_api)
                .or(logout_api)
                .recover(error::handle_rejection)
        );

    // This is here to stop unused variable warning, since with the feature `dev_cors` enabled, the
    // port is reassigned without use.
    #[cfg(not(feature = "dev_cors"))]
    let port = 80;

    #[cfg(feature = "dev_cors")]
    let (port, api_routes) = {
        const ORIGIN: &str = "http://localhost:8080";
        println!("allowing CORS for development, origin: {}", ORIGIN);
        (
            9090,
            api_routes
                .with(warp::cors()
                    .allow_origin(ORIGIN)
                    .allow_methods(vec!["GET", "PUT", "POST", "DELETE"])
                    .allow_headers(vec!["content-type", "user-agent", "authorization"])
                    .allow_credentials(true)
            ),
        )
    };

    const WEB_APP_DIR: &str = "./public";
    let spa_handler = warp::fs::dir(WEB_APP_DIR);

    let routes = api_routes
        .or(spa_handler)
        .or(warp::fs::file(format!("{}/index.html", WEB_APP_DIR)));

    println!("running webserver");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime should start")
        .block_on(async {
            warp::serve(routes)
                .tls()
                    .key_path("tls/server.rsa.key")
                    .cert_path("tls/server.rsa.crt")
                    .run(([0, 0, 0, 0], port)).await;
            }
        );
}

/// Used to authenticate with a password and retrieve a refresh token.
async fn login_handler(
    user_agent: String,
    req: auth::AuthenticateRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(auth::authenticate(user_agent, req).await
        .map(|(token, max_age)| {
            const SECURITY_FLAGS: &str = "Secure; HttpOnly; SameSite=Lax;";
            warp::http::Response::builder()
                .header(
                    "set-cookie",
                    &format!(
                        "refresh_token={}; Max-Age={}; Path=/api/auth; {}",
                        token, max_age, SECURITY_FLAGS
                    ),
                )
                .body("success")
        })?
    )
}

/// Used to get a new access token using a refresh token
async fn access_handler(
    user_agent: String,
    refresh_token: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(
        auth::access(&user_agent, &refresh_token)
            .await
            .map(|token| warp::http::Response::builder().body(token))?
    )
}

/// Used to explicitly log out by revoking the refresh token.
async fn logout_handler(
    user_agent: String,
    refresh_token: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Ignore result, always reply with 200. Don't want an attacker to know if they logged out with
    // actual credentials or not.
    let _ = auth::logout(&user_agent, &refresh_token).await;
    Ok(warp::reply())
}

/// Returns a filter that checks if the request is authorized based on the `required_role`
/// provided.
///
/// For example, if this called with `auth::Role::Admin`, then the returned filter will reject any
/// requests that do not have an access token that states they are an admin.
fn with_auth(
    required_role: auth::Role
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    use once_cell::sync::Lazy;
    static AUTH_HEADER: Lazy<&str> = Lazy::new(|| http::header::AUTHORIZATION.as_str());
    filters::header::header::<String>(&AUTH_HEADER)
        .map(move |auth_header| (required_role, auth_header))
        .and_then(authorize)
}

/// Warp-ified wrapper for `auth::authorize`.
async fn authorize(
    (required_role, auth_header): (auth::Role, String)
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
