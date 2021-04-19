mod auth;
mod error;
mod routes;
mod storage;

use std::net::SocketAddrV4;
use std::process::exit;
use warp::Filter;

#[derive(structopt::StructOpt)]
struct Args {
    #[structopt(short, long, help = "Address to bind to, e.g. 127.0.0.1:80")]
    address: Option<String>,

    #[structopt(short, long, help = "Database URL, e.g. sqlite:///tmp/db.sql")]
    database: Option<String>,
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) {
    init_log();

    log::info!("rust spa auth starting");

    log::info!("initializing password pretend processing");
    auth::pretend_password_processing().await;

    let store = init_store(args.database).await;

    let sockaddr: SocketAddrV4 = match &args.address {
        Some(v) => v.parse().unwrap_or_else(|_| {
            log::error!("Invalid socket address provided");
            exit(1);
        }),
        None => SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080),
    };

    // It actually seems a bit cleaner to use a feature flag here rather than a conditional,
    // because the type of `api_routes` is changing here. So there would need to be a CORS branch
    // and a non-CORS branch with some repeated code to do this with a conditional instead of a
    // feature flag.
    #[cfg(feature = "dev_cors")]
    let sockaddr = {
        if args.address.is_some() {
            log::warn!(
                "for feature `dev_cors`, address 127.0.0.1:9090 is used instead of input {}",
                sockaddr
            );
        }
        SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 9090)
    };

    let routes = routes::api(store).or(routes::spa("./public".into()));

    log::info!("running webserver");
    warp::serve(routes)
        .tls()
        .key_path("tls/server.rsa.key")
        .cert_path("tls/server.rsa.crt")
        .run(sockaddr)
        .await;
}

fn init_log() {
    env_logger::Builder::from_env(
        env_logger::Env::default()
            // use info level by default
            .default_filter_or("info"),
    )
    .init();
}

#[cfg(not(feature = "in_memory"))]
async fn init_store(db: Option<String>) -> impl storage::Storage + Send + Sync + Clone {
    log::info!("connecting to database");
    let db = db.unwrap_or_else(|| {
        std::env::var("DATABASE_URL")
            .expect("Need `--database <db>` flag or `DATABASE_URL` env variable")
    });
    storage::new_db_storage(&db)
        .await
        .expect("could not connect to database")
}

#[cfg(feature = "in_memory")]
async fn init_store(_: Option<String>) -> impl storage::Storage + Send + Sync + Clone {
    let store = storage::new_in_memory_storage();
    // Need to store some default users for in_memory, otherwise nothing will exist. This
    // does not apply to a database, because a database can have pre-existing users.
    log::info!("preparing default users for in-memory store");
    auth::store_user(&store, "user@localhost", "userpassword", auth::Role::User)
        .await
        .expect("could not store default user");
    auth::store_user(
        &store,
        "admin@localhost",
        "adminpassword",
        auth::Role::Admin,
    )
    .await
    .expect("could not store default admin");
    store
}
