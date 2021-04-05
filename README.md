# Rust SPA + Auth

This project contains a Rust server that serves a single page application and
has authentication + JWT-based authorization.

It was written as a learning exercise and can hopefully be a useful example for
a Rust-backed website that uses authentication + authorization. It's a bit more
complete and closer to prodution-ready than other example code I've seen
online, e.g. [JWT with warp](#special-mentions).

## Warning

Though I am somewhat informed, I am not a security expert. Don't deploy this
code to production.

# Demo

![Demo video](https://user-images.githubusercontent.com/6634136/113497053-c2505200-94b4-11eb-8010-27a132a010e9.mp4)

# Dependencies

- A recent version of Rust+Cargo (MSRV unknown)
- A recent version of npm (minimum unknown)

## Note regarding Warp

If you check [Cargo.toml](server/Cargo.toml), you'll see that the `warp`
dependency is my personal warp fork. This is due to waiting on [my
PR](https://github.com/seanmonstar/warp/pull/827) for more convenient rejection
handling to be merged.

# Notable content

## Server

- Rust with a [Warp web server](https://crates.io/crates/warp)
- Authentication using Argon2 password hashing to produce refresh token cookies
- Authorization with 2 basic roles using JWT access tokens for claims
- [Optional CORS](#serve-the-spa-separately) for more rapid client side development
- Example for abstracting a data store with a trait
  - In-memory implementation exists

## Client

- [Vue 2.X](https://vuejs.org/) framework
- [Axios](https://www.npmjs.com/package/axios) for API requests
- Login
- Logout
- Conditionally visible UI components based on JWT claims
- Automatic refreshing of access tokens on 403 error

I am not the most proficient client-side dev, so the structure of the client side
code may not be what you want to emulate. The [API requests using
axios](client/src/api/index.js) are probably the most useful to look at with
regards to using the server APIs.

# Note on server framework and async runtime

The authorization code is hopefully not closely tied to Warp framework details
— most of the Warp-specific code is in `main.rs` with a sprinkle in
`error.rs`. As long as the server framework used is async capable, the auth
code should be a decent starting point for use with other server frameworks.

Since the webserver uses Warp, the code uses on the tokio runtime. Apart from
the Warp related code, the `auth` module has a few instances where it is
reliant on tokio. These are pretty minimal so it should be simple to adapt for
webservers with another runtime, e.g. [Tide](https://crates.io/crates/tide).

Instances of tokio reliance:

- `init_default_users`: uses `block_on` to run async code in a sync function
- `authenticate`: spawns a blocking task to run password verification
- `pretend_password_processing`: uses tokio sleep

# Serve the SPA with Rust

```
cd $(git rev-parse --show-toplevel)
./build-debug.sh
cd build-output
./rust-spa-auth
```

# Serve the SPA separately

To serve the SPA and the server separately for more rapid client side code
development, you can use the following commands:

Note - you may have to navigate to https://localhost:9090 manually and accept
the certificate warning before this works.

Serve client files:
``` sh
cd $(git rev-parse --show-toplevel)/client
npm run serve
```

Run server:
``` sh
cd $(git rev-parse --show-toplevel)/server
cargo run --features dev_cors
```

# Example API Usage

You can check the API functionality without your browser using cURL.

See an example sequence below.

``` sh

curl -v https://localhost:9090/api/login \
  --cacert tls/server.rsa.crt \
  -d '{"email": "user@localhost", "pw": "userpassword"}' \
  -H 'Content-Type: application/json'

# result is in set-cookie header:
# set-cookie: refresh_token=QpOddMUkW9wk/S4B.s/a3k3JttPFH3v4j43gxx7KL+3y05Opm1rjiQBV+07z9NXacLv8PeQn6DRDoblFDerGQ9qeUp1TpaNAg5f1cYtLf3t3xnvGkHUDW2TK/mDJr4A=="; Max-Age=2592000; path=/api/auth/access; Secure; HttpOnly; SameSite=Lax;


curl https://localhost:9090/api/auth/access \
  --cacert tls/server.rsa.crt \
  --cookie "refresh_token=QpOddMUkW9wk/S4B.s/a3k3JttPFH3v4j43gxx7KL+3y05Opm1rjiQBV+07z9NXacLv8PeQn6DRDoblFDerGQ9qeUp1TpaNAg5f1cYtLf3t3xnvGkHUDW2TK/mDJr4A=="

# result:
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTY5MjY2NTd9.kj9GR-FPUVmZh2BEvGmbqg6tAz4lsjvLxtcTXOjdDXLwD0KGZ2NrDueuuyJ1Y4z8z98q9VcpDNHYjS4veM2hYw

curl https://localhost:9090/api/user \
  --cacert tls/server.rsa.crt \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTcwNjUxMDJ9.imixaRk8YgoEv8Hh33qidty_jGBAo9ewIOd7vWqAjAHiN-MZJOFeSXg25nWx86SW9Pc_QFH_qlFYaSmPG_MfRA'

# result:
# user user@localhost

curl https://localhost:9090/api/admin \
  --cacert tls/server.rsa.crt \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTcwNjUxMDJ9.imixaRk8YgoEv8Hh33qidty_jGBAo9ewIOd7vWqAjAHiN-MZJOFeSXg25nWx86SW9Pc_QFH_qlFYaSmPG_MfRA'

# result:
# {"message":"no permission","status":"403 Forbidden"}⏎

curl https://localhost:9090/api/auth/logout \
  -X POST \
  --cacert tls/server.rsa.crt \
  --cookie "refresh_token=QpOddMUkW9wk/S4B.s/a3k3JttPFH3v4j43gxx7KL+3y05Opm1rjiQBV+07z9NXacLv8PeQn6DRDoblFDerGQ9qeUp1TpaNAg5f1cYtLf3t3xnvGkHUDW2TK/mDJr4A=="

```

# Potential changes/additions

- tests
- auth rate limit
- http to https redirect
- delete the cookie on the client on logout
- put all password processing on a single thread?
  - is this a good idea?
- clap 3.0 CLI args
- lets-encrypt certificates
- better logging
- use an [AEAD implementation crate](https://github.com/RustCrypto/AEADs)
  directly instead of ring

# Special mentions

These sources were useful starting points.

- [Hosting SPA with Warp](https://freiguy1.gitlab.io/posts/hosting-spa-with-warp.html)
- [JWT authentication with Warp](https://blog.logrocket.com/jwt-authentication-in-rust/)

# License

This project is licensed under the [MIT license](LICENSE).

# Contribution

Pull requests are welcome. The goal of this project is to serve as a useful
example for building a website with a Rust backend that includes some security.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you shall be licensed as MIT without any additional terms or
conditions.
