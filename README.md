# Rust SPA + Auth

This project contains a Warp webserver that serves a single page application
and has authentication + JWT-based authorization.

It was written as a learning exercise and can hopefully be a useful example
for a Rust application that needs authentication + authorization.

I am not the most procient client-side dev, so the structure of the client side
code may not be what you want to emulate. The file `client/src/api/index.js` is
probably the most noteworthy file with regards to using the server APIs. It
makes use of the [axios library](https://www.npmjs.com/package/axios) to call
APIs.

# Demo

![Demo video](https://user-images.githubusercontent.com/6634136/113497053-c2505200-94b4-11eb-8010-27a132a010e9.mp4)


# Dependencies

- A recent version of Rust+Cargo (MSRV unknown)
- A recent version of npm (minimum unknown)

# Note on async runtime

Since the webserver uses Warp, the code uses on the tokio runtime. Apart from
the Warp related code, the `auth` module has a few instances where it is
reliant on tokio. These are pretty minimal so it should be simple to adapt for
webservers with another runtime, e.g.  Tide.

Instances of tokio reliance:

- `init_default_users`: uses `block_on` to run async code in a sync function
- `authenticate`: spawns a blocking task to run bcrypt verification
- `pretend_password_processing`: uses tokio sleep

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

serve client files:
``` sh
cd $(git rev-parse --show-toplevel)/client
npm run serve
```

run server
``` sh
cd $(git rev-parse --show-toplevel)/server
cargo run --features dev_cors
```

# Potential additions

- put all password processing on a single thread?
  - is this a good idea?
- clap 3.0 CLI args
- auth rate limit
- https redirect
- lets-encrypt
- better logging
- tests

# License

This project is licensed under the [MIT license](LICENSE).

# Contribution

Pull requests are welcome. The goal of this project is to serve as a useful
example for building a website with a Rust backend that includes some security.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you shall be licensed as MIT without any additional terms or
conditions.
