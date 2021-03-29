# Rust SPA + Auth

This project contains a Warp webserver that serves a Vue 2.X single page
application and has authentication and JWT-based authorization.

It was written as a learning exercise and can hopefully be a useful example
for Rust application that needs authentication + authorization.

# Example API Usage

``` sh
curl https://localhost:9090/api/auth/login \
  --cacert tls/server.rsa.crt \
  -d '{"email": "user@localhost", "pw": "userpassword"}' \
  -H 'Content-Type: application/json'
# result:
# 20JhkbEiIsjAZz32.yN/3tsqTlChhDWrz+z43TEm29V/sqXa2vKtyde/wwRnN0wNZsYObcGrRb2CZYz+eaTgD2oGnS28r4yWqzBL/o9ilvYW8wlWpT4IHq1OideYI2w==


curl https://localhost:9090/api/auth/access \
  --cacert tls/server.rsa.crt \
  -d '{"refresh_token": "20JhkbEiIsjAZz32.yN/3tsqTlChhDWrz+z43TEm29V/sqXa2vKtyde/wwRnN0wNZsYObcGrRb2CZYz+eaTgD2oGnS28r4yWqzBL/o9ilvYW8wlWpT4IHq1OideYI2w=="}' \
  -H 'Content-Type: application/json'
# result:
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTY5MjY2NTd9.kj9GR-FPUVmZh2BEvGmbqg6tAz4lsjvLxtcTXOjdDXLwD0KGZ2NrDueuuyJ1Y4z8z98q9VcpDNHYjS4veM2hYw

curl https://localhost:9090/api/user \
  --cacert tls/server.rsa.crt \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTY5MjY3NjB9.RjT3mn1nD-1xP3iDS0t_TwRdVVkqVsNZlCWgdapNMwTKEI1L5ghXOTwgw06Xj36a7qaRKLO9eM5SwLqLbX5kjQ'
# result:
# user user@localhost

curl https://localhost:9090/api/admin \
  --cacert tls/server.rsa.crt \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJlbWFpbCI6InVzZXJAbG9jYWxob3N0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE2MTY5MjY3NjB9.RjT3mn1nD-1xP3iDS0t_TwRdVVkqVsNZlCWgdapNMwTKEI1L5ghXOTwgw06Xj36a7qaRKLO9eM5SwLqLbX5kjQ'
# result:
# {"message":"no permission","status":"401 Unauthorized"}⏎
```

# Build to serve the SPA

```
cd $(git rev-parse --show-toplevel)
./build-debug.sh
```

# Serving the SPA and server separately

To serve the SPA and the server separately for more rapid client side code development, you can
use the following commands:

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

# TODOs

- auth rate limit
- Vue SPA
- https redirect
- lets-encrypt
- users mocked?
- better logging
- testing
- put refresh token in cookie
- put access token in cookie

# License

This project is licensed under the [MIT license](LICENSE).

# Contribution

Pull requests are welcome. The goal of this project is to serve as a useful
example for building a website with a Rust backend that includes some security.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you shall be licensed as MIT without any additional terms or
conditions.
