# Rust SPA + Auth

This project contains a Warp webserver that serves a Vue 2.X single page
application and has authentication and JWT-based authorization.

It was written as a learning exercise and can hopefully be a useful example
for Rust application that needs authentication + authorization.

# Example API Usage

``` sh

curl -v https://localhost:9090/api/auth/login \
  --cacert tls/server.rsa.crt \
  -d '{"email": "user@localhost", "pw": "userpassword"}' \
  -H 'Content-Type: application/json'

# result is in set-cookie header:
# set-cookie: refresh_token=ZzmdZ2jSYzRjRs2y.wYrUBTcHbG++Lr7JEO75xXArDWTNrMb1B6SwDWFFuUPNrA9vBWdfIx9+eBAwAUhpApFTj1eUfV7dlmTHRXAZ7I8RWZMC1iqha67lMjykQ7Wxqw==; Max-Age=2592000; path=/api/auth/access; Secure; HttpOnly; SameSite=Lax;


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
  - add this: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-storage-on-client-side
  - add this: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers
  - logout
- https redirect
- lets-encrypt
- better logging
- testing
- fix refresh token impl - L3 address is no good
  - add this: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#defense-in-depth-techniques
  - add this: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#cookie-with-__host-prefix
- add to access token: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking

# License

This project is licensed under the [MIT license](LICENSE).

# Contribution

Pull requests are welcome. The goal of this project is to serve as a useful
example for building a website with a Rust backend that includes some security.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you shall be licensed as MIT without any additional terms or
conditions.
