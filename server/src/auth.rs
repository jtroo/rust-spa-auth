//! Provides functions for authentication and authorization.

use crate::{error::Error, storage};
use anyhow::anyhow;
use once_cell::sync::Lazy;
use rand::RngCore;
use ring::aead;
use serde::{Deserialize, Serialize};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

static STORAGE: Lazy<Box<dyn storage::Storage + Send + Sync>>
    = Lazy::new(|| Box::new(storage::new_in_memory_storage()));

/// Used for role differentiation to showcase authorization of the admin route.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    // Doesn't use std::str::FromStr since the trait impl returns a Result and this is infallible.
    fn from_str(role: &str) -> Self {
        match role {
            "admin" => Self::Admin,
            _ => Self::User,
        }
    }

    fn to_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

static ARGON2: Lazy<Argon2> = Lazy::new(|| Argon2::default());

async fn store_user<P: AsRef<[u8]>>(email: &str, pw: P, role: Role) -> Result<(), anyhow::Error> {
    let hashed_pw = ARGON2.hash_password_simple(
        pw.as_ref(),
        SaltString::generate(rand::thread_rng()).as_ref(),
    ).map_err(|e| anyhow!(e))?.to_string();
    STORAGE.store_user(
        storage::User {
            email: email.into(),
            hashed_pw,
            role,
        }
    ).await.map_err(|e| anyhow!(e))
}

/// Initialize a user and an admin account. Panics if it cannot run.
pub fn init_default_users() {
    let rt = tokio::runtime::Runtime::new().expect("could not spawn runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        // also initialize the duration in `pretend_password_processing`
        pretend_password_processing().await;
        store_user("user@localhost", "userpassword", Role::User).await.expect("could not store default user");
        store_user("admin@localhost", "adminpassword", Role::Admin).await.expect("could not store default admin");
    });
}

// Need to change this if refresh token persistence is desired after restarting the binary.
static REFRESH_TOKEN_KEY: Lazy<aead::LessSafeKey> = Lazy::new(|| {
    let alg = &aead::CHACHA20_POLY1305;
    let mut key = vec![0u8; alg.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    aead::LessSafeKey::new(aead::UnboundKey::new(&alg, &key).expect("incorrect ring usage"))
});

/// Content of the encrypted + encoded token that is sent in an authenticate response. The
/// `user_agent` field is used to mitigate against token theft. It's not a very good check since
/// the header can easily be faked, but it's at least something. The `email` field is used to
/// ensure that the user that created the token is still valid. The `exp` field is used to ensure
/// that the token has an expiry time (good practice?) and needs to re-authenticate once in a
/// while.
///
/// If security is more important than convenience (mobile phones can change IP frequently), can
/// use the L3 source IP address and compare against it. Though according to
/// https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
/// this might have issues with the European GDPR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RefreshToken {
    pub user_agent: String,
    pub email: String,
    pub exp: i64,
}

/// 30 days in seconds
const REFRESH_TOKEN_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;

impl RefreshToken {
    /// Create a new refresh token.
    fn new(user_agent: &str, email: &str) -> Result<Self, Error> {
        let exp = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(REFRESH_TOKEN_MAX_AGE_SECS))
            .ok_or_else(|| {
                println!("could not make timestamp");
                Error::InternalError
            })?
            .timestamp();

        Ok(Self {
            user_agent: user_agent.into(),
            email: email.into(),
            exp,
        })
    }

    /// Returns a `String` to be used as a token by client-side code. The data is serialized,
    /// encrypted, then base64 encoded.
    fn encrypt_encode(&self) -> Result<String, Error> {
        let mut nonce = [0u8; aead::NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce_string = base64::encode(&nonce);
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let mut token = bincode::serialize(&self).map_err(|_| {
            println!("failed to serialize refresh token");
            Error::InternalError
        })?;

        REFRESH_TOKEN_KEY
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut token)
            .map_err(|_| Error::InternalError)?;

        let token_string = base64::encode(&token);
        Ok(format!("{}.{}", nonce_string, token_string))
    }
}

use std::str::FromStr;

impl std::str::FromStr for RefreshToken {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut nonce_token_strs = s.splitn(2, '.');
        let nonce_str = nonce_token_strs
            .next()
            .ok_or(Error::RefreshTokenError)?;
        let token_str = nonce_token_strs
            .next()
            .ok_or(Error::RefreshTokenError)?;
        let nonce_bytes = base64::decode(nonce_str).map_err(|_| Error::RefreshTokenError)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| Error::RefreshTokenError)?;
        let mut token_bytes =
            base64::decode(token_str).map_err(|_| Error::RefreshTokenError)?;
        let token_bin = REFRESH_TOKEN_KEY
            .open_in_place(nonce, aead::Aad::empty(), token_bytes.as_mut())
            .map_err(|_| Error::RefreshTokenError)?;
        Ok(bincode::deserialize::<RefreshToken>(&token_bin)
            .map_err(|_| Error::RefreshTokenError)?)
    }
}

/// Add a new refresh token to the data store, returning its `String` representation for saving on
/// the client side on success.
async fn add_refresh_token(user_agent: &str, email: &str) -> Result<String, Error> {
    let token = RefreshToken::new(user_agent, email)?;
    let ret = token.encrypt_encode()?;
    STORAGE.add_refresh_token(token).await?;
    Ok(ret)
}

#[derive(Deserialize)]
pub struct AuthenticateRequest {
    pub email: String,
    pub pw: String,
}

/// On success, returns a refresh token cookie string that can be used to get access tokens.
///
/// The refresh token is opaque and should only be able to be read by this server.
///
/// This contrasts the access token which is a JWT and has claims that are publicly visible. The
/// claims in an access token can be used by the client-side code to manipulate what the user can
/// see based on the claims.
///
/// Unlike the access token, the browser has does not need to know what's inside a refresh token —
/// they just need to give it back to get their access tokens. Thus this function (mis?)uses
/// symmetric encryption from `ring::aead`, so that the browser does not know what's inside.
///
/// I am not a security professional and so am unsure if the following is correct or not:
///
/// The implementation exposes the nonce and does not check for re-used nonces. My understanding is
/// that in `ring:aead`, the intent of the nonce to protect against attacks the network
/// communication, e.g. replay attacks in https, ssh.
///
/// For symmetric keys, accidentally re-using a nonce does not risk leaking the key. In this
/// webserver, the encrypted message is intended to be replayed back, so exposing the nonce and
/// allowing duplicates should be fine.
///
/// The token should only be visible in the user's browser - not through network communication,
/// because network comms should be encrypted via https. In addition, token theft is mitigated by
/// checking the request's L3 source IP and the user agent header in the `access` function.
pub async fn authenticate(
    user_agent: &str,
    cookie_path: &str,
    req: AuthenticateRequest,
) -> Result<String, Error> {
    let user = match STORAGE.get_user(&req.email).await {
        Some(v) => v,
        None => {
            return Err(pretend_password_processing().await);
        }
    };

    // Split up ownership of `email` and `hashed_pw`. The blocking task needs `hashed_pw` and the
    // verification needs `email`.
    let email = user.email;
    let hashed_pw = user.hashed_pw;

    // Password verification is done in a blocking task because it is CPU intensive.
    let verification_result = tokio::task::spawn_blocking(
        move || {
            let parsed_hash = PasswordHash::new(&hashed_pw).map_err(|e| {
                println!("could not parse password hash: {}", e);
                Error::InternalError
            })?;
            ARGON2.verify_password(req.pw.as_bytes(), &parsed_hash)
                .map_err(|_| Error::WrongCredentialsError)
        }).await.map_err(|e| {
            println!("tokio err {}", e);
            Error::InternalError
        })?;

    const SECURITY_FLAGS: &str = "Secure; HttpOnly; SameSite=Lax;";

    match verification_result {
        Ok(()) => Ok(format!(
                "refresh_token={}; Path={}; Max-Age={}; {}",
                add_refresh_token(&user_agent, &email).await?,
                cookie_path,
                REFRESH_TOKEN_MAX_AGE_SECS,
                SECURITY_FLAGS
            ),
        ),
        Err(e) => Err(e),
    }
}

/// This exists to pretend that a password is being processed in the cases where it's not. This
/// makes it harder to guess if a malicious request got an existing email with non-matching
/// password vs. an email that does not exist.
///
/// There is currently a bug: on the first time this function is called, the delay is a lot longer
/// than on every other call. A workaround is to call this function at some point during
/// initialization. I'm too `Lazy` to fix it, so it's called in `init_default_users` to do the
/// workaround.
async fn pretend_password_processing() -> Error {
    static PROCESSING_TIME: Lazy<std::time::Duration> = Lazy::new(|| {
        let salt = SaltString::generate(rand::thread_rng());
        let pwhash = ARGON2.hash_password_simple(
            b"badpassword",
            salt.as_ref(),
        ).expect("could not hash password");
        let start = std::time::Instant::now();
        let _ = ARGON2.verify_password(b"abcdefg", &pwhash);
        let end = std::time::Instant::now();
        end - start
    });
    println!("pretending to process password - should be an invalid email");
    tokio::time::sleep(*PROCESSING_TIME).await;
    Error::WrongCredentialsError
}

/// On success, returns an access token that can be used to authorize with other APIs.
///
/// The access request includes a refresh token that will only work for the user agent that
/// originally created the token. If the provided token is used from a different user agent, then
/// the token will be invalidated.
pub async fn access(user_agent: &str, refresh_token: &str) -> Result<String, Error> {
    let refresh_token = valid_refresh_token_from_str(user_agent, refresh_token).await?;

    let user = match STORAGE.get_user(&refresh_token.email).await {
        Some(v) => v,
        None => {
            println!("valid token for non-existent email {:?}", refresh_token);
            return Err(remove_bad_refresh_token(&refresh_token).await);
        }
    };

    create_jwt(&user).map_err(|e| {
        println!("jwt create err: {}", e);
        Error::InternalError
    })
}

/// Revokes the refresh token provided. This is done regardless of the validations, because if the
/// validations fail then the token **should** be revoked anyway.
pub async fn logout(user_agent: &str, refresh_token: &str) -> Result<(), Error> {
    let refresh_token = valid_refresh_token_from_str(user_agent, refresh_token).await?;

    if STORAGE.get_user(&refresh_token.email).await.is_none() {
        println!("valid token for non-existent email {:?}", refresh_token);
        return Err(remove_bad_refresh_token(&refresh_token).await);
    };

    STORAGE.remove_refresh_token(&refresh_token).await
}

/// Returns a valid `RefreshToken` on success and an error otherwise.
async fn valid_refresh_token_from_str(user_agent: &str, refresh_token: &str) -> Result<RefreshToken, Error> {
    let refresh_token = RefreshToken::from_str(refresh_token)?;

    // make sure the token is known
    if !STORAGE.refresh_token_exists(&refresh_token).await {
        return Err(Error::RefreshTokenError);
    }

    // remove token if expired
    if refresh_token.exp < chrono::Utc::now().timestamp() {
        return Err(remove_bad_refresh_token(&refresh_token).await);
    }

    // ensure token is used by same user agent
    if user_agent != refresh_token.user_agent {
        println!(
            "token used by different agent {}, token: {:?}",
            user_agent, &refresh_token
        );
        return Err(remove_bad_refresh_token(&refresh_token).await);
    }

    Ok(refresh_token)
}

/// Remove a bad refresh token from the set of known tokens.
async fn remove_bad_refresh_token(
    token: &RefreshToken,
) -> Error {
    if let Err(e) = STORAGE.remove_refresh_token(token).await {
        return e;
    }
    Error::RefreshTokenError
}

static MY_JWT_SECRET: Lazy<[u8; 256]> = Lazy::new(|| {
    let mut a = [0u8; 256];
    rand::thread_rng().fill_bytes(&mut a);
    a
});
static ENCODING_KEY: Lazy<jsonwebtoken::EncodingKey> =
    Lazy::new(|| jsonwebtoken::EncodingKey::from_secret(MY_JWT_SECRET.as_ref()));
static DECODING_KEY: Lazy<jsonwebtoken::DecodingKey> =
    Lazy::new(|| jsonwebtoken::DecodingKey::from_secret(MY_JWT_SECRET.as_ref()));
static VALIDATION_PARAMS: Lazy<jsonwebtoken::Validation> =
    Lazy::new(|| jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS512));

/// Could add this to the access token claims:
/// https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
/// but doesn't seem worthwhile considering that the refresh token serves a similar role - the access
/// token is short-lived and should be kept in memory as opposed to a cookie or sessionStorage /
/// localStorage.
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    email: String,
    role: String,
    exp: i64,
}

#[cfg(not(feature = "dev_cors"))]
const ACCESS_TOKEN_DURATION: i64 = 60;

// use very short duration for testing
#[cfg(feature = "dev_cors")]
const ACCESS_TOKEN_DURATION: i64 = 5;

fn create_jwt(user: &storage::User) -> Result<String, anyhow::Error> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(ACCESS_TOKEN_DURATION))
        .ok_or_else(|| anyhow!("could not make timestamp"))?
        .timestamp();

    let claims = Claims {
        email: user.email.clone(),
        role: user.role.to_str().into(),
        exp,
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS512);
    jsonwebtoken::encode(&header, &claims, &ENCODING_KEY).map_err(|e| anyhow!(e))
}

/// Checks that a request is allowed to proceed based on the authorization header. Returns the
/// email of the user on success. The `auth_header` is checked to ensure it is a valid JWT and that
/// its claims satisfy `role_required`.
///
/// In other words, an error will be returned if the JWT is invalid, or if the JWT is valid but the
/// claimed role is insufficient.
pub fn authorize(role_required: Role, auth_header: String) -> Result<String, Error> {
    const BEARER: &str = "Bearer ";

    if !auth_header.starts_with(BEARER) {
        return Err(Error::InvalidAuthHeaderError);
    }
    let jwt_str = auth_header.trim_start_matches(BEARER);

    let decoded_claims =
        jsonwebtoken::decode::<Claims>(&jwt_str, &DECODING_KEY, &VALIDATION_PARAMS)
            .map_err(|_| Error::JwtTokenError)?;

    if role_required == Role::Admin && Role::from_str(&decoded_claims.claims.role) != Role::Admin {
        return Err(Error::NoPermissionError);
    }

    Ok(decoded_claims.claims.email)
}
