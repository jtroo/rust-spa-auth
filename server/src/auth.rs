//! Provides functions for authentication
//!

use crate::{error::Error, storage};
use anyhow::anyhow;
use once_cell::sync::Lazy;
use rand::RngCore;
use ring::aead;
use serde::{Deserialize, Serialize};

static STORAGE: Lazy<Box<dyn storage::Storage + Send + Sync>>
    = Lazy::new(|| Box::new(storage::new_in_memory_storage()));

/// Used for role differentiation to showcase authorization of the admin route.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    // Doesn't use std::str::FromStr since that requires a Result and this is infallible.
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

/// Initialize a user and an admin account.
pub fn init_default_users() -> Result<(), anyhow::Error> {
    // also initialize the duration in `pretend_password_processing`
    let rt = tokio::runtime::Runtime::new().expect("could not spawn runtime");
    tokio::task::LocalSet::new().block_on(&rt, pretend_password_processing());

    store_user("user@localhost", "userpassword", Role::User)?;
    store_user("admin@localhost", "adminpassword", Role::Admin)
}

const BCRYPT_COST: u32 = 10;

fn store_user<P: AsRef<[u8]>>(email: &str, pw: P, role: Role) -> Result<(), anyhow::Error> {
    let hashed_pw = bcrypt::hash(pw, BCRYPT_COST)?;
    STORAGE.store_user(
        storage::User {
            email: email.into(),
            hashed_pw,
            role,
        }
    ).map_err(|e| anyhow!(e))
}

// Need to change this if want session persistence after restarting the binary.
static REFRESH_TOKEN_KEY: Lazy<aead::LessSafeKey> = Lazy::new(|| {
    let alg = &aead::CHACHA20_POLY1305;
    let mut key = vec![0u8; alg.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    aead::LessSafeKey::new(aead::UnboundKey::new(&alg, &key).expect("incorrect ring usage"))
});

/// Content of the encrypted+encoded token that is sent in an authenticate response. The
/// `user_agent` field is used to mitigate against token theft. It's not a very good check since
/// the header can easily be faked, but it's at least something. The `email` field is used to
/// ensure that the user that created the token is still valid. The `exp` field is used to ensure
/// that the token has an expire time (good practice?) and needs to re-authenticate once in a
/// while.
///
/// If security is more important than convenience (mobile phones can change IP frequently), can
/// use the L3 source IP address and compare against it. Though according to
/// https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
/// this might have issues with the European GDR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RefreshToken {
    pub user_agent: String,
    pub email: String,
    pub exp: i64,
}

/// 30 days
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
            .ok_or(Error::WrongCredentialsError)?;
        let token_str = nonce_token_strs
            .next()
            .ok_or(Error::WrongCredentialsError)?;
        let nonce_bytes = base64::decode(nonce_str).map_err(|_| Error::WrongCredentialsError)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| Error::WrongCredentialsError)?;
        let mut token_bytes =
            base64::decode(token_str).map_err(|_| Error::WrongCredentialsError)?;
        let token_bin = REFRESH_TOKEN_KEY
            .open_in_place(nonce, aead::Aad::empty(), token_bytes.as_mut())
            .map_err(|_| Error::WrongCredentialsError)?;
        Ok(bincode::deserialize::<RefreshToken>(&token_bin)
            .map_err(|_| Error::WrongCredentialsError)?)
    }
}

fn add_refresh_token(user_agent: &str, email: &str) -> Result<String, Error> {
    let token = RefreshToken::new(user_agent, email)?;
    let ret = token.encrypt_encode()?;
    STORAGE.add_refresh_token(token)?;
    Ok(ret)
}

#[derive(Deserialize)]
pub struct AuthenticateRequest {
    pub email: String,
    pub pw: String,
}

/// On success, returns a refresh token that can be used to get access tokens.
///
/// The refresh token is opaque and should only be able to be read by this server.
///
/// This contrasts the access token which is a JWT and has claims that are publicly visible. The
/// claims in an access token can be used by the client-side code to manipulate what the user can
/// see based on the claims.
///
/// Unlike the access token, the browser has does not need to know what's inside a refresh token -
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
    user_agent: String,
    req: AuthenticateRequest,
) -> Result<(String, i64), Error> {
    let user = match STORAGE.get_user(&req.email) {
        Some(v) => v,
        None => {
            return Err(pretend_password_processing().await);
        }
    };
    tokio::task::spawn_blocking(
        move || {
                match bcrypt::verify(&req.pw, &user.hashed_pw).map_err(|e| {
                println!("bcrypt verify err: {}", e);
                Error::InternalError
            })? {
                true => Ok(
                    (
                        add_refresh_token(&user_agent, &user.email)?,
                        REFRESH_TOKEN_MAX_AGE_SECS,
                    )
                ),
                false => Err(Error::WrongCredentialsError),
        }
    }).await.map_err(|e| {
        println!("tokio err {}", e);
        Error::InternalError
    })?
}

/// This exists to pretend that a password is being processed in the cases where it's not. This
/// makes it harder to guess if a malicious request got an existing email with non-matching
/// password, vs. an email that does not exist.
///
/// There is currently a bug - on the first time this function is called, the delay is a lot longer
/// than on every other call. A workaround is to call this function at some point during
/// initialization. I'm too `Lazy` to fix it, so it's called in `init_default_users` to do the
/// workaround.
async fn pretend_password_processing() -> Error {
    static PROCESSING_TIME: Lazy<std::time::Duration> = Lazy::new(|| {
        let hashed_pw = bcrypt::hash("badpassword", BCRYPT_COST).expect("could not hash pw");
        let start = std::time::Instant::now();
        let _ = bcrypt::verify("abcdefg", &hashed_pw);
        let end = std::time::Instant::now();
        end - start
    });
    println!("pretending to process password - should be an invalid email");
    tokio::time::sleep(*PROCESSING_TIME).await;
    Error::WrongCredentialsError
}

/// On success, returns an access token that can be used to authorize with other APIs.
///
/// The access request includes a refresh token that will only work for the L3 IP and user agent
/// that originally created the token. If the provided token is used from a different IP or user
/// agent, then the token will be invalidated.
pub fn access(user_agent: &str, refresh_token: &str) -> Result<String, Error> {
    let refresh_token = RefreshToken::from_str(refresh_token)?;

    // make sure the token is known
    if !STORAGE.refresh_token_exists(&refresh_token) {
        return Err(Error::WrongCredentialsError);
    }

    // remove token if expired
    if refresh_token.exp < chrono::Utc::now().timestamp() {
        return Err(remove_bad_refresh_token(&refresh_token));
    }

    // ensure token is used by same user agent and originates from same IP
    if user_agent != refresh_token.user_agent {
        println!(
            "token used by different agent {}, token: {:?}",
            user_agent, &refresh_token
        );
        return Err(remove_bad_refresh_token(&refresh_token));
    }

    let user = STORAGE.get_user(&refresh_token.email).ok_or_else(|| {
        println!("valid token for non-existent email {:?}", refresh_token);
        remove_bad_refresh_token(&refresh_token)
    })?;

    create_jwt(&user).map_err(|e| {
        println!("jwt create err: {}", e);
        Error::InternalError
    })
}

/// Remove a bad refresh token from the set of known tokens.
fn remove_bad_refresh_token(
    token: &RefreshToken,
) -> Error {
    if let Err(e) = STORAGE.remove_refresh_token(token) {
        return e;
    }
    Error::WrongCredentialsError
}

static MY_SECRET: Lazy<[u8; 256]> = Lazy::new(|| {
    let mut a = [0u8; 256];
    rand::thread_rng().fill_bytes(&mut a);
    a
});
static ENCODING_KEY: Lazy<jsonwebtoken::EncodingKey> =
    Lazy::new(|| jsonwebtoken::EncodingKey::from_secret(MY_SECRET.as_ref()));
static DECODING_KEY: Lazy<jsonwebtoken::DecodingKey> =
    Lazy::new(|| jsonwebtoken::DecodingKey::from_secret(MY_SECRET.as_ref()));
static VALIDATION_PARAMS: Lazy<jsonwebtoken::Validation> =
    Lazy::new(|| jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS512));

/// Could add this to the access token claims:
/// https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking
/// but doesn't seem worthwhile considering that the access token is short-lived and should be kept
/// in memory as opposed to a cookie or sessionStorage / localStorage.
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    email: String,
    role: String,
    exp: i64,
}

fn create_jwt(user: &storage::User) -> Result<String, anyhow::Error> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
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
            .map_err(|_| Error::JWTTokenError)?;

    if role_required == Role::Admin && Role::from_str(&decoded_claims.claims.role) != Role::Admin {
        return Err(Error::NoPermissionError);
    }

    Ok(decoded_claims.claims.email)
}
