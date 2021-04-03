//! This module serves as an example for how a data store might be abstracted with multiple
//! implementations. Currently the only data store implementation is an in-memory one using
//! `parking_lot::RwLock` and `HashSet/HashMap`.
//!
//! A current TODO is to create a database-backed data store implementation.

use crate::auth;
use crate::error::Error;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

/// User storage
#[derive(Clone, Debug)]
pub struct User {
    pub email: String,
    pub hashed_pw: String,
    pub role: auth::Role,
}

struct InMemoryStore {
    users: RwLock<HashMap<String, User>>,
    refresh_tokens: RwLock<HashSet<auth::RefreshToken>>,
}

/// Trait to unify the methods exposed by a data store implementation. The trait methods are async
/// because database access should probably be async for better performance (see sqlx).
#[async_trait::async_trait]
pub trait Storage {
    async fn get_user(&self, email: &str) -> Option<User>;

    async fn store_user(&self, user: User) -> Result<(), Error>;

    async fn refresh_token_exists(&self, token: &auth::RefreshToken) -> bool;

    async fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error>;

    async fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error>;
}

// None of these functions are actually async. Could have use tokio's async locks, but if the
// critical sections are short (which these should be), then it is suggested to use blocking locks.
//
// See:
// https://docs.rs/tokio/1.4.0/tokio/sync/struct.Mutex.html#which-kind-of-mutex-should-you-use
#[async_trait::async_trait]
impl Storage for InMemoryStore {
    async fn get_user(&self, email: &str) -> Option<User> {
        self.users.read().get(email).cloned()
    }

    async fn store_user(&self, user: User) -> Result<(), Error> {
        self.users.write().insert(user.email.clone(), user);
        Ok(())
    }

    async fn refresh_token_exists(&self, token: &auth::RefreshToken) -> bool {
        self.refresh_tokens.read().get(token).is_some()
    }

    async fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error> {
        self.refresh_tokens.write().insert(token);
        Ok(())
    }

    async fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error> {
        self.refresh_tokens.write().remove(token);
        Ok(())
    }
}

/// Returns an implementer of `Storage + Send + Sync` that stores data in memory, as opposed to in
/// a file or database.
pub fn new_in_memory_storage() -> impl Storage + Send + Sync {
    InMemoryStore {
        users: RwLock::new(HashMap::new()),
        refresh_tokens: RwLock::new(HashSet::new()),
    }
}
