//! This module serves as an example for how a data store might be abstracted with multiple
//! implementations. Currently the only data store implementation is an in-memory one using
//! `parking_lot::RwLock` and `HashSet/HashMap`.

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

pub trait Storage {
    fn get_user(&self, email: &str) -> Option<User>;

    fn store_user(&self, user: User) -> Result<(), Error>;

    fn refresh_token_exists(&self, token: &auth::RefreshToken) -> bool;

    fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error>;

    fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error>;
}

impl Storage for InMemoryStore {
    fn get_user(&self, email: &str) -> Option<User> {
        self.users.read().get(email).cloned()
    }

    fn store_user(&self, user: User) -> Result<(), Error> {
        self.users.write().insert(user.email.clone(), user);
        Ok(())
    }

    fn refresh_token_exists(&self, token: &auth::RefreshToken) -> bool {
        self.refresh_tokens.read().get(token).is_some()
    }

    fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error> {
        self.refresh_tokens.write().insert(token);
        Ok(())
    }

    fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error> {
        self.refresh_tokens.write().remove(token);
        Ok(())
    }
}

/// Returns an implementor of `Storage + Send + Sync` that stores data in memory, as opposed to in
/// a file or database.
pub fn new_in_memory_storage() -> impl Storage + Send + Sync {
    InMemoryStore {
        users: RwLock::new(HashMap::new()),
        refresh_tokens: RwLock::new(HashSet::new()),
    }
}
