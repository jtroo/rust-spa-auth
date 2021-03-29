//! This module serves as an example for how a data store might be abstracted with multiple
//! implementations. Currently the only data store implemented is an in-memory one using
//! `parking_lot::RwLock` and a `HashMap`.

use crate::auth;
use parking_lot::RwLock;
use std::collections::HashMap;

/// User storage
#[derive(Clone, Debug)]
pub struct User {
    pub email: String,
    pub hashed_pw: String,
    pub role: auth::Role,
}

pub trait Storage {
    fn get_user(&self, email: &str) -> Option<User>;
    fn store_user(&self, user: User) -> Result<(), String>;
}

impl Storage for RwLock<HashMap<String, User>> {
    fn get_user(&self, email: &str) -> Option<User> {
        self.read().get(email).cloned()
    }

    fn store_user(&self, user: User) -> Result<(), String> {
        self.write().insert(user.email.clone(), user);
        Ok(())
    }
}

/// Returns an implementor of `Storage + Send + Sync` that stores data in memory, as opposed to in
/// a file or database.
pub fn new_in_memory_storage() -> impl Storage + Send + Sync {
    RwLock::new(HashMap::<String, User>::new())
}
