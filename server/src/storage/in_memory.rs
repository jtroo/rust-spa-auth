use crate::{auth, error::Error};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

use std::sync::Arc;

use super::*;

pub struct InMemoryStore {
    users: RwLock<HashMap<String, User>>,
    refresh_tokens: RwLock<HashSet<auth::RefreshToken>>,
}

// None of these functions are actually async. Could have use async locks, but if the critical
// sections are short (which these should be), then it is suggested to use blocking locks.
//
// See:
// https://docs.rs/tokio/1.4.0/tokio/sync/struct.Mutex.html#which-kind-of-mutex-should-you-use
#[async_trait::async_trait]
impl Storage for Arc<InMemoryStore> {
    async fn get_user(&self, email: &str) -> Result<Option<User>, Error> {
        Ok(self.users.read().get(email).cloned())
    }

    async fn store_user(&self, user: User) -> Result<(), Error> {
        self.users.write().insert(user.email.clone(), user);
        Ok(())
    }

    async fn refresh_token_exists(&self, token: &auth::RefreshToken) -> Result<bool, Error> {
        Ok(self.refresh_tokens.read().get(token).is_some())
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

/// Returns an implementer of `Storage + Send + Sync + Clone` that stores data in memory, as
/// opposed to in a file or database.
pub fn new_in_memory_storage() -> Arc<InMemoryStore> {
    Arc::new(InMemoryStore {
        users: RwLock::new(HashMap::new()),
        refresh_tokens: RwLock::new(HashSet::new()),
    })
}
