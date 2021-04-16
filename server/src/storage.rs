//! This module serves as an example for how a data store might be abstracted with multiple
//! implementations. Currently the only data store implementation is an in-memory one using
//! `parking_lot::RwLock` and `HashSet/HashMap`.
//!
//! A current TODO is to create a database-backed data store implementation.

use crate::{auth, error::Error};

#[cfg(feature = "in_memory")]
mod in_memory;
#[cfg(feature = "in_memory")]
pub use in_memory::*;

#[cfg(not(feature = "in_memory"))]
mod db;
#[cfg(not(feature = "in_memory"))]
pub use db::*;

/// User storage
#[derive(Clone, Debug)]
pub struct User {
    pub email: String,
    pub hashed_pw: String,
    pub role: auth::Role,
}

/// Trait to unify the methods exposed by a data store implementation. The trait methods are async
/// because database access should probably be async for better performance (see sqlx).
#[async_trait::async_trait]
pub trait Storage {
    async fn get_user(&self, email: &str) -> Result<Option<User>, Error>;

    async fn store_user(&self, user: User) -> Result<(), Error>;

    async fn refresh_token_exists(&self, token: &auth::RefreshToken) -> Result<bool, Error>;

    async fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error>;

    async fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error>;
}
