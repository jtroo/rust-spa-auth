//! Provides a database backed implementation of `Storage`. This implementation puts everything in
//! the database, but an alternative implementation could put only the users in the database and
//! keep the refresh tokens in memory.

#[cfg(not(feature = "in_memory"))]
use sqlx::sqlite::SqlitePool;

use super::*;

fn map_sqlx_err(e: sqlx::Error) -> Error {
    log::error!("{}", e);
    Error::InternalError
}

#[cfg(not(feature = "in_memory"))]
#[async_trait::async_trait]
impl Storage for SqlitePool {
    async fn get_user(&self, email: &str) -> Result<Option<User>, Error> {
        sqlx::query_file!(
            "src/storage/get_user.sql",
            email,
        )
        .fetch_optional(self)
        .await
        .map(|maybe_user| {
            maybe_user.map(|u| User {
                email: u.email,
                hashed_pw: u.hashed_pw,
                role: auth::Role::from_str(&u.role),
            })
        })
        .map_err(map_sqlx_err)
    }

    async fn store_user(&self, user: User) -> Result<(), Error> {
        let role = user.role.to_str().to_owned();
        match sqlx::query!(
            "INSERT OR REPLACE INTO users VALUES(?1, ?2, ?3)",
            user.email,
            user.hashed_pw,
            role,
        )
        .execute(self)
        .await
        .map_err(map_sqlx_err)?
        .rows_affected()
        {
            1 => Ok(()),
            0 => {
                log::error!("no rows affected when storing user");
                Err(Error::InternalError)
            }
            _ => {
                log::error!("more than 1 row affected when storing user");
                Err(Error::InternalError)
            }
        }
    }

    async fn refresh_token_exists(&self, token: &auth::RefreshToken) -> Result<bool, Error> {
        sqlx::query!(
            "SELECT expires FROM refresh_tokens WHERE email = ? AND user_agent = ? AND expires = ?",
            token.email,
            token.user_agent,
            token.exp,
        )
        .fetch_optional(self)
        .await
        .map(|t| t.is_some())
        .map_err(map_sqlx_err)
    }

    async fn add_refresh_token(&self, token: auth::RefreshToken) -> Result<(), Error> {
        match sqlx::query!(
            "INSERT OR REPLACE INTO refresh_tokens VALUES(?, ?, ?)",
            token.email,
            token.user_agent,
            token.exp,
        )
        .execute(self)
        .await
        .map_err(map_sqlx_err)?
        .rows_affected()
        {
            1 => Ok(()),
            0 => {
                log::error!("no rows affected when adding token");
                Err(Error::InternalError)
            }
            _ => {
                log::error!("more than 1 row affected when adding token");
                Err(Error::InternalError)
            }
        }
    }

    async fn remove_refresh_token(&self, token: &auth::RefreshToken) -> Result<(), Error> {
        match sqlx::query!(
            "DELETE FROM refresh_tokens WHERE email = ? AND user_agent = ? AND expires = ?",
            token.email,
            token.user_agent,
            token.exp,
        )
        .execute(self)
        .await
        .map_err(map_sqlx_err)?
        .rows_affected()
        {
            1 => Ok(()),
            0 => {
                log::error!("no rows affected when deleting token");
                Err(Error::RefreshTokenError)
            }
            _ => {
                log::error!("more than 1 row affected when deleting token");
                Err(Error::InternalError)
            }
        }
    }
}

/// Returns an implementer of `Storage + Send + Clone` that is backed by the sqlite database
/// provided as the URL input.
#[cfg(not(feature = "in_memory"))]
pub async fn new_db_storage(url: &str) -> Result<SqlitePool, Error> {
    Ok(SqlitePool::connect(url).await.map_err(|e| {
        log::error!("{}", e);
        Error::InternalError
    })?)
}
