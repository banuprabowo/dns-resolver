use std::collections::HashSet;
use std::sync::Arc;
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    Json,
};
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use crate::StatsDb;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Database error:{0}")]
    DatabaseError(#[from] rusqlite::Error),
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) blocklist: Arc<RwLock<HashSet<String>>>,
    pub(crate) db_path: String,
    pub(crate) stats_db: StatsDb,
}

#[derive(Serialize)]
pub(crate) struct DomainStat {
    domain: String,
    blocked_count: i64,
    allowed_count: i64,
}

#[derive(Deserialize)]
pub(crate) struct AddDomainRequest {
    domain: String,
}

#[derive(Serialize)]
pub(crate) struct DomainList{
    domains: Vec<String>,
}


#[derive(Serialize)]
pub(crate) struct SuggestedDomain {
    domain: String,
    allowed_count: i64,
}

const SUGGESTION_MIN_COUNT:i64 = 3;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "Database error occurred");
        let (status, response) = match self {
            AppError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
        };

        let body = Json(json!({
            "error": response,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

pub(crate) async fn get_suggestion(State(state): State<AppState>) -> Result<Json<Vec<SuggestedDomain>>, AppError> {
    let conn = state.stats_db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT domain, allowed_count FROM domain_stats WHERE domain NOT IN (SELECT domain from blocklist) AND allowed_count >= ?1 ORDER BY allowed_count DESC",
        )?;
    let rows = stmt
        .query_map([SUGGESTION_MIN_COUNT], |row| {
            Ok(SuggestedDomain {domain: row.get(0)?, allowed_count: row.get(1)?})
        })?;

    //Option 1
    match rows.collect() {
        Ok(suggestion)=> Ok(Json(suggestion)),
        Err(e) => Err(AppError::DatabaseError(e)),
    }

    //Option 2
    // let suggestion = rows.collect::<Result<Vec<_>, _>>()?;
    // Ok(Json(suggestion))
}
pub(crate) async fn get_stats(State(state): State<AppState>) -> Result<Json<Vec<DomainStat>>, AppError> {
    let conn = state.stats_db.lock().await;
    let mut stmt = conn.prepare("SELECT domain, blocked_count, allowed_count FROM domain_stats ORDER by blocked_count DESC")?;
    let rows = stmt.query_map((), |row| {
        Ok(DomainStat {
            domain: row.get(0)?,
            blocked_count: row.get(1)?,
            allowed_count: row.get(2)?,
        })
    })?;

    //Option 1
    match rows.collect() {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(AppError::DatabaseError(e)),
    }

    //Option 2
    // let stats = rows.collect::Result<Vec<_>,_>>()?;
    // Ok(Json(stats))

}

pub(crate) async fn list_domains(State(state): State<AppState>) -> Json<DomainList>{
    let list = state.blocklist.read().await;
    Json(DomainList{domains: list.iter().cloned().collect()})
}

pub(crate) async fn add_domain(
    State(state): State<AppState>,
    Json(payload): Json<AddDomainRequest>,
) -> Result<StatusCode, AppError> {
    let domain = payload.domain.trim().to_lowercase();
    let conn = Connection::open(&state.db_path)?;
    let result = conn.execute("INSERT OR IGNORE INTO blocklist (domain) VALUES (?1)", [&domain])?;

    match result {
        0 => Ok(StatusCode::OK),
        _ => {
            state.blocklist.write().await.insert(domain);
            Ok(StatusCode::CREATED)
        },
    }
}

pub(crate) async fn remove_domain(
    State(state): State<AppState>,
    AxumPath(domain): AxumPath<String>,
) -> Result<StatusCode, AppError> {
    let conn = Connection::open(&state.db_path)?;
    let result = conn.execute("DELETE FROM blocklist WHERE domain = ?1", [&domain])?;

    match result {
        0 => Ok(StatusCode::NOT_FOUND),
        _ => {
            state.blocklist.write().await.remove(&domain);
            Ok(StatusCode::NO_CONTENT)
        },
    }
}