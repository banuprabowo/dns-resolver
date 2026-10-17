use crate::blocklist_api::{AppError, AppState};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rand::RngExt;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

const WG_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: u32 = 20;
const MAX_DEVICE_NAME_CHARS: usize = 64;

#[derive(Serialize, Deserialize, Debug)]
pub struct AddPeer {
    pub device_name: String,
    pub pub_key: String,
}

#[derive(Serialize, Debug)]
pub struct PeerResponse {
    pub server_pub_key: String,
    pub endpoint: String,
    pub ip: Ipv4Addr,
}

async fn set_wg(pub_key: &str, ip: &Ipv4Addr) -> Result<(), AppError> {
    let allowed_ip = format!("{ip}/32");

    let output = tokio::process::Command::new("wg")
        .arg("set")
        .arg("wg0")
        .arg("peer")
        .arg(pub_key)
        .arg("allowed-ips")
        .arg(allowed_ip)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| AppError::WireguardError(format!("could not run wg: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(AppError::WireguardError(format!("wg: {stderr}")));
    }
    Ok(())
}

fn validate_pub_key(pub_key: &str) -> bool {
    if pub_key.len() != 44 {
        return false;
    }

    if !pub_key.ends_with("=") {
        return false;
    }

    let base_64payload = &pub_key[..43];
    base_64payload
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

fn validate_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_DEVICE_NAME_CHARS
        && name.chars().all(|c| !c.is_control())
}

fn pub_key_exists(conn: &Connection, pub_key: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM peer WHERE pub_key = ?1)",
        [pub_key],
        |row| row.get(0),
    )
}

fn create_ip(start: &Ipv4Addr, end: &Ipv4Addr) -> Ipv4Addr {
    let start_num = u32::from(*start);
    let end_num = u32::from(*end);

    let mut rng = rand::rng();
    let random_u32 = rng.random_range(start_num..=end_num);

    Ipv4Addr::from(random_u32)
}

pub async fn add_peer(
    State(state): State<AppState>,
    Json(payload): Json<AddPeer>,
) -> Result<(StatusCode, Json<PeerResponse>), AppError> {
    let pub_key = payload.pub_key;
    let device_name = payload.device_name.trim().to_string();

    if !validate_pub_key(&pub_key) {
        return Err(AppError::InvalidPublicKey);
    }
    if !validate_device_name(&device_name) {
        return Err(AppError::InvalidDeviceName);
    }
    let conn = Connection::open(&state.db_path)?;
    let start_ip = Ipv4Addr::new(10, 13, 13, 2);
    let end_ip = Ipv4Addr::new(10, 13, 13, 254);

    let mut ip_set = state.ip_set.write().await;

    if pub_key_exists(&conn, &pub_key)? {
        return Err(AppError::DuplicatePublicKey);
    }

    let mut claimed_ip = None;

    for _ in 0..MAX_ATTEMPTS {
        let candidate = create_ip(&start_ip, &end_ip);
        let candidate_str = candidate.to_string();

        if ip_set.contains(&candidate_str) {
            continue;
        }

        let rows = conn.execute(
            "INSERT OR IGNORE INTO peer (ip_address, device_name, pub_key) VALUES (?1, ?2, ?3)",
            [&candidate_str, &device_name, &pub_key],
        )?;

        if rows > 0 {
            ip_set.insert(candidate_str);
            claimed_ip = Some(candidate);
            break;
        }
    }
    match claimed_ip {
        Some(ip) => {
            let wg_result = timeout(WG_TIMEOUT, set_wg(&pub_key, &ip))
                .await
                .unwrap_or_else(|_| Err(AppError::WireguardError("wireguard timeout".to_string())));

            if let Err(e) = wg_result {
                ip_set.remove(&ip.to_string());
                if let Err(db_err) =
                    conn.execute("DELETE FROM peer WHERE ip_address = ?1", [&ip.to_string()])
                {
                    tracing::error!(error = %db_err, ip = %ip, "rollback failed: peer row left behind");
                }
                return Err(e);
            }
            Ok((
                StatusCode::CREATED,
                Json(PeerResponse {
                    ip,
                    server_pub_key: state.server_pub_key.clone(),
                    endpoint: state.server_endpoint.clone(),
                }),
            ))
        }
        None => {
            tracing::warn!("could not find a free ip after {MAX_ATTEMPTS} attempts");
            Err(AppError::NoFreeIpAddress)?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::{Mutex, RwLock};

    fn good_key() -> String {
        format!("{}=", "A".repeat(43))
    }

    // One temp dir (so one SQLite file and one ip_set) per test,
    // because tests run in parallel by default.
    fn test_state(dir: &tempfile::TempDir) -> AppState {
        let db_path = dir.path().join("test.db").to_string_lossy().to_string();
        let ip_set = crate::load_peer(&db_path).unwrap(); // real schema, empty set
        AppState {
            blocklist: Arc::new(RwLock::new(HashSet::new())),
            ip_set: Arc::new(RwLock::new(ip_set)),
            db_path,
            stats_db: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            admin_private_key: "test".to_string(),
            server_pub_key: "server-key".to_string(),
            server_endpoint: "127.0.0.1:51820".to_string(),
        }
    }

    fn request(device_name: &str, pub_key: String) -> Json<AddPeer> {
        Json(AddPeer {
            device_name: device_name.into(),
            pub_key,
        })
    }

    fn peer_count(state: &AppState) -> i64 {
        Connection::open(&state.db_path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM peer", [], |row| row.get(0))
            .unwrap()
    }

    // --- validate_pub_key -------------------------------------------------

    #[test]
    fn accepts_well_formed_key() {
        // Positive control: without this, a validator that rejected
        // everything would still pass every rejection test below.
        assert!(validate_pub_key(&good_key()));
    }

    #[test]
    fn rejects_key_with_leading_dash() {
        let key = format!("-{}=", "A".repeat(42));
        assert!(!validate_pub_key(&key));
    }

    #[test]
    fn rejects_wrong_length_and_missing_padding() {
        assert!(!validate_pub_key("short="));
        assert!(!validate_pub_key(&"A".repeat(44)));
        assert!(!validate_pub_key(&format!("{}==", "A".repeat(43))));
    }

    #[test]
    fn rejects_multibyte_char_without_panicking() {
        // 44 bytes long and ends with '=', but starts with a 2-byte char.
        let key = format!("é{}=", "A".repeat(41));
        assert_eq!(key.len(), 44);
        assert!(!validate_pub_key(&key));
    }

    // --- validate_device_name ---------------------------------------------

    #[test]
    fn device_name_rules() {
        assert!(validate_device_name("Dad's phone"));
        assert!(validate_device_name(&"x".repeat(MAX_DEVICE_NAME_CHARS)));
        assert!(!validate_device_name(""));
        assert!(!validate_device_name(
            &"x".repeat(MAX_DEVICE_NAME_CHARS + 1)
        ));
        assert!(!validate_device_name("bad\nname"));
    }

    // --- add_peer: paths that return before wg is ever called -------------

    #[tokio::test]
    async fn garbage_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        let result = add_peer(State(state.clone()), request("phone", "not-a-key".into())).await;

        assert!(matches!(result, Err(AppError::InvalidPublicKey)));
        assert_eq!(peer_count(&state), 0);
    }

    #[tokio::test]
    async fn blank_device_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        let result = add_peer(State(state.clone()), request("   ", good_key())).await;

        assert!(matches!(result, Err(AppError::InvalidDeviceName)));
        assert_eq!(peer_count(&state), 0);
    }

    #[tokio::test]
    async fn duplicate_key_is_rejected_and_claims_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        Connection::open(&state.db_path)
            .unwrap()
            .execute(
                "INSERT INTO peer (ip_address, device_name, pub_key) VALUES ('10.13.13.9', 'old', ?1)",
                [good_key()],
            )
            .unwrap();

        let result = add_peer(State(state.clone()), request("new", good_key())).await;

        assert!(matches!(result, Err(AppError::DuplicatePublicKey)));
        assert_eq!(peer_count(&state), 1);
        assert!(state.ip_set.read().await.is_empty());
    }

    #[tokio::test]
    async fn full_range_returns_no_free_ip() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        {
            let mut set = state.ip_set.write().await;
            for last in 2..=254 {
                set.insert(format!("10.13.13.{last}"));
            }
        }

        let result = add_peer(State(state.clone()), request("phone", good_key())).await;

        assert!(matches!(result, Err(AppError::NoFreeIpAddress)));
        assert_eq!(peer_count(&state), 0);
    }

    #[tokio::test]
    async fn failed_insert_does_not_leak_ip_into_ip_set() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        // Make every INSERT fail with a real SQLite error.
        Connection::open(&state.db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_insert BEFORE INSERT ON peer
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();

        let result = add_peer(State(state.clone()), request("phone", good_key())).await;

        assert!(matches!(result, Err(AppError::DatabaseError(_))));
        assert!(state.ip_set.read().await.is_empty());
    }
}
