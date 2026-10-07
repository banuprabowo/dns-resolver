use std::net::Ipv4Addr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::RngExt;
use rusqlite::Connection;
use serde::{Serialize, Deserialize};
use crate::blocklist_api::{AppError, AppState};

#[derive(Serialize, Deserialize, Debug)]
pub struct AddPeer {
    pub device_name: String,
    pub pub_key: String,
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
    Json(payload): Json<AddPeer>
) -> Result<StatusCode, AppError> {
    let conn = Connection::open(&state.db_path)?;
    let start_ip = Ipv4Addr::new(10, 13, 13, 2);
    let end_ip = Ipv4Addr::new(10, 13, 13, 254);
    let device_name = payload.device_name;
    let pub_key = payload.pub_key;

    let mut ip_set = state.ip_set.write().await;
    const MAX_ATTEMPTS: u32 = 20;
    let mut claimed_ip = None;


   for _ in 0..MAX_ATTEMPTS {
       let candidate = create_ip(&start_ip, &end_ip);

       if ip_set.contains(&candidate.to_string()) {
           continue;
       }

       ip_set.insert(candidate.to_string());

       let rows = conn.execute("INSERT OR IGNORE INTO peer (ip_address, device_name, pub_key) VALUES (?1, ?2, ?3)",[&candidate.to_string(), &device_name, &pub_key],
       )?;

       if rows > 0 {
           claimed_ip = Some(candidate);
           break;
       }else {
           ip_set.remove(&candidate.to_string());
       }
   }
    match claimed_ip {
        Some(_ip) => Ok(StatusCode::CREATED),
        None => {
            tracing::warn!("could not find a free ip after {MAX_ATTEMPTS} attempts");
            Ok(StatusCode::SERVICE_UNAVAILABLE)
        }
    }

}