pub mod blocklist_api;

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    serialize::{binary::{
        BinDecodable, BinEncodable
    }}
};
use std::{collections::{HashSet}, env, net::SocketAddr, sync::Arc};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};
use axum::{Router, routing::get};
use dotenvy::dotenv;
use rusqlite::Connection;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use blocklist_api::{AppState, list_domains, add_domain, remove_domain};
use crate::blocklist_api::{get_stats, get_suggestion};


type StatsDb = Arc<Mutex<Connection>>;
type DnsCache = Arc<RwLock<HashMap<(String, String), CachedEntity>>>;
type PendingMap = Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;

#[derive(Clone,Debug)]
struct CachedEntity {
    expiry : Instant,
    data: Message,
}


fn load_blocklist(db_path: &str) -> rusqlite::Result<HashSet<String>> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY)",(),
    )?;

    // Seed a couple of test entries so there's something to test against
    // immediately. Harmless once real entries exist — INSERT OR IGNORE
    // just skips rows that already have that domain.
    conn.execute(
        "INSERT OR IGNORE INTO blocklist (domain) VALUES ('doubleclick.net')",
        (),
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO blocklist (domain) VALUES ('example-ads.com')",
        (),
    )?;

    let mut stmt = conn.prepare("SELECT domain FROM blocklist")?;
    let rows = stmt.query_map((), |row| row.get::<_, String>(0))?;

    let mut set = HashSet::new();
    for domain in rows {
        set.insert(domain?);
    }

    Ok(set)
}

fn open_stats_db(db_path:&str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS domain_stats ( \
        domain TEXT PRIMARY KEY, \
        blocked_count INTEGER NULL DEFAULT 0, \
        allowed_count INTEGER NULL DEFAULT 0)",(),
    )?;
    Ok(conn)
}

async fn record_stat(stats_db: &StatsDb, domain: &str, blocked: bool) {
    let column =  if blocked {"blocked_count"} else {"allowed_count"};
    // Safe to interpolate here specifically: `column` only ever comes from
    // the two hardcoded strings above, never from the query itself — the
    // actual untrusted value (`domain`) still goes through a bound parameter.
    let sql = format!(
        "INSERT INTO domain_stats (domain, {column}) VALUES ($1, 1) ON CONFLICT(domain) DO UPDATE SET {column} = {column} + 1"
    );
    let conn = stats_db.lock().await;
    if let Err(e) = conn.execute(&sql, [domain]) {
        tracing::warn!(domain = %domain, error = %e, "failed to record stat");
    }
}

fn is_blocked(domain: &str, blocklist: &HashSet<String>) -> bool {
    let domain = domain.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();

    // Check the full domain, then progressively shorter suffixes:
    // "ads.doubleclick.net" -> "doubleclick.net" -> "net"
    // Matches if ANY level is in the blocklist — one entry for
    // "doubleclick.net" now also catches every subdomain of it.
    for i in 0..labels.len() {
        let candidate = labels[i..].join(".");
        if blocklist.contains(&candidate){
            return true;
        }
    }
    false
}

fn build_nxdomain(query: &Message) -> Message {
    let mut resp = Message::new(query.id, MessageType::Response, query.op_code);
    resp.metadata.authoritative = true;
    resp.metadata.response_code = ResponseCode::NXDomain;
    if let Some(q) = query.queries.first(){
        resp.add_query(q.clone());
    }
    resp
}

fn build_servfail(query: &Message) -> Message {
    let mut resp = Message::new(query.id, MessageType::Response, query.op_code);
    resp.metadata.authoritative = true;
    resp.metadata.response_code = ResponseCode::ServFail;
    if let Some(q) = query.queries.first(){
        resp.add_query(q.clone());
    }
    resp
}

fn build_cached_response(cached: Message, cache_id: u16) -> Message {
   let mut resp = Message::new(cache_id, MessageType::Response, cached.op_code);
    resp.metadata.authoritative = true;
    resp.metadata.response_code = cached.response_code;
    for answer in cached.answers {
        resp.add_answer(answer.clone());
    }
    resp
}

fn build_new_query(query: &Message, new_id: u16) -> Message {
    let mut queries = Message::new(new_id, MessageType::Query, query.op_code);
    for q in query.queries.iter() {
        queries.add_query(q.clone());
    };
    queries
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Variable from env
    let db_path = env::var("DB_PATH").unwrap_or_else(|_| "blocklist.db".to_string());
    let listen_addr = env::var("LISTEN_ADDR").unwrap_or_else(|_| "10.13.13.1:53".to_string());
    let upstream_dns = env::var("UPSTREAM_DNS").unwrap_or_else(|_| "1.1.1.1:53".to_string());
    let api_listen_addr = env::var("API_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let upstream_timeout_secs: u64 = env::var("UPSTREAM_TIMEOUT_SECS").unwrap_or_else(|_|"15".to_string()).parse()?;

    let blocklist: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(load_blocklist(&db_path)?));
    tracing::info!(count = %blocklist.read().await.len(), "blocklist loaded");
    let dns_cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
    let pending_map: PendingMap = Arc::new(Mutex::new(HashMap::new()));


    let stats_db: StatsDb = Arc::new(Mutex::new(open_stats_db(&db_path)?));
    let stats_count: i64 = {
        let conn = stats_db.lock().await;
        conn.query_row("SELECT COUNT(*) FROM domain_stats", [], |row| row.get(0))?
    };
    tracing::info!(count = %stats_count, "loaded stats");


    let app_state = AppState{
        blocklist: blocklist.clone(),
        db_path: db_path,
        stats_db: stats_db.clone(),
    };

    let api_router = Router::new()
        .route("/domains", get(list_domains).post(add_domain))
        .route("/domains/{domain}", axum::routing::delete(remove_domain))
        .route("/stats", get(get_stats))
        .route("/suggestions", get(get_suggestion))
        .with_state(app_state);

    let api_listener = tokio::net::TcpListener::bind(&api_listen_addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, api_router).await {
            tracing::error!("api listener stopped: {e}");
        }
    });

    println!("Started http DNS resolver");

    let socket = Arc::new(UdpSocket::bind(&listen_addr).await?);
    let upstream_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    upstream_socket.connect(&upstream_dns).await?;
    tracing::info!("DNS resolver listening on {listen_addr}");

    let mut buf = [0u8;512];
    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        let upstream_socket = upstream_socket.clone();
        let query_bytes = buf[..len].to_vec();
        let socket = socket.clone();
        let blocklist = blocklist.clone();
        let stats_db = stats_db.clone();
        let dns_cache = dns_cache.clone();
        let pending_map = pending_map.clone();
        let upstream_timeout_secs = upstream_timeout_secs;

        // Handle each query on its own task so one slow upstream_socket lookup
        // doesn't stall queries from other devices.
        tokio::spawn(async move {
            if let Err(e) = handle_query(socket,upstream_socket, query_bytes,client_addr, blocklist, stats_db, dns_cache, pending_map, upstream_timeout_secs).await {
                tracing::error!(error = %e, "error handling query");
            }
        });
    }
}


async fn handle_query(
    socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    query_bytes: Vec<u8>,
    client_addr: SocketAddr,
    blocklist: Arc<RwLock<HashSet<String>>>,
    stats_db: StatsDb,
    dns_cache: DnsCache,
    pending_map: PendingMap,
    upstream_timeout_secs: u64,
) -> std::io::Result<()> {
    let query = match Message::from_bytes(&query_bytes) {
        Ok(m) => m,
        Err(_) => return Ok(()) // not a valid DNS Message - silently drop
    };

    let (tx, rx) = oneshot::channel();

    // Take domain name from query
    let domain = query.queries.first().map(|q| q.name().to_string()).unwrap_or_default();
    let query_type = query.queries.first().map(|q|q.query_type.to_string()).unwrap_or_default();

    // Check if domain in blocklist
    let blocked = {
        let list = blocklist.read().await;
        is_blocked(&domain, &list)
    };

    record_stat(&stats_db, &domain, blocked).await;

    // if blocked send nxdomain to client
    if blocked {
        tracing::info!(domain = %domain, "blocked");
        let response = build_nxdomain(&query);
        if let Ok(response_byte) = response.to_vec() {
            socket.send_to(&response_byte, client_addr).await?;
        }
        return Ok(())
    }

    tracing::info!(domain = %domain, "allowed");

    // Cached Block
    let keys = (domain.clone(), query_type.clone());

    let cache_hit = {
        let cache = dns_cache.read().await;
        cache.get(&keys).filter(|c| c.expiry > Instant::now()).cloned()
    };

    if let Some(cache) = cache_hit {
        let response = build_cached_response(cache.data,query.id);
        if let Ok(response_byte) = response.to_vec() {
            socket.send_to(&response_byte, client_addr).await?;
        }
        return Ok(())
    }

    let mut new_id= rand::random::<u16>();
    let mut lock = pending_map.lock().await;

    let finalize_id = {
        loop {
            match lock.entry(new_id) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    tracing::info!(new_id = %new_id, "Collision detected! Generate a new id...");
                    new_id = rand::random::<u16>();
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(tx);
                    tracing::info!(new_id = %new_id, "Unique ID secured and inserted");
                    break new_id;
                }
            }
        }
    };



    // Forward the exact original query bytes upstream_socket, unchanged, then
    // relay whatever comes back — no need to reparse the reply.
    let new_query = build_new_query(&query, finalize_id);
    if let Ok(query_bytes) = new_query.to_vec() {
        upstream_socket.send(&query_bytes).await?;
    }

    let mut upstream_buf = [0u8; 512];
    let upstream_resp = upstream_socket.recv(&mut upstream_buf);

    match timeout (Duration::from_secs(upstream_timeout_secs), upstream_resp).await {
        Ok(result) => {
            let n = result?;
            if let Ok(q) = Message::from_bytes(&upstream_buf[..n]) {
                let record = q.clone();
                // Write DnsCache
                if let Some(ttl) = record.answers.get(0) {
                    let expiry = Instant::now() + Duration::from_secs(ttl.ttl.into());
                    dns_cache.write().await.insert(
                        (domain, query_type),
                        CachedEntity {
                            expiry,
                            data: record,
                        }
                    );
                }
            }

            socket.send_to(&upstream_buf[..n], client_addr).await?;
            tracing::info!("Query forwarded to upstream");
        }
        Err(_elapsed) => {
            tracing::warn!(domain = %domain, "Upstream DNS request timed out");
            let response = build_servfail(&query);
            if let Ok(response_byte) = response.to_vec() {
                socket.send_to(&response_byte, client_addr).await?;
            }
        }
    }
     Ok(())
}
