use anyhow::Result;
use rusqlite::Connection;

use crate::config::get_config_path;

pub fn create_conn() -> Result<Connection> {
    let db_path = get_config_path().join("metrics.db");
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            cached BOOLEAN NOT NULL,
            blacklisted BOOLEAN NOT NULL
        )", [],
    )?;

    Ok(conn)
}
