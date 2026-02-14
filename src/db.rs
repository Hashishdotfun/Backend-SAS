use crate::error::ApiError;
use rusqlite::Connection;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, ApiError> {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ApiError::Db(format!("Failed to create db dir: {e}")))?;
        }

        let conn = Connection::open(path).map_err(|e| ApiError::Db(e.to_string()))?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), ApiError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS verified_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT NOT NULL,
                attestation_pda TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(wallet_address, attestation_pda)
            );
            CREATE INDEX IF NOT EXISTS idx_wallet ON verified_devices(wallet_address);",
        )
        .map_err(|e| ApiError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn upsert_device(&self, wallet: &str, attestation_pda: &str) -> Result<(), ApiError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO verified_devices (wallet_address, attestation_pda, verified_at, last_seen)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(wallet_address, attestation_pda)
             DO UPDATE SET last_seen = ?3",
            rusqlite::params![wallet, attestation_pda, now],
        )?;
        Ok(())
    }
}
