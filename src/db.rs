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
                rent_recipient TEXT,
                verified_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(wallet_address, attestation_pda)
            );
            CREATE INDEX IF NOT EXISTS idx_wallet ON verified_devices(wallet_address);",
        )
        .map_err(|e| ApiError::Db(e.to_string()))?;

        let has_rent_recipient = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(verified_devices)")
                .map_err(|e| ApiError::Db(e.to_string()))?;
            let columns = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| ApiError::Db(e.to_string()))?;

            let has_column = columns
                .filter_map(Result::ok)
                .any(|name| name == "rent_recipient");

            has_column
        };

        if !has_rent_recipient {
            conn.execute(
                "ALTER TABLE verified_devices ADD COLUMN rent_recipient TEXT",
                [],
            )
            .map_err(|e| ApiError::Db(e.to_string()))?;
        }

        Ok(())
    }

    pub fn upsert_device(
        &self,
        wallet: &str,
        attestation_pda: &str,
        rent_recipient: Option<&str>,
    ) -> Result<(), ApiError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO verified_devices (wallet_address, attestation_pda, rent_recipient, verified_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(wallet_address, attestation_pda)
             DO UPDATE SET rent_recipient = excluded.rent_recipient, last_seen = ?4",
            rusqlite::params![wallet, attestation_pda, rent_recipient, now],
        )?;
        Ok(())
    }
}
