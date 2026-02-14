pub struct Config {
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub database_path: String,
    pub solana_rpc_url: String,
    pub authority_keypair_path: Option<String>,
    pub program_id: Option<String>,
    /// When true, only attestation verification endpoints are available (no Solana)
    pub attestation_only: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".into())
            .parse::<u16>()
            .map_err(|e| format!("Invalid PORT: {e}"))?;

        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret".into());

        let jwt_expiry_hours = std::env::var("JWT_EXPIRY_HOURS")
            .unwrap_or_else(|_| "168".into())
            .parse::<i64>()
            .map_err(|e| format!("Invalid JWT_EXPIRY_HOURS: {e}"))?;

        let database_path =
            std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/devices.db".into());

        let attestation_only = std::env::var("ATTESTATION_ONLY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let solana_rpc_url = std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".into());

        let authority_keypair_path = std::env::var("AUTHORITY_KEYPAIR_PATH").ok();
        let program_id = std::env::var("PROGRAM_ID").ok();

        Ok(Config {
            host,
            port,
            jwt_secret,
            jwt_expiry_hours,
            database_path,
            solana_rpc_url,
            authority_keypair_path,
            program_id,
            attestation_only,
        })
    }
}
