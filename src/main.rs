mod attestation_tx;
mod config;
mod db;
mod error;
mod hw_attest;
mod jwt;

use actix_web::{get, post, web, App, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::db::Database;
use crate::error::ApiError;

pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub solana_rpc_url: String,
    /// Raw 64-byte keypair (Keypair is !Sync, so we store bytes and reconstruct)
    pub authority_keypair_bytes: Option<Vec<u8>>,
    pub program_id: Option<Pubkey>,
    /// Pending challenges: nonce → (created_at). Expire after 5 minutes.
    pub challenges: Mutex<HashMap<String, Instant>>,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Deserialize)]
struct VerifyDeviceRequest {
    /// Base64-encoded DER certificate chain from Android Key Attestation
    certificate_chain: Vec<String>,
    /// The challenge nonce that was used
    challenge: String,
    /// Wallet address (base58, to bind the attestation to)
    wallet_address: String,
}

#[derive(Deserialize)]
struct VerifyDeviceOnlyRequest {
    /// Base64-encoded DER certificate chain from Android Key Attestation
    certificate_chain: Vec<String>,
    /// The challenge nonce that was used
    challenge: String,
}

#[derive(Serialize)]
struct VerifyDeviceResponse {
    verified: bool,
    device: Option<String>,
    /// Base64-encoded partially signed transaction (create_attestation)
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_tx: Option<String>,
    /// Base58 attestation PDA address
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_pda: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct DeviceInfoResponse {
    brand: String,
    model: String,
    manufacturer: String,
    product: String,
    attestation_security_level: String,
    keymaster_security_level: String,
    verified_boot_state: String,
    device_locked: bool,
    app_package_name: Option<String>,
    app_signature_digests: Vec<String>,
    os_version: Option<String>,
    os_patch_level: Option<String>,
    attestation_version: i64,
    /// Tags found in softwareEnforced (debug)
    sw_tags: Vec<u32>,
    /// Tags found in teeEnforced (debug)
    tee_tags: Vec<u32>,
}

#[derive(Serialize)]
struct VerifyDeviceOnlyResponse {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_info: Option<DeviceInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[get("/health")]
async fn health(state: web::Data<Arc<AppState>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "mode": if state.config.attestation_only { "attestation-only" } else { "full" }
    }))
}

/// Step 1: Get a challenge nonce from the server.
/// The app will use this to create an attested key in the TEE.
#[get("/api/v1/challenge")]
async fn get_challenge(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let challenge = hw_attest::generate_challenge();

    {
        let mut challenges = state.challenges.lock().unwrap();
        let cutoff = Instant::now() - Duration::from_secs(300);
        challenges.retain(|_, created| *created > cutoff);
        challenges.insert(challenge.clone(), Instant::now());
    }

    HttpResponse::Ok().json(ChallengeResponse { challenge })
}

/// Attestation-only endpoint: verify device TEE certificates without Solana.
/// Returns detailed device info on success.
#[post("/api/v1/verify-device-only")]
async fn verify_device_only(
    state: web::Data<Arc<AppState>>,
    body: web::Json<VerifyDeviceOnlyRequest>,
) -> Result<HttpResponse, ApiError> {
    let challenge = body.challenge.clone();
    let cert_chain = body.certificate_chain.clone();

    // Check challenge exists and is fresh
    {
        let mut challenges = state.challenges.lock().unwrap();
        match challenges.remove(&challenge) {
            Some(created) => {
                if created.elapsed() > Duration::from_secs(300) {
                    return Ok(HttpResponse::BadRequest().json(VerifyDeviceOnlyResponse {
                        verified: false,
                        device_info: None,
                        error: Some("Challenge expired".into()),
                    }));
                }
            }
            None => {
                return Ok(HttpResponse::BadRequest().json(VerifyDeviceOnlyResponse {
                    verified: false,
                    device_info: None,
                    error: Some("Invalid challenge".into()),
                }));
            }
        }
    }

    // Verify the certificate chain (CPU-bound)
    let result = web::block(move || -> Result<VerifyDeviceOnlyResponse, ApiError> {
        match hw_attest::verify_attestation(&cert_chain, &challenge) {
            Ok(device_info) => {
                tracing::info!(
                    brand = %device_info.brand,
                    model = %device_info.model,
                    manufacturer = %device_info.manufacturer,
                    security_level = %device_info.attestation_security_level,
                    boot_state = %device_info.verified_boot_state,
                    "Device verified (attestation-only)"
                );

                Ok(VerifyDeviceOnlyResponse {
                    verified: true,
                    device_info: Some(DeviceInfoResponse {
                        brand: device_info.brand,
                        model: device_info.model,
                        manufacturer: device_info.manufacturer,
                        product: device_info.product,
                        attestation_security_level: device_info.attestation_security_level.to_string(),
                        keymaster_security_level: device_info.keymaster_security_level.to_string(),
                        os_version: device_info.os_version,
                        os_patch_level: device_info.os_patch_level,
                        verified_boot_state: device_info.verified_boot_state.to_string(),
                        device_locked: device_info.device_locked,
                        app_package_name: device_info.app_package_name,
                        app_signature_digests: device_info.app_signature_digests,
                        attestation_version: device_info.attestation_version,
                        sw_tags: device_info.sw_tags,
                        tee_tags: device_info.tee_tags,
                    }),
                    error: None,
                })
            }
            Err(e) => {
                tracing::warn!(error = %e, "Attestation verification failed");
                Ok(VerifyDeviceOnlyResponse {
                    verified: false,
                    device_info: None,
                    error: Some(format!("Verification failed: {e}")),
                })
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("Block error: {e}")))?
    ?;

    if result.verified {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::Forbidden().json(result))
    }
}

/// Step 2: Verify the device attestation certificate chain.
/// If valid Seeker: build a create_attestation tx, partially sign it,
/// and return it for the app to co-sign and submit on-chain.
#[post("/api/v1/verify-device")]
async fn verify_device(
    state: web::Data<Arc<AppState>>,
    body: web::Json<VerifyDeviceRequest>,
) -> Result<HttpResponse, ApiError> {
    let challenge = body.challenge.clone();
    let wallet_address = body.wallet_address.clone();
    let cert_chain = body.certificate_chain.clone();

    // Check challenge exists and is fresh
    {
        let mut challenges = state.challenges.lock().unwrap();
        match challenges.remove(&challenge) {
            Some(created) => {
                if created.elapsed() > Duration::from_secs(300) {
                    return Ok(HttpResponse::BadRequest().json(VerifyDeviceResponse {
                        verified: false,
                        device: None,
                        attestation_tx: None,
                        attestation_pda: None,
                        error: Some("Challenge expired".into()),
                    }));
                }
            }
            None => {
                return Ok(HttpResponse::BadRequest().json(VerifyDeviceResponse {
                    verified: false,
                    device: None,
                    attestation_tx: None,
                    attestation_pda: None,
                    error: Some("Invalid challenge".into()),
                }));
            }
        }
    }

    // Verify the certificate chain + build attestation tx (CPU-bound)
    let state_clone = state.clone();
    let result = web::block(move || -> Result<VerifyDeviceResponse, ApiError> {
        match hw_attest::verify_attestation(&cert_chain, &challenge) {
            Ok(device_info) => {
                // Verified Seeker! Now build the on-chain attestation tx
                let miner_pubkey = Pubkey::from_str(&wallet_address)
                    .map_err(|e| ApiError::InvalidRequest(format!("Invalid wallet: {e}")))?;

                let authority_bytes = state_clone.authority_keypair_bytes.as_ref()
                    .ok_or_else(|| ApiError::Internal("Solana not configured (running in attestation-only mode?)".into()))?;

                let program_id = state_clone.program_id
                    .ok_or_else(|| ApiError::Internal("Program ID not configured".into()))?;

                // Reconstruct keypair and RPC client (Keypair is !Sync)
                let authority = Keypair::try_from(authority_bytes.as_slice())
                    .map_err(|e| ApiError::Internal(format!("Keypair error: {e}")))?;
                let rpc = solana_client::rpc_client::RpcClient::new(state_clone.solana_rpc_url.clone());

                let (tx_b64, attestation_pda) = attestation_tx::build_attestation_tx(
                    &rpc,
                    &program_id,
                    &authority,
                    &miner_pubkey,
                )
                .map_err(|e| ApiError::Internal(format!("Failed to build attestation tx: {e}")))?;

                state_clone
                    .db
                    .upsert_device(&wallet_address, &format!("hw:{}", device_info.model))?;

                tracing::info!(
                    wallet = %wallet_address,
                    brand = %device_info.brand,
                    model = %device_info.model,
                    manufacturer = %device_info.manufacturer,
                    security_level = %device_info.attestation_security_level,
                    boot_state = %device_info.verified_boot_state,
                    attestation_pda = %attestation_pda,
                    "Seeker verified → attestation tx built"
                );

                Ok(VerifyDeviceResponse {
                    verified: true,
                    device: Some(format!("{} {}", device_info.brand, device_info.model)),
                    attestation_tx: Some(tx_b64),
                    attestation_pda: Some(attestation_pda.to_string()),
                    error: None,
                })
            }
            Err(e) => {
                tracing::warn!(wallet = %wallet_address, error = %e, "Attestation verification failed");
                Ok(VerifyDeviceResponse {
                    verified: false,
                    device: None,
                    attestation_tx: None,
                    attestation_pda: None,
                    error: Some(format!("Verification failed: {e}")),
                })
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("Block error: {e}")))?
    ?;

    if result.verified {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::Forbidden().json(result))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hashish_backend=debug".parse().unwrap()),
        )
        .init();

    let config = Config::from_env().expect("Failed to load config");
    let bind = (config.host.clone(), config.port);
    let attestation_only = config.attestation_only;

    tracing::info!("Starting server on {}:{}", bind.0, bind.1);

    if attestation_only {
        tracing::info!("Running in ATTESTATION-ONLY mode (no Solana)");
    }

    let db = Database::new(&config.database_path).expect("Failed to initialize database");

    // Load Solana config only if not in attestation-only mode
    let (authority_keypair_bytes, program_id) = if !attestation_only {
        // Try AUTHORITY_KEYPAIR_JSON env var first (for cloud deployments),
        // then fall back to file path
        let authority_keypair = if let Ok(json) = std::env::var("AUTHORITY_KEYPAIR_JSON") {
            let bytes: Vec<u8> = serde_json::from_str(&json)
                .expect("Failed to parse AUTHORITY_KEYPAIR_JSON");
            Keypair::try_from(bytes.as_slice())
                .expect("Invalid keypair bytes in AUTHORITY_KEYPAIR_JSON")
        } else {
            let keypair_path = config.authority_keypair_path.as_deref()
                .unwrap_or("./authority-keypair.json");
            attestation_tx::load_keypair(keypair_path)
                .expect("Failed to load authority keypair")
        };
        let authority_pubkey = authority_keypair.pubkey();
        let authority_bytes = authority_keypair.to_bytes().to_vec();

        let pid_str = config.program_id.as_deref()
            .unwrap_or("Ai9XrxSUmDLNCXkoeoqnYuzPgN9F2PeF9WtLq9GyqER");
        let pid = Pubkey::from_str(pid_str).expect("Invalid PROGRAM_ID");

        tracing::info!(
            authority = %authority_pubkey,
            program = %pid,
            rpc = %config.solana_rpc_url,
            "Solana config loaded"
        );

        (Some(authority_bytes), Some(pid))
    } else {
        (None, None)
    };

    let solana_rpc_url = config.solana_rpc_url.clone();

    let state = Arc::new(AppState {
        db,
        config,
        solana_rpc_url,
        authority_keypair_bytes,
        program_id,
        challenges: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(actix_cors::Cors::permissive())
            .service(health)
            .service(get_challenge)
            .service(verify_device_only);

        if !attestation_only {
            app = app.service(verify_device);
        }

        app
    })
    .bind(bind)?
    .run()
    .await
}
