use crate::error::ApiError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub wallet: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn generate(wallet: &str, secret: &str, expiry_hours: i64) -> Result<(String, i64), ApiError> {
    let now = chrono::Utc::now();
    let exp = (now + chrono::Duration::hours(expiry_hours)).timestamp();
    let claims = Claims {
        wallet: wallet.to_string(),
        iat: now.timestamp(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok((token, exp))
}

#[allow(dead_code)]
pub fn validate(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}
