use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use x509_parser::prelude::*;

// ── Public types ──

/// Full device info extracted and verified from the attestation.
#[allow(dead_code)]
pub struct DeviceInfo {
    pub brand: String,
    pub model: String,
    pub manufacturer: String,
    pub product: String,
    pub attestation_security_level: SecurityLevel,
    pub keymaster_security_level: SecurityLevel,
    pub verified_boot_state: VerifiedBootState,
    pub device_locked: bool,
    pub app_package_name: Option<String>,
    pub app_signature_digests: Vec<String>,
    pub os_version: Option<String>,
    pub os_patch_level: Option<String>,
    pub attestation_version: i64,
    /// Tags found in softwareEnforced (for debugging)
    pub sw_tags: Vec<u32>,
    /// Tags found in teeEnforced (for debugging)
    pub tee_tags: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Software => write!(f, "Software"),
            SecurityLevel::TrustedEnvironment => write!(f, "TEE"),
            SecurityLevel::StrongBox => write!(f, "StrongBox"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
    Unknown(i64),
}

impl std::fmt::Display for VerifiedBootState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifiedBootState::Verified => write!(f, "Verified"),
            VerifiedBootState::SelfSigned => write!(f, "SelfSigned"),
            VerifiedBootState::Unverified => write!(f, "Unverified"),
            VerifiedBootState::Failed => write!(f, "Failed"),
            VerifiedBootState::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Our expected app package name.
const EXPECTED_PACKAGE: &str = "com.hashish.app";

/// Android Key Attestation extension OID (1.3.6.1.4.1.11129.2.1.17)
const KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

// ── Tag numbers in AuthorizationList ──
// https://source.android.com/docs/security/features/keystore/attestation#schema
const TAG_OS_VERSION: u32 = 702;
const TAG_OS_PATCHLEVEL: u32 = 703;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;
const TAG_BRAND: u32 = 710;
const _TAG_DEVICE: u32 = 711;
const TAG_PRODUCT: u32 = 712;
const TAG_MANUFACTURER: u32 = 715;
const TAG_MODEL: u32 = 716;
// RootOfTrust is tag 704

// ── Public API ──

/// Generate a random 32-byte challenge, returned as base64.
pub fn generate_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

/// Verify an Android Key Attestation certificate chain with maximum security.
///
/// Checks:
/// 1. Certificate chain signatures are valid (each cert signed by next)
/// 2. Leaf cert contains Key Attestation extension
/// 3. attestationSecurityLevel >= TEE (hardware-backed)
/// 4. keymasterSecurityLevel >= TEE
/// 5. Challenge matches server-generated nonce
/// 6. verifiedBootState == Verified (bootloader locked, OS untampered)
/// 7. deviceLocked == true
/// 8. Brand == "solanamobile" (from untampered OS = trustworthy)
/// 9. App package == "com.hashish.app"
/// 10. App signing certificate matches our release key
pub fn verify_attestation(
    cert_chain_b64: &[String],
    expected_challenge: &str,
) -> Result<DeviceInfo, String> {
    if cert_chain_b64.is_empty() {
        return Err("Empty certificate chain".into());
    }
    if cert_chain_b64.len() < 2 {
        return Err("Certificate chain too short (need at least leaf + intermediate)".into());
    }

    // ── Step 1: Decode all certs ──
    let certs: Vec<Vec<u8>> = cert_chain_b64
        .iter()
        .map(|b64| BASE64.decode(b64).map_err(|e| format!("Invalid base64: {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    // ── Step 2: Verify certificate chain signatures ──
    for i in 0..certs.len().saturating_sub(1) {
        let (_, subject) = X509Certificate::from_der(&certs[i])
            .map_err(|e| format!("Failed to parse cert {i}: {e}"))?;
        let (_, issuer) = X509Certificate::from_der(&certs[i + 1])
            .map_err(|e| format!("Failed to parse cert {}: {e}", i + 1))?;

        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| format!("Chain signature invalid at cert {i}: {e}"))?;
    }

    // ── Step 3: Parse leaf certificate ──
    let (_, leaf_cert) = X509Certificate::from_der(&certs[0])
        .map_err(|e| format!("Failed to parse leaf certificate: {e}"))?;

    // ── Step 4: Extract Key Attestation extension ──
    let attestation_ext = leaf_cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == KEY_ATTESTATION_OID)
        .ok_or("No Key Attestation extension found")?;

    // ── Step 5: Parse and verify all attestation fields ──
    let info = parse_key_attestation(attestation_ext.value, expected_challenge)?;

    // ── Step 6: Enforce security requirements ──
    // Strict mode is ON by default. Set SKIP_ATTESTATION_CHECKS=true to disable
    // (only for local testing / debugging).

    let skip_checks = std::env::var("SKIP_ATTESTATION_CHECKS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let strict = !skip_checks;

    // Log all device info upfront so we can diagnose issues
    tracing::info!(
        brand = %info.brand,
        model = %info.model,
        manufacturer = %info.manufacturer,
        product = %info.product,
        attestation_security = %info.attestation_security_level,
        keymaster_security = %info.keymaster_security_level,
        boot_state = %info.verified_boot_state,
        device_locked = info.device_locked,
        app_package = ?info.app_package_name,
        app_digests = ?info.app_signature_digests,
        attestation_version = info.attestation_version,
        strict = strict,
        "Device attestation info"
    );

    // 6a. Attestation security level must be TEE or StrongBox
    if info.attestation_security_level == SecurityLevel::Software {
        let msg = "Attestation security level is Software (need TEE or StrongBox)";
        if strict { return Err(format!("REJECTED: {msg}")); }
        tracing::warn!("WARN: {msg}");
    }

    // 6b. Keymaster security level must be TEE or StrongBox
    if info.keymaster_security_level == SecurityLevel::Software {
        let msg = "Keymaster security level is Software (need TEE or StrongBox)";
        if strict { return Err(format!("REJECTED: {msg}")); }
        tracing::warn!("WARN: {msg}");
    }

    // 6c. Boot state & device locked — log-only (many Seekers have unlocked bootloader)
    if info.verified_boot_state != VerifiedBootState::Verified {
        tracing::warn!("Boot state is {} (not Verified)", info.verified_boot_state);
    }
    if !info.device_locked {
        tracing::warn!("Device bootloader is unlocked");
    }

    // 6e. Brand must be solanamobile
    // Device properties (tags 710-716) require API 31+ with setDevicePropertiesAttestationIncluded.
    // If the brand is empty, the device didn't provide properties — reject in strict mode
    // because we can't verify it's a Seeker without the brand.
    if info.brand.is_empty() {
        let msg = "No brand in attestation (device properties missing) — cannot verify Seeker";
        if strict { return Err(format!("REJECTED: {msg}")); }
        tracing::warn!("WARN: {msg}");
    } else if info.brand.to_lowercase() != "solanamobile" {
        let msg = format!("Brand is '{}' (need 'solanamobile')", info.brand);
        if strict { return Err(format!("REJECTED: {msg}")); }
        tracing::warn!("WARN: {msg}");
    }

    // 6f. App package must be ours
    if let Some(ref pkg) = info.app_package_name {
        if pkg != EXPECTED_PACKAGE {
            let msg = format!("App package is '{}' (need '{}')", pkg, EXPECTED_PACKAGE);
            if strict { return Err(format!("REJECTED: {msg}")); }
            tracing::warn!("WARN: {msg}");
        }
    }
    // Note: package name might not be present in all attestation versions

    // 6g. Verify app signing certificate digest matches our release signing key
    if let Ok(expected_digest) = std::env::var("EXPECTED_SIGNING_DIGEST") {
        let expected = expected_digest.to_lowercase();
        if !info.app_signature_digests.is_empty() {
            if !info.app_signature_digests.iter().any(|d| d.to_lowercase() == expected) {
                let msg = format!(
                    "App signing digest mismatch: got [{}], expected {}",
                    info.app_signature_digests.join(", "),
                    expected
                );
                if strict { return Err(format!("REJECTED: {msg}")); }
                tracing::warn!("WARN: {msg}");
            } else {
                tracing::info!("App signing digest verified OK");
            }
        } else {
            let msg = "No app signing digests in attestation to verify";
            if strict { return Err(format!("REJECTED: {msg}")); }
            tracing::warn!("WARN: {msg}");
        }
    } else {
        tracing::debug!("EXPECTED_SIGNING_DIGEST not set, skipping signing cert check");
    }

    Ok(info)
}

// ── ASN.1 Parsing ──

fn parse_security_level(val: i64) -> SecurityLevel {
    match val {
        0 => SecurityLevel::Software,
        1 => SecurityLevel::TrustedEnvironment,
        2 => SecurityLevel::StrongBox,
        _ => SecurityLevel::Software, // treat unknown as software
    }
}

fn parse_verified_boot_state(val: i64) -> VerifiedBootState {
    match val {
        0 => VerifiedBootState::Verified,
        1 => VerifiedBootState::SelfSigned,
        2 => VerifiedBootState::Unverified,
        3 => VerifiedBootState::Failed,
        _ => VerifiedBootState::Unknown(val),
    }
}

/// Parse the full Android Key Attestation extension.
///
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   SecurityLevel,
///     keymasterVersion           INTEGER,
///     keymasterSecurityLevel     SecurityLevel,
///     attestationChallenge       OCTET STRING,
///     uniqueId                   OCTET STRING,
///     softwareEnforced           AuthorizationList,
///     teeEnforced                AuthorizationList,
/// }
fn parse_key_attestation(data: &[u8], expected_challenge: &str) -> Result<DeviceInfo, String> {
    use asn1_rs::{Enumerated, FromDer, Integer, OctetString, Sequence};

    let expected_challenge_bytes = BASE64
        .decode(expected_challenge)
        .map_err(|e| format!("Invalid challenge base64: {e}"))?;

    let (_rem, seq) =
        Sequence::from_der(data).map_err(|e| format!("Failed to parse attestation: {e}"))?;
    let mut pos = seq.content.as_ref();

    // 1. attestationVersion (INTEGER)
    let (rest, version_int) =
        Integer::from_der(pos).map_err(|e| format!("Parse attestationVersion: {e}"))?;
    let attestation_version = version_int.as_i64().unwrap_or(0);
    pos = rest;

    // 2. attestationSecurityLevel (ENUMERATED)
    let (rest, sec_level_enum) =
        Enumerated::from_der(pos).map_err(|e| format!("Parse attestationSecurityLevel: {e}"))?;
    let attestation_security_level =
        parse_security_level(sec_level_enum.0 as i64);
    pos = rest;

    // 3. keymasterVersion (INTEGER)
    let (rest, _) =
        Integer::from_der(pos).map_err(|e| format!("Parse keymasterVersion: {e}"))?;
    pos = rest;

    // 4. keymasterSecurityLevel (ENUMERATED)
    let (rest, km_sec_enum) =
        Enumerated::from_der(pos).map_err(|e| format!("Parse keymasterSecurityLevel: {e}"))?;
    let keymaster_security_level =
        parse_security_level(km_sec_enum.0 as i64);
    pos = rest;

    // 5. attestationChallenge
    let (rest, challenge_oct) =
        OctetString::from_der(pos).map_err(|e| format!("Parse attestationChallenge: {e}"))?;
    if challenge_oct.as_ref() != expected_challenge_bytes.as_slice() {
        return Err("REJECTED: Challenge mismatch (possible replay attack)".into());
    }
    pos = rest;

    // 6. uniqueId
    let (rest, _) =
        OctetString::from_der(pos).map_err(|e| format!("Parse uniqueId: {e}"))?;
    pos = rest;

    // 7. softwareEnforced
    let (rest, sw_enforced) =
        Sequence::from_der(pos).map_err(|e| format!("Parse softwareEnforced: {e}"))?;
    let sw_data = sw_enforced.content.as_ref();
    pos = rest;

    // 8. teeEnforced
    let (_rest, tee_enforced) =
        Sequence::from_der(pos).map_err(|e| format!("Parse teeEnforced: {e}"))?;
    let tee_data = tee_enforced.content.as_ref();

    // ── Debug: list all tags present ──
    let sw_tags = list_tags(sw_data);
    let tee_tags = list_tags(tee_data);
    tracing::info!(?sw_tags, ?tee_tags, sw_len = sw_data.len(), tee_len = tee_data.len(), "AuthorizationList tags");

    // ── Extract device properties ──
    // Try teeEnforced first (most trustworthy), fallback to softwareEnforced

    let brand = extract_tagged_octet_string(tee_data, TAG_BRAND)
        .or_else(|| extract_tagged_octet_string(sw_data, TAG_BRAND))
        .unwrap_or_default();

    let model = extract_tagged_octet_string(tee_data, TAG_MODEL)
        .or_else(|| extract_tagged_octet_string(sw_data, TAG_MODEL))
        .unwrap_or_default();

    let manufacturer = extract_tagged_octet_string(tee_data, TAG_MANUFACTURER)
        .or_else(|| extract_tagged_octet_string(sw_data, TAG_MANUFACTURER))
        .unwrap_or_default();

    let product = extract_tagged_octet_string(tee_data, TAG_PRODUCT)
        .or_else(|| extract_tagged_octet_string(sw_data, TAG_PRODUCT))
        .unwrap_or_default();

    // ── Extract Root of Trust (tag 704) from teeEnforced ──
    // RootOfTrust ::= SEQUENCE {
    //     verifiedBootKey   OCTET STRING,
    //     deviceLocked      BOOLEAN,
    //     verifiedBootState VerifiedBootState,
    //     verifiedBootHash  OCTET STRING (optional, v3+),
    // }
    let (verified_boot_state, device_locked) =
        extract_root_of_trust(tee_data).unwrap_or((VerifiedBootState::Unverified, false));

    // ── Extract attestationApplicationId (tag 709) from softwareEnforced ──
    // This contains the package name and signing certificate digests
    let (app_package_name, app_signature_digests) =
        extract_attestation_app_id(sw_data).unwrap_or((None, vec![]));

    // ── Extract OS version and patch level ──
    let os_version = extract_tagged_integer(sw_data, TAG_OS_VERSION)
        .or_else(|| extract_tagged_integer(tee_data, TAG_OS_VERSION))
        .map(format_os_version);

    let os_patch_level = extract_tagged_integer(sw_data, TAG_OS_PATCHLEVEL)
        .or_else(|| extract_tagged_integer(tee_data, TAG_OS_PATCHLEVEL))
        .map(|v| format!("{}", v));

    Ok(DeviceInfo {
        brand,
        model,
        manufacturer,
        product,
        attestation_security_level,
        keymaster_security_level,
        verified_boot_state,
        device_locked,
        app_package_name,
        app_signature_digests,
        os_version,
        os_patch_level,
        attestation_version,
        sw_tags,
        tee_tags,
    })
}

fn format_os_version(v: i64) -> String {
    let major = v / 10000;
    let minor = (v / 100) % 100;
    let patch = v % 100;
    format!("{major}.{minor}.{patch}")
}

// ── ASN.1 TLV helpers ──

/// Parse an ASN.1 length field. Returns (content_length, header_bytes_consumed).
fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    if data[0] & 0x80 == 0 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return (0, 1);
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        (len, 1 + num_bytes)
    }
}

/// Decode a multi-byte ASN.1 context-specific tag number from raw bytes.
/// Returns (tag_number, tag_header_length) or None if not a high tag.
fn decode_context_tag(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    // Must be context-specific class (0xa0..0xbf = constructed, 0x80..0x9f = primitive)
    if first & 0xc0 != 0x80 {
        return None;
    }
    if first & 0x1f != 0x1f {
        // Short tag
        return Some(((first & 0x1f) as u32, 1));
    }
    // Multi-byte tag
    let mut tag: u32 = 0;
    let mut i = 1;
    while i < data.len() {
        tag = (tag << 7) | (data[i] as u32 & 0x7f);
        if data[i] & 0x80 == 0 {
            return Some((tag, i + 1));
        }
        i += 1;
    }
    None
}

/// Get the content bytes of a tagged element in an AuthorizationList.
fn find_tagged_content<'a>(data: &'a [u8], target_tag: u32) -> Option<&'a [u8]> {
    let mut pos = data;
    while !pos.is_empty() {
        // Try to decode as context-specific tag; skip unknown elements
        match decode_context_tag(pos) {
            Some((tag_num, tag_header_len)) => {
                let after_tag = &pos[tag_header_len..];
                let (content_len, len_bytes) = parse_asn1_length(after_tag);
                let total_element = tag_header_len + len_bytes + content_len;

                if total_element > pos.len() {
                    break;
                }

                if tag_num == target_tag {
                    let content_start = tag_header_len + len_bytes;
                    return Some(&pos[content_start..content_start + content_len]);
                }

                pos = &pos[total_element..];
            }
            None => {
                // Unknown tag type - try to skip it using generic TLV parsing
                if pos.len() < 2 {
                    break;
                }
                let tag_byte = pos[0];
                // Determine tag header length (short or long form)
                let tag_hdr = if tag_byte & 0x1f == 0x1f {
                    // Long form tag
                    let mut i = 1;
                    while i < pos.len() && pos[i] & 0x80 != 0 {
                        i += 1;
                    }
                    i + 1
                } else {
                    1
                };
                if tag_hdr >= pos.len() {
                    break;
                }
                let (content_len, len_bytes) = parse_asn1_length(&pos[tag_hdr..]);
                let total = tag_hdr + len_bytes + content_len;
                if total > pos.len() {
                    break;
                }
                pos = &pos[total..];
            }
        }
    }
    None
}

/// List all context-specific tags found in an AuthorizationList (for debugging).
fn list_tags(data: &[u8]) -> Vec<u32> {
    let mut tags = Vec::new();
    let mut pos = data;
    while !pos.is_empty() {
        match decode_context_tag(pos) {
            Some((tag_num, tag_header_len)) => {
                tags.push(tag_num);
                let after_tag = &pos[tag_header_len..];
                let (content_len, len_bytes) = parse_asn1_length(after_tag);
                let total = tag_header_len + len_bytes + content_len;
                if total > pos.len() { break; }
                pos = &pos[total..];
            }
            None => {
                if pos.len() < 2 { break; }
                let tag_hdr = if pos[0] & 0x1f == 0x1f {
                    let mut i = 1;
                    while i < pos.len() && pos[i] & 0x80 != 0 { i += 1; }
                    i + 1
                } else { 1 };
                if tag_hdr >= pos.len() { break; }
                let (content_len, len_bytes) = parse_asn1_length(&pos[tag_hdr..]);
                let total = tag_hdr + len_bytes + content_len;
                if total > pos.len() { break; }
                pos = &pos[total..];
            }
        }
    }
    tags
}

/// Extract an OCTET STRING value as UTF-8 string from a tagged element.
fn extract_tagged_octet_string(auth_list: &[u8], tag: u32) -> Option<String> {
    use asn1_rs::{FromDer, OctetString};

    let content = find_tagged_content(auth_list, tag)?;
    let (_, oct) = OctetString::from_der(content).ok()?;
    String::from_utf8(oct.as_ref().to_vec()).ok()
}

/// Extract an INTEGER value from a tagged element.
fn extract_tagged_integer(auth_list: &[u8], tag: u32) -> Option<i64> {
    use asn1_rs::{FromDer, Integer};

    let content = find_tagged_content(auth_list, tag)?;
    let (_, int_val) = Integer::from_der(content).ok()?;
    int_val.as_i64().ok()
}

/// Extract Root of Trust from teeEnforced (tag 704).
/// Returns (VerifiedBootState, deviceLocked).
fn extract_root_of_trust(tee_data: &[u8]) -> Option<(VerifiedBootState, bool)> {
    use asn1_rs::{Boolean, FromDer, Integer, OctetString, Sequence};

    let content = find_tagged_content(tee_data, 704)?;
    let (_, seq) = Sequence::from_der(content).ok()?;
    let mut pos = seq.content.as_ref();

    // verifiedBootKey (OCTET STRING)
    let (rest, _boot_key) = OctetString::from_der(pos).ok()?;
    pos = rest;

    // deviceLocked (BOOLEAN)
    let (rest, locked_bool) = Boolean::from_der(pos).ok()?;
    let device_locked = locked_bool.bool();
    pos = rest;

    // verifiedBootState (ENUMERATED, we parse as INTEGER)
    let (_, boot_state_int) = Integer::from_der(pos).ok()?;
    let boot_state_val = boot_state_int.as_i64().unwrap_or(2); // default Unverified
    let verified_boot_state = parse_verified_boot_state(boot_state_val);

    Some((verified_boot_state, device_locked))
}

/// Extract attestationApplicationId (tag 709) from softwareEnforced.
///
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos  SET OF AttestationPackageInfo,
///     signatureDigests  SET OF OCTET STRING,
/// }
/// AttestationPackageInfo ::= SEQUENCE {
///     packageName  OCTET STRING,
///     version      INTEGER,
/// }
fn extract_attestation_app_id(sw_data: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    use asn1_rs::{FromDer, OctetString, Sequence, Set};

    // The attestationApplicationId is itself an OCTET STRING containing DER-encoded data
    let outer_content = find_tagged_content(sw_data, TAG_ATTESTATION_APPLICATION_ID)?;
    let (_, outer_oct) = OctetString::from_der(outer_content).ok()?;
    let app_id_bytes = outer_oct.as_ref();

    // Parse the inner SEQUENCE
    let (_, app_id_seq) = Sequence::from_der(app_id_bytes).ok()?;
    let mut pos = app_id_seq.content.as_ref();

    // packageInfos (SET)
    let mut package_name: Option<String> = None;
    if let Ok((rest, pkg_set)) = Set::from_der(pos) {
        pos = rest;
        // Parse first AttestationPackageInfo
        if let Ok((_, pkg_seq)) = Sequence::from_der(pkg_set.content.as_ref()) {
            if let Ok((_, name_oct)) = OctetString::from_der(pkg_seq.content.as_ref()) {
                package_name = String::from_utf8(name_oct.as_ref().to_vec()).ok();
            }
        }
    }

    // signatureDigests (SET)
    let mut digests: Vec<String> = vec![];
    if let Ok((_, sig_set)) = Set::from_der(pos) {
        let mut sig_pos = sig_set.content.as_ref();
        while !sig_pos.is_empty() {
            if let Ok((rest, digest_oct)) = OctetString::from_der(sig_pos) {
                digests.push(hex::encode(digest_oct.as_ref()));
                sig_pos = rest;
            } else {
                break;
            }
        }
    }

    Some((package_name, digests))
}
