/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Machine Identity module for JWT-SVID token generation and management.
//!
//! This module handles signing JWT-SVID tokens for machine identity verification.
#![allow(dead_code)] // Signer, Es256Signer, SignOptions used from tests and from handler once key loading is implemented
use std::collections::BTreeMap;

use ::rpc::forge::{self as rpc, MachineIdentityResponse};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::Value;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::auth::AuthContext;

/// Error type for JWT-SVID signing.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("invalid JSON payload: {0}")]
    InvalidPayload(String),
    #[error("encode error: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
}

/// Options for signing (e.g. future overrides for expiry, audience).
#[derive(Debug, Default, Clone)]
pub struct SignOptions {}

/// Abstraction for signing JWT-SVID tokens. Key loading and metadata (e.g. from DB)
/// stay outside: the caller builds a signer and passes it here.
pub trait Signer: Send + Sync {
    /// Signs the given JSON payload (JWT claims) and returns the signed JWT string.
    fn sign(&self, payload: &Value, opts: &SignOptions) -> Result<String, SignError>;

    /// Key identifier (e.g. for JWKS `kid`, JWT header `kid`).
    fn key_id(&self) -> &str;

    /// Algorithm name (e.g. `"ES256"`).
    fn algorithm(&self) -> &str;
}

/// ES256 signer (ECDSA P-256 + SHA-256). Holds key material and key_id only;
/// no I/O or DB access.
pub struct Es256Signer {
    key_id: String,
    encoding_key: EncodingKey,
}

impl Es256Signer {
    /// Builds an ES256 signer from PEM-encoded EC P-256 private key and key id.
    pub fn new(key: &[u8], key_id: impl Into<String>) -> Result<Self, SignError> {
        let encoding_key = EncodingKey::from_ec_pem(key).map_err(SignError::Encode)?;
        Ok(Self {
            key_id: key_id.into(),
            encoding_key,
        })
    }
}

impl Signer for Es256Signer {
    fn sign(&self, payload: &Value, _opts: &SignOptions) -> Result<String, SignError> {
        let claims = payload
            .as_object()
            .ok_or_else(|| SignError::InvalidPayload("payload must be a JSON object".to_string()))?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>();

        let header = Header::new(jsonwebtoken::Algorithm::ES256);
        let token = encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        "ES256"
    }
}

/// Convenience: signs a JSON payload with an EC P-256 private key (PEM) and returns a JWT-SVID.
/// Uses a default key_id. For production, prefer building an `Es256Signer` (e.g. from DB-loaded key)
/// and calling `Signer::sign`.
pub fn sign(payload: &Value, key: &[u8]) -> Result<String, SignError> {
    let signer = Es256Signer::new(key, "default")?;
    signer.sign(payload, &SignOptions::default())
}

/// Signs a JWT-SVID token for machine identity.
///
/// This handler validates the machine identity request, generates a signed JWT-SVID
/// token containing the machine's SPIFFE ID, and returns the token along with
/// metadata about its validity and type.
///
/// # Authentication
/// The machine_id is extracted from the client's mTLS certificate SPIFFE ID
/// (embedded in the Subject Alternative Name URI extension).
///
/// # Arguments
/// * `api` - Reference to the API context
/// * `request` - The gRPC request containing audience list
///
/// # Returns
/// * `MachineIdentityResponse` containing the signed access token and metadata
pub(crate) async fn sign_machine_identity(
    _api: &Api,
    request: Request<rpc::MachineIdentityRequest>,
) -> Result<Response<MachineIdentityResponse>, Status> {
    std::future::ready(()).await; // dummy await to satisfy clippy (function not complete yet)
    log_request_data(&request);

    // Extract machine_id from the client certificate's SPIFFE ID
    let auth_context = request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    let machine_id_str = auth_context
        .get_spiffe_machine_id()
        .ok_or_else(|| Status::unauthenticated("No machine identity in client certificate"))?;

    tracing::info!(machine_id = %machine_id_str, "Processing machine identity request");

    // Parse the machine_id string into a MachineId (will be used for JWT SPIFFE ID generation)
    let _machine_id: carbide_uuid::machine::MachineId = machine_id_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("Invalid machine ID format: {}", e)))?;

    let req = request.get_ref();
    let _audience = &req.audience; // TODO: Use audience in JWT claims

    // TODO: Implement the full JWT-SVID signing flow:
    // 1. Validate the machine exists and is authorized
    // 2. Retrieve the tenant's encrypted signing key from the database
    // 3. Decrypt the signing key using the master key from Vault KV
    // 4. Generate JWT-SVID with SPIFFE ID (spiffe://<trust-domain>/machine/<machine-id>)
    // 5. Sign the JWT with the tenant's private key
    // 6. Optionally call Exchange Token Service for token exchange

    // Placeholder response - to be replaced with actual implementation
    let response = MachineIdentityResponse {
        access_token: String::new(), // TODO: Generate actual JWT-SVID
        issued_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: "3600".to_string(), // 1 hour default
    };

    Ok(Response::new(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns an EC P-256 private key in PKCS#8 PEM format (standard encoding), generated at test time.
    fn ec_p256_private_key_pem() -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().expect("generate test key");
        key_pair.serialize_pem().into_bytes()
    }

    #[test]
    fn sign_returns_jwt_svid_for_valid_object_payload_and_key() {
        let payload = serde_json::json!({
            "sub": "spiffe://example.org/machine/123",
            "iss": "https://carbide/v1/org/org-id",
            "aud": ["service-a"],
            "exp": 1678886400,
            "iat": 1678882800,
        });
        let key = ec_p256_private_key_pem();
        let result = sign(&payload, &key);
        assert!(result.is_ok(), "sign should succeed: {:?}", result.err());
        let token = result.unwrap();
        // JWT has three base64url parts separated by dots
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT-SVID must have 3 segments");
    }

    #[test]
    fn sign_returns_invalid_payload_error_when_payload_is_not_an_object() {
        let payload = serde_json::json!(["not", "an", "object"]);
        let key = ec_p256_private_key_pem();
        let result = sign(&payload, &key);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SignError::InvalidPayload(_)),
            "expected InvalidPayload, got {:?}",
            err
        );
    }

    #[test]
    fn sign_returns_invalid_payload_error_when_payload_is_primitive() {
        let payload = serde_json::json!("a string");
        let key = ec_p256_private_key_pem();
        let result = sign(&payload, &key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignError::InvalidPayload(_)));
    }

    #[test]
    fn sign_returns_encode_error_for_invalid_key() {
        let payload = serde_json::json!({ "sub": "test" });
        let key = b"not valid PEM";
        let result = sign(&payload, key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignError::Encode(_)));
    }

    #[test]
    fn es256_signer_implements_signer_trait() {
        let key = ec_p256_private_key_pem();
        let signer = Es256Signer::new(&key, "test-key-1").expect("create signer");
        assert_eq!(signer.key_id(), "test-key-1");
        assert_eq!(signer.algorithm(), "ES256");
        let payload = serde_json::json!({ "sub": "spiffe://example.org/machine/456" });
        let token = signer
            .sign(&payload, &SignOptions::default())
            .expect("sign");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }
}
