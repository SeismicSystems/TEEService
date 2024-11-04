use hyper::{body::to_bytes, Body, Request, Response};
use std::convert::Infallible;

use secp256k1::ecdh::SharedSecret;
use secp256k1::SecretKey;

use tee_service_api::request_types::tx_io::*;
use crate::utils::crypto_utils::*;
use crate::utils::response_utils::{
    invalid_ciphertext_resp, invalid_json_body_resp, invalid_req_body_resp,
};

/// Handles an IO encryption request, encrypting the provided data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the data to be encrypted. The body of the request
///   Should be a JSON-encoded `IoEncryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the encrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the encrypted data as part of an `IoEncryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or encrypting the data fails.
pub async fn tx_io_encrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into IoEncryptionRequest
    let encryption_request: IoEncryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // load key and encrypt data
    let ecdh_sk = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(&encryption_request.msg_sender, &ecdh_sk);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| format!("Error while deriving AES key: {:?}", e))
        .unwrap();
    let encrypted_data = aes_encrypt(&aes_key, &encryption_request.data, encryption_request.nonce);

    let response_body = IoEncryptionResponse { encrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Handles an IO decryption request, decrypting the provided encrypted data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the encrypted data. The body of the request
///   Should be a JSON-encoded `IoDecryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the decrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the decrypted data as part of an `IoDecryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or decrypting the data fails.
pub async fn tx_io_decrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into IoDecryptionRequest
    let decryption_request: IoDecryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };
    // load key and decrypt data
    let ecdh_sk = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(&decryption_request.msg_sender, &ecdh_sk);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| format!("Error while deriving AES key: {:?}", e))
        .unwrap();
    let decrypted_data = aes_decrypt(&aes_key, &decryption_request.data, decryption_request.nonce);

    let decrypted_data = match decrypted_data {
        Ok(data) => data,
        Err(e) => {
            return Ok(invalid_ciphertext_resp(e));
        }
    };

    let response_body = IoDecryptionResponse { decrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Loads a secp256k1 private key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `SecretKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
fn get_secp256k1_sk() -> SecretKey {
    get_sample_secp256k1_sk()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};
    use secp256k1::PublicKey;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_encryption_handler_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req = Request::builder()
            .method("POST")
            .uri("/encrypt")
            .header("Content-Type", "application/json")
            .body(Body::from("invalid body"))
            .unwrap();

        let res = tx_io_encrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response["error"], "Invalid JSON in request body");
    }

    #[tokio::test]
    async fn test_decryption_handler_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req = Request::builder()
            .method("POST")
            .uri("/decrypt")
            .header("Content-Type", "application/json")
            .body(Body::from("invalid body"))
            .unwrap();

        let res = tx_io_decrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response["error"], "Invalid JSON in request body");
    }

    #[tokio::test]
    async fn test_io_encryption() {
        // Prepare encryption request body
        let base_url = "http://localhost:7878";
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let encryption_request = IoEncryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: data_to_encrypt.clone(),
            nonce: 12345678,
        };
        let payload_json = serde_json::to_string(&encryption_request).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/tx_io/encrypt", base_url))
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = tx_io_encrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let enc_response: IoEncryptionResponse = serde_json::from_slice(&body).unwrap();
        assert!(!enc_response.encrypted_data.is_empty());

        println!("Encrypted data: {:?}", enc_response.encrypted_data);

        // check that decryption returns the original data
        // Prepare decrypt request body
        let decryption_request = IoDecryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: enc_response.encrypted_data,
            nonce: 12345678,
        };
        let payload_json = serde_json::to_string(&decryption_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/tx_io/decrypt", base_url))
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = tx_io_decrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let dec_response: IoDecryptionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(dec_response.decrypted_data, data_to_encrypt);
    }

    #[tokio::test]
    async fn test_decrypt_invalid_ciphertext() {
        let base_url = "http://localhost:7878";
        let bad_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let decryption_request = IoDecryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: bad_ciphertext,
            nonce: 12345678,
        };
        let payload_json = serde_json::to_string(&decryption_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/tx_io/decrypt", base_url))
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = tx_io_decrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 422);
    }
}
