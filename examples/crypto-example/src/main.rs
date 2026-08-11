use crypto::CryptoEngine;
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("FIDO2 Crypto Example");
    info!("Demonstrates Ed25519, ES256, and hybrid encryption.");

    let crypto = CryptoEngine::new()?;

    // 1. Ed25519 sign/verify
    let (seed, pub_key) = crypto.generate_key_pair()?;
    info!("Ed25519 public key: {} bytes", pub_key.len());

    let message = b"hello fido2";
    let signature = crypto.sign(message, &seed)?;
    info!("Ed25519 signature: {} bytes", signature.len());

    crypto.verify(message, &signature, &pub_key)?;
    info!("Ed25519 signature valid");

    // 2. ES256 (P-256) sign/verify
    let (priv_key_p256, pub_key_p256) = crypto.generate_p256_key_pair()?;
    info!("ES256 public key: {} bytes", pub_key_p256.len());

    let sig_p256 = crypto.sign_p256(&priv_key_p256, message)?;
    info!("ES256 signature: {} bytes", sig_p256.len());

    crypto.verify_p256(&pub_key_p256, message, &sig_p256)?;
    info!("ES256 signature valid");

    // 3. ChaCha20-Poly1305 encrypt/decrypt
    let plaintext = b"secret credential data";
    let nonce = crypto.random_bytes(12);
    let ciphertext = crypto.encrypt(plaintext, &nonce)?;
    info!("Ciphertext: {} bytes", ciphertext.len());

    let decrypted = crypto.decrypt(&ciphertext, &nonce)?;
    info!("Decrypted matches plaintext: {}", decrypted == plaintext);

    // 4. Hybrid encryption (ECIES)
    let (recipient_priv, recipient_pub) = crypto::hybrid_generate_keypair()?;
    let secret = b"shared secret";
    let encrypted = crypto::hybrid_encrypt(&recipient_pub, secret)?;
    info!("Hybrid ciphertext: {} bytes", encrypted.serialize().len());

    let recovered = crypto::hybrid_decrypt(recipient_priv, &recipient_pub, &encrypted)?;
    info!("Hybrid decrypted matches: {}", recovered == secret);

    // 5. HMAC-SHA256
    let key = crypto.random_bytes(32);
    let mac = crypto.compute_hmac(message, &key)?;
    info!("HMAC-SHA256: {} bytes", mac.len());

    crypto.verify_hmac(message, &mac, &key)?;
    info!("HMAC valid");

    // 6. SHA-256
    let hash = crypto.sha256(message);
    info!("SHA-256: {} bytes", hash.len());

    info!("Example complete.");
    Ok(())
}
