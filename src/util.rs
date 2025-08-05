use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::SystemTime;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn millis() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

pub fn sign(secret: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(msg.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_milliseconds() {
        assert!(millis() > 0);
    }

    #[test]
    fn test_sign() {
        assert_eq!(
            sign("secret", "message"),
            String::from("8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b")
        );
    }
}

