use sha2::{Digest, Sha512};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha512::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salt = format!("{}{}", salt, word);
    let mut hash_engine = Sha512::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}
