use sha3::{Digest, Sha3_256};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha3_256::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha3_256::new();
    hash_engine.update(salted);
    format!("{:x}", hash_engine.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        // echo -n password | sha3-256sum
        assert_eq!(crack("password"), "c04529d81c000336594d6092004273f550bc6a987627443f01740925232a9e3e");
        assert_eq!(crack("admin"), "08e803ca87889151590e804f568779901768e999c063462d164d1f5682851d7e");
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(crack_with_salt("password", "x7k2"), "28e2d27e89e023199e52e46e8c75043a539f37c3563964147053e1a067e6f663");
    }
}
