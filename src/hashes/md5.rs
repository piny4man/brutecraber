pub fn crack(word: &str) -> String {
    format!("{:x}", md5::compute(word))
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    format!("{:x}", md5::compute(salted))
}
