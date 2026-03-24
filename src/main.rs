use anyhow;
use clap::Parser;
use colored::Colorize;
use md5::compute;
use std::fs;

#[derive(Parser)] // sabe leer argumentos (derive(parser))
struct Args {
    #[arg(short = 'f')]
    file: String,

    #[arg(short = 'w')]
    wordlist: String,
}

fn banner() {
    println!(
        r#"
 ___.                 __                            ___.
 \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________
  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \
  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/
  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|
      \/                       \/     \/           \/    \/     \/
                                                Author: erikgavs
                                                v0.1.0

 [!] DISCLAIMER: This software is provided for ethical hacking and penetration testing
     only. You are solely responsible for your actions. Using this tool against targets
     without prior consent is a violation of applicable laws. Use at your own risk.
    "#
    );
}

fn main() -> anyhow::Result<()> {
    banner();
    let good_star = "[*]";
    let bad_star = "[*]";
    let mut found = 0;

    // we save user input (file and wordlist)
    let args = Args::parse(); // user input because Args (struct) have a string

    //read content
    let content = fs::read_to_string(&args.file)?;

    // each line is a str "sadsadads", "asdasdasda"
    let hashes: Vec<&str> = content.lines().collect();

    let wordlist = fs::read_to_string(&args.wordlist)?;

    println!("\nSelected file: {}", args.file.green());
    println!("Selected wordlist {}", args.wordlist.green());

    // for each word in wordlist, convert it to md5 hash
    // if the hash matches one in hashes.txt, that word is the original text
    for word in wordlist.lines() {
        let hash = format!("{:x}", md5::compute(word));
        if hashes.contains(&hash.as_str()) {
            println!(
                "\n{} Hash cracked {} -> {}\n",
                good_star.green(),
                hash,
                word.truecolor(227, 120, 49)
            );

            found += 1;
        }
    }

    if found == 0 {
        println!("\n{} failed cracking hashes or bad file\n", bad_star.red())
    }

    if found > 0 {
        println!(
            "{} cracked {}/{} hashes\n",
            good_star.green(),
            found,
            hashes.len()
        );
    }
    Ok(())
}
