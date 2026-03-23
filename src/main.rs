use anyhow;
use clap::Parser;


#[derive(Parser)] // sabe leer argumentos (derive(parser))
struct Args {
    file: String,
}

fn main() -> anyhow::Result<()> {

    // we save user input
    let args = Args::parse(); // user input because Args (struct) have a string
    println!("{}", args.file);

    Ok(())
}
