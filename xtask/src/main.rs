use anyhow::{bail, Result};

mod conv_registry;
mod listx;

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().skip(1).collect();
  match args.first().map(String::as_str) {
    Some("gen-tables") => gen_tables(&args[1..]),
    _ => {
      eprintln!("usage: cargo xtask gen-tables --module <M> --out <path> [--check]");
      bail!("unknown command");
    }
  }
}

fn gen_tables(_rest: &[String]) -> Result<()> {
  // Filled in Task 6.
  Ok(())
}
